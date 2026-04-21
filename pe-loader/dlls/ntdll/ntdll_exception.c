/*
 * ntdll_exception.c - SEH/VEH exception handling infrastructure
 *
 * Implements Structured Exception Handling (SEH) and Vectored Exception
 * Handling (VEH) by translating Unix signals (SIGSEGV, SIGFPE, etc.)
 * into Windows EXCEPTION_RECORD structures and dispatching them through
 * the registered handler chain.
 *
 * Handler dispatch order (matching Windows):
 *  1. Vectored Exception Handlers (first chance)
 *  2. SEH frame chain (via __C_specific_handler)
 *  3. Vectored Continue Handlers
 *  4. Unhandled Exception Filter
 *  5. Default handler (terminate)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <pthread.h>
#include <unistd.h>

#include "common/dll_common.h"
#include "eventbus/pe_event.h"

/* ----------------------------------------------------------------
 * Windows exception constants
 * ---------------------------------------------------------------- */

#define EXCEPTION_ACCESS_VIOLATION      0xC0000005
#define EXCEPTION_ARRAY_BOUNDS_EXCEEDED 0xC000008C
#define EXCEPTION_BREAKPOINT            0x80000003
#define EXCEPTION_DATATYPE_MISALIGNMENT 0x80000002
#define EXCEPTION_FLT_DENORMAL_OPERAND  0xC000008D
#define EXCEPTION_FLT_DIVIDE_BY_ZERO    0xC000008E
#define EXCEPTION_FLT_INEXACT_RESULT    0xC000008F
#define EXCEPTION_FLT_INVALID_OPERATION 0xC0000090
#define EXCEPTION_FLT_OVERFLOW          0xC0000091
#define EXCEPTION_FLT_STACK_CHECK       0xC0000092
#define EXCEPTION_FLT_UNDERFLOW         0xC0000093
#define EXCEPTION_ILLEGAL_INSTRUCTION   0xC000001D
#define EXCEPTION_IN_PAGE_ERROR         0xC0000006
#define EXCEPTION_INT_DIVIDE_BY_ZERO    0xC0000094
#define EXCEPTION_INT_OVERFLOW          0xC0000095
#define EXCEPTION_INVALID_DISPOSITION   0xC0000026
#define EXCEPTION_NONCONTINUABLE_EXCEPTION 0xC0000025
#define EXCEPTION_PRIV_INSTRUCTION      0xC0000096
#define EXCEPTION_SINGLE_STEP           0x80000004
#define EXCEPTION_STACK_OVERFLOW        0xC00000FD

/* Software exception raised by RaiseException */
#define EXCEPTION_SOFTWARE              0xE0000000

/* C++ exception code used by MSVC */
#define EXCEPTION_CPP_MSC               0xE06D7363

/* Exception flags */
#define EXCEPTION_NONCONTINUABLE        0x01
#define EXCEPTION_UNWINDING             0x02
#define EXCEPTION_EXIT_UNWIND           0x04
#define EXCEPTION_STACK_INVALID         0x08
#define EXCEPTION_NESTED_CALL           0x10
#define EXCEPTION_TARGET_UNWIND         0x20
#define EXCEPTION_COLLIDED_UNWIND       0x40
#define EXCEPTION_UNWIND                0x66

/* Exception handler return values */
#define EXCEPTION_CONTINUE_EXECUTION    (-1)
#define EXCEPTION_CONTINUE_SEARCH       0
#define EXCEPTION_EXECUTE_HANDLER       1

/* Maximum number of exception parameters */
#define EXCEPTION_MAXIMUM_PARAMETERS    15

/* ----------------------------------------------------------------
 * Exception structures (Windows-compatible layout)
 * ---------------------------------------------------------------- */

typedef struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;

/*
 * CONTEXT structure (x86-64 subset).
 * Full Windows CONTEXT is 1232 bytes. We define the critical registers
 * that exception handlers actually inspect.
 */
typedef struct _CONTEXT {
    DWORD64 P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
    DWORD   ContextFlags;
    DWORD   MxCsr;
    /* Segment registers */
    WORD    SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
    DWORD   EFlags;
    /* Debug registers */
    DWORD64 Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    /* Integer registers */
    DWORD64 Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
    DWORD64 R8, R9, R10, R11, R12, R13, R14, R15;
    /* Program counter */
    DWORD64 Rip;
    /* Floating-point (XMM) state - simplified */
    BYTE    FltSave[512];
    /* Vector registers */
    BYTE    VectorRegister[26 * 16];
    DWORD64 VectorControl;
    /* Debug control */
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT;

#define CONTEXT_AMD64               0x00100000
#define CONTEXT_CONTROL             (CONTEXT_AMD64 | 0x0001)
#define CONTEXT_INTEGER             (CONTEXT_AMD64 | 0x0002)
#define CONTEXT_SEGMENTS            (CONTEXT_AMD64 | 0x0004)
#define CONTEXT_FLOATING_POINT      (CONTEXT_AMD64 | 0x0008)
#define CONTEXT_FULL                (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)

typedef struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT          ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;

/* ----------------------------------------------------------------
 * Vectored Exception Handler list
 * ---------------------------------------------------------------- */

typedef LONG (__attribute__((ms_abi)) *PVECTORED_EXCEPTION_HANDLER)(EXCEPTION_POINTERS *ExceptionInfo);

typedef struct veh_entry {
    PVECTORED_EXCEPTION_HANDLER handler;
    struct veh_entry *next;
    struct veh_entry *prev;
    DWORD  id;          /* Unique ID for RemoveVectoredExceptionHandler */
} veh_entry_t;

static veh_entry_t *g_veh_first_head = NULL;   /* First-chance VEH */
static veh_entry_t *g_veh_first_tail = NULL;
static veh_entry_t *g_vch_head = NULL;          /* Vectored continue handlers */
static veh_entry_t *g_vch_tail = NULL;
static DWORD g_veh_next_id = 1;
static pthread_mutex_t g_veh_lock = PTHREAD_MUTEX_INITIALIZER;

/* Unhandled exception filter */
typedef LONG (__attribute__((ms_abi)) *LPTOP_LEVEL_EXCEPTION_FILTER)(EXCEPTION_POINTERS *ExceptionInfo);
static LPTOP_LEVEL_EXCEPTION_FILTER g_unhandled_filter = NULL;

/* Flag to prevent recursive signal delivery during exception dispatch */
static __thread int g_dispatching_exception = 0;

/* ----------------------------------------------------------------
 * pe_exception.c integration (real frame-based unwinding)
 * ---------------------------------------------------------------- */

/* RUNTIME_FUNCTION for x64 exception unwinding */
typedef struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

/*
 * pe_exception.c provides the real implementations - resolve at runtime
 * since ntdll is a .so that may load before the loader is fully linked.
 *
 * The lookup/vunwind/unwind_ex functions are ms_abi since they're called
 * from within ntdll's ms_abi (WINAPI_EXPORT) wrapper functions.
 * The dispatch_frames function is sysv_abi since it's called from ntdll's
 * internal (sysv_abi) dispatch_exception().
 */
typedef PRUNTIME_FUNCTION (__attribute__((ms_abi)) *pe_lookup_fn)(
    DWORD64, PDWORD64, PVOID);
typedef void *(__attribute__((ms_abi)) *pe_virtual_unwind_fn)(
    DWORD, DWORD64, DWORD64, PRUNTIME_FUNCTION,
    PCONTEXT, PVOID *, PDWORD64, PVOID);
typedef void (__attribute__((ms_abi)) *pe_unwind_ex_fn)(
    PVOID, PVOID, PEXCEPTION_RECORD, PVOID, PCONTEXT, PVOID);
typedef int (*pe_dispatch_frames_fn)(PEXCEPTION_RECORD, PCONTEXT);

/* These are set by pe_exception_wire_ntdll() called from the loader */
static pe_lookup_fn         g_pe_lookup_entry = NULL;
static pe_virtual_unwind_fn g_pe_virtual_unwind = NULL;
static pe_unwind_ex_fn      g_pe_unwind_ex = NULL;
static pe_dispatch_frames_fn g_pe_dispatch_frames = NULL;

/*
 * Wire the real pe_exception.c implementations into ntdll.
 * Called from pe_exception.c or the loader after both are loaded.
 */
__attribute__((visibility("default")))
void ntdll_exception_wire_pe(void *lookup, void *vunwind,
                              void *unwind_ex, void *dispatch_frames)
{
    /*
     * ORDERING: This must be called before any exceptions can fire
     * (i.e., before the PE entry point runs).  The loader calls this
     * from main.c after loading ntdll but before invoking the PE.
     * A full memory barrier ensures the stores are visible to signal
     * handlers on other cores before we proceed.
     */
    g_pe_lookup_entry = (pe_lookup_fn)lookup;
    g_pe_virtual_unwind = (pe_virtual_unwind_fn)vunwind;
    g_pe_unwind_ex = (pe_unwind_ex_fn)unwind_ex;
    g_pe_dispatch_frames = (pe_dispatch_frames_fn)dispatch_frames;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

/* ----------------------------------------------------------------
 * Signal installation tracking
 * ---------------------------------------------------------------- */

static int g_signals_installed = 0;
static void *g_sigalt_stack_mem = NULL;
static struct sigaction g_old_sigsegv;
static struct sigaction g_old_sigfpe;
static struct sigaction g_old_sigbus;
static struct sigaction g_old_sigill;
static struct sigaction g_old_sigtrap;

/* ----------------------------------------------------------------
 * Fill CONTEXT from ucontext_t (Linux signal context)
 * ---------------------------------------------------------------- */

static void fill_context_from_ucontext(CONTEXT *ctx, ucontext_t *uc)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->ContextFlags = CONTEXT_FULL;

    if (!uc)
        return;

    mcontext_t *mc = &uc->uc_mcontext;

    ctx->Rax = mc->gregs[REG_RAX];
    ctx->Rcx = mc->gregs[REG_RCX];
    ctx->Rdx = mc->gregs[REG_RDX];
    ctx->Rbx = mc->gregs[REG_RBX];
    ctx->Rsp = mc->gregs[REG_RSP];
    ctx->Rbp = mc->gregs[REG_RBP];
    ctx->Rsi = mc->gregs[REG_RSI];
    ctx->Rdi = mc->gregs[REG_RDI];
    ctx->R8  = mc->gregs[REG_R8];
    ctx->R9  = mc->gregs[REG_R9];
    ctx->R10 = mc->gregs[REG_R10];
    ctx->R11 = mc->gregs[REG_R11];
    ctx->R12 = mc->gregs[REG_R12];
    ctx->R13 = mc->gregs[REG_R13];
    ctx->R14 = mc->gregs[REG_R14];
    ctx->R15 = mc->gregs[REG_R15];
    ctx->Rip = mc->gregs[REG_RIP];
    ctx->EFlags = (DWORD)mc->gregs[REG_EFL];
    ctx->SegCs = (WORD)mc->gregs[REG_CSGSFS];
}

/*
 * Apply CONTEXT back to ucontext (for EXCEPTION_CONTINUE_EXECUTION)
 */
static void apply_context_to_ucontext(const CONTEXT *ctx, ucontext_t *uc)
{
    if (!uc)
        return;

    mcontext_t *mc = &uc->uc_mcontext;

    mc->gregs[REG_RAX] = ctx->Rax;
    mc->gregs[REG_RCX] = ctx->Rcx;
    mc->gregs[REG_RDX] = ctx->Rdx;
    mc->gregs[REG_RBX] = ctx->Rbx;
    mc->gregs[REG_RSP] = ctx->Rsp;
    mc->gregs[REG_RBP] = ctx->Rbp;
    mc->gregs[REG_RSI] = ctx->Rsi;
    mc->gregs[REG_RDI] = ctx->Rdi;
    mc->gregs[REG_R8]  = ctx->R8;
    mc->gregs[REG_R9]  = ctx->R9;
    mc->gregs[REG_R10] = ctx->R10;
    mc->gregs[REG_R11] = ctx->R11;
    mc->gregs[REG_R12] = ctx->R12;
    mc->gregs[REG_R13] = ctx->R13;
    mc->gregs[REG_R14] = ctx->R14;
    mc->gregs[REG_R15] = ctx->R15;
    mc->gregs[REG_RIP] = ctx->Rip;
    mc->gregs[REG_EFL] = ctx->EFlags;
}

/* ----------------------------------------------------------------
 * Exception dispatch
 * ---------------------------------------------------------------- */

/*
 * Dispatch an exception through the handler chain.
 * Returns EXCEPTION_CONTINUE_EXECUTION if a handler fixed the problem,
 * EXCEPTION_CONTINUE_SEARCH if no handler claimed it.
 */
/*
 * Resume iteration after a handler ran unlocked. The previous entry's
 * next-pointer may have been free()d by a concurrent Remove call, so we
 * re-locate the entry by id. If the previous entry still exists, return
 * its next-pointer. If it was removed, restart from head. Called with
 * g_veh_lock held.
 */
static veh_entry_t *veh_find_next_after_id(veh_entry_t *head, DWORD last_id)
{
    if (last_id == 0)
        return head;
    for (veh_entry_t *cur = head; cur; cur = cur->next) {
        if (cur->id == last_id)
            return cur->next;
    }
    /* Previous entry was removed while unlocked: restart from head.
     * Track a visited set via id to avoid re-invoking same handlers twice
     * is a larger fix; the short-circuit CONTINUE_EXECUTION below mitigates
     * duplicate dispatch risk. */
    return head;
}

static LONG dispatch_exception(EXCEPTION_POINTERS *ep)
{
    LONG result;
    veh_entry_t *entry;
    DWORD last_id;

    /*
     * Phase 1: Vectored Exception Handlers (first chance).
     *
     * NOTE: dispatch_exception() may be called from a signal handler,
     * where pthread_mutex_lock is not async-signal-safe and will deadlock
     * if the signal interrupted code holding g_veh_lock.  Use trylock:
     * if we can't acquire the lock, skip VEH dispatch (better than deadlock).
     */
    if (pthread_mutex_trylock(&g_veh_lock) == 0) {
        last_id = 0;
        entry = g_veh_first_head;
        while (entry) {
            PVECTORED_EXCEPTION_HANDLER handler = entry->handler;
            DWORD entry_id = entry->id;
            pthread_mutex_unlock(&g_veh_lock);

            result = handler(ep);
            if (result == EXCEPTION_CONTINUE_EXECUTION)
                return EXCEPTION_CONTINUE_EXECUTION;

            if (pthread_mutex_trylock(&g_veh_lock) != 0) {
                /* Can't re-acquire lock; abandon VEH walk.
                 * We already released above, so nothing to unlock. */
                goto veh_done;
            }
            /* Re-locate next entry by id: previously-saved entry->next may
             * have been free()d by a concurrent RemoveVectoredExceptionHandler. */
            last_id = entry_id;
            entry = veh_find_next_after_id(g_veh_first_head, last_id);
        }
        /* Loop ended normally: we still hold the lock from trylock */
        pthread_mutex_unlock(&g_veh_lock);
    }
veh_done:

    /*
     * Phase 2: SEH frame-based handlers.
     * Walk the .pdata unwind tables to find __try/__except handlers.
     * If pe_exception.c is wired in, use real frame-based dispatch.
     */
    if (g_pe_dispatch_frames) {
        int handled = g_pe_dispatch_frames(ep->ExceptionRecord, ep->ContextRecord);
        if (handled)
            return EXCEPTION_CONTINUE_EXECUTION;
    }

    /* Phase 3: Vectored Continue Handlers */
    if (pthread_mutex_trylock(&g_veh_lock) == 0) {
        last_id = 0;
        entry = g_vch_head;
        while (entry) {
            PVECTORED_EXCEPTION_HANDLER handler = entry->handler;
            DWORD entry_id = entry->id;
            pthread_mutex_unlock(&g_veh_lock);

            result = handler(ep);
            if (result == EXCEPTION_CONTINUE_EXECUTION)
                return EXCEPTION_CONTINUE_EXECUTION;

            if (pthread_mutex_trylock(&g_veh_lock) != 0)
                goto vch_done;
            last_id = entry_id;
            entry = veh_find_next_after_id(g_vch_head, last_id);
        }
        pthread_mutex_unlock(&g_veh_lock);
    }
vch_done:

    /* Phase 4: Unhandled exception filter */
    if (g_unhandled_filter) {
        result = g_unhandled_filter(ep);
        if (result == EXCEPTION_CONTINUE_EXECUTION)
            return EXCEPTION_CONTINUE_EXECUTION;
        if (result == EXCEPTION_EXECUTE_HANDLER) {
            /* Filter says handle it - terminate gracefully */
            return EXCEPTION_EXECUTE_HANDLER;
        }
        /* EXCEPTION_CONTINUE_SEARCH - fall through to default */
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/* ----------------------------------------------------------------
 * Signal → Exception translation
 * ---------------------------------------------------------------- */

static DWORD signal_to_exception_code(int sig, siginfo_t *info)
{
    switch (sig) {
    case SIGSEGV:
        return EXCEPTION_ACCESS_VIOLATION;

    case SIGBUS:
        return EXCEPTION_IN_PAGE_ERROR;

    case SIGFPE:
        if (info) {
            switch (info->si_code) {
            case FPE_INTDIV: return EXCEPTION_INT_DIVIDE_BY_ZERO;
            case FPE_INTOVF: return EXCEPTION_INT_OVERFLOW;
            case FPE_FLTDIV: return EXCEPTION_FLT_DIVIDE_BY_ZERO;
            case FPE_FLTOVF: return EXCEPTION_FLT_OVERFLOW;
            case FPE_FLTUND: return EXCEPTION_FLT_UNDERFLOW;
            case FPE_FLTRES: return EXCEPTION_FLT_INEXACT_RESULT;
            case FPE_FLTINV: return EXCEPTION_FLT_INVALID_OPERATION;
            default:         return EXCEPTION_FLT_INVALID_OPERATION;
            }
        }
        return EXCEPTION_FLT_INVALID_OPERATION;

    case SIGILL:
        return EXCEPTION_ILLEGAL_INSTRUCTION;

    case SIGTRAP:
        return EXCEPTION_BREAKPOINT;

    default:
        return EXCEPTION_ACCESS_VIOLATION;
    }
}

static void exception_signal_handler(int sig, siginfo_t *info, void *ucontext_raw)
{
    ucontext_t *uc = (ucontext_t *)ucontext_raw;

    /* Prevent recursive exception dispatch */
    if (g_dispatching_exception) {
        fprintf(stderr, "[ntdll] Recursive exception during dispatch (signal %d), aborting\n", sig);
        _exit(128 + sig);
    }
    g_dispatching_exception = 1;

    /* Build CONTEXT from signal ucontext (needed for ExceptionAddress) */
    CONTEXT ctx;
    fill_context_from_ucontext(&ctx, uc);

    /* Build EXCEPTION_RECORD */
    EXCEPTION_RECORD rec;
    memset(&rec, 0, sizeof(rec));
    rec.ExceptionCode = signal_to_exception_code(sig, info);
    rec.ExceptionFlags = 0;
    rec.ExceptionRecord = NULL;
    /*
     * ExceptionAddress is the INSTRUCTION that caused the fault (RIP),
     * not the faulting data address. info->si_addr is the data address
     * for SIGSEGV/SIGBUS but the instruction address for SIGILL/SIGTRAP.
     */
    rec.ExceptionAddress = (PVOID)ctx.Rip;

    /* For access violations, provide read/write info */
    if (sig == SIGSEGV || sig == SIGBUS) {
        rec.NumberParameters = 2;
        /*
         * Parameter 0: 0=read, 1=write, 8=DEP.
         * Use si_code to distinguish: SEGV_ACCERR on a writable page
         * suggests a write fault, but Linux doesn't reliably expose
         * read vs write. Default to 0 (read).
         */
        rec.ExceptionInformation[0] = 0;
        /* Parameter 1: faulting data address */
        rec.ExceptionInformation[1] = (ULONG_PTR)(info ? info->si_addr : 0);
    }

    /* Build EXCEPTION_POINTERS */
    EXCEPTION_POINTERS ep;
    ep.ExceptionRecord = &rec;
    ep.ContextRecord = &ctx;

    /*
     * Emit PE_EVT_EXCEPTION to the AI Cortex (fire-and-forget telemetry).
     * Payload is a compact fixed-size struct: exception code, faulting RIP,
     * faulting data address (for access violations), and the delivering
     * signal. The cortex uses this to detect crash patterns and per-PID
     * instability without parsing stdout/stderr. Emitted BEFORE dispatch
     * so the cortex hears about exceptions even if a handler swallows them.
     */
    {
        struct __attribute__((packed)) pe_evt_exception {
            uint32_t exception_code;     /* EXCEPTION_ACCESS_VIOLATION etc. */
            uint32_t signo;              /* Delivering POSIX signal */
            uint64_t exception_address;  /* Faulting RIP */
            uint64_t fault_address;      /* si_addr (for SIGSEGV/SIGBUS) */
            uint32_t flags;              /* EXCEPTION_NONCONTINUABLE etc. */
            uint32_t num_parameters;
        } evt;
        memset(&evt, 0, sizeof(evt));
        evt.exception_code    = rec.ExceptionCode;
        evt.signo             = (uint32_t)sig;
        evt.exception_address = (uint64_t)(uintptr_t)rec.ExceptionAddress;
        evt.fault_address     = (rec.NumberParameters >= 2)
                                ? (uint64_t)rec.ExceptionInformation[1]
                                : 0;
        evt.flags             = rec.ExceptionFlags;
        evt.num_parameters    = rec.NumberParameters;
        pe_event_emit(PE_EVT_EXCEPTION, &evt, sizeof(evt));
    }

    /* Dispatch through handler chain */
    LONG result = dispatch_exception(&ep);

    g_dispatching_exception = 0;

    if (result == EXCEPTION_CONTINUE_EXECUTION) {
        /* Handler fixed the problem - apply modified context and resume */
        apply_context_to_ucontext(&ctx, uc);
        return; /* Signal handler returns, execution resumes at modified RIP */
    }

    /* No handler claimed the exception - terminate */
    fprintf(stderr, "[ntdll] Unhandled exception 0x%08X at %p\n",
            rec.ExceptionCode, rec.ExceptionAddress);

    /* Restore original signal handler and re-raise */
    struct sigaction *old = NULL;
    switch (sig) {
    case SIGSEGV: old = &g_old_sigsegv; break;
    case SIGFPE:  old = &g_old_sigfpe;  break;
    case SIGBUS:  old = &g_old_sigbus;  break;
    case SIGILL:  old = &g_old_sigill;  break;
    case SIGTRAP: old = &g_old_sigtrap; break;
    }

    if (old) {
        sigaction(sig, old, NULL);
        raise(sig);
    } else {
        _exit(128 + sig);
    }
}

/* ----------------------------------------------------------------
 * Install/uninstall signal handlers
 * ---------------------------------------------------------------- */

static pthread_mutex_t g_signals_install_lock = PTHREAD_MUTEX_INITIALIZER;

static void install_signal_handlers(void)
{
    /* Double-checked lock: concurrent callers must not both install, because
     * the second install would overwrite g_old_sig* with our own handler,
     * losing the real chained handler and turning re-raise into infinite
     * recursion. */
    if (__atomic_load_n(&g_signals_installed, __ATOMIC_ACQUIRE))
        return;

    pthread_mutex_lock(&g_signals_install_lock);
    if (g_signals_installed) {
        pthread_mutex_unlock(&g_signals_install_lock);
        return;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = exception_signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);

    /* Use alternate signal stack to handle stack overflow */
    stack_t ss;
    if (!g_sigalt_stack_mem)
        g_sigalt_stack_mem = malloc(SIGSTKSZ);
    ss.ss_sp = g_sigalt_stack_mem;
    if (ss.ss_sp) {
        ss.ss_size = SIGSTKSZ;
        ss.ss_flags = 0;
        if (sigaltstack(&ss, NULL) == 0)
            sa.sa_flags |= SA_ONSTACK;
    }

    sigaction(SIGSEGV, &sa, &g_old_sigsegv);
    sigaction(SIGFPE,  &sa, &g_old_sigfpe);
    sigaction(SIGBUS,  &sa, &g_old_sigbus);
    sigaction(SIGILL,  &sa, &g_old_sigill);
    sigaction(SIGTRAP, &sa, &g_old_sigtrap);

    __atomic_store_n(&g_signals_installed, 1, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&g_signals_install_lock);
    return;
}

/* ----------------------------------------------------------------
 * VEH public API
 * ---------------------------------------------------------------- */

static veh_entry_t *add_handler(veh_entry_t **head, veh_entry_t **tail,
                                 ULONG first, PVECTORED_EXCEPTION_HANDLER handler)
{
    veh_entry_t *entry = calloc(1, sizeof(veh_entry_t));
    if (!entry)
        return NULL;

    entry->handler = handler;

    /* Install signal handlers on first registration */
    install_signal_handlers();

    pthread_mutex_lock(&g_veh_lock);
    /* Assign id under the lock so two concurrent adds don't share an id.
     * Also guarantees ids are monotonically increasing in list order, which
     * the safe iterator in dispatch_exception relies on. */
    entry->id = g_veh_next_id++;

    if (first) {
        /* Insert at head */
        entry->next = *head;
        entry->prev = NULL;
        if (*head)
            (*head)->prev = entry;
        *head = entry;
        if (!*tail)
            *tail = entry;
    } else {
        /* Insert at tail */
        entry->prev = *tail;
        entry->next = NULL;
        if (*tail)
            (*tail)->next = entry;
        *tail = entry;
        if (!*head)
            *head = entry;
    }

    pthread_mutex_unlock(&g_veh_lock);
    return entry;
}

static ULONG remove_handler(veh_entry_t **head, veh_entry_t **tail, PVOID handle)
{
    veh_entry_t *entry = (veh_entry_t *)handle;
    if (!entry)
        return 0;

    pthread_mutex_lock(&g_veh_lock);

    /* Verify entry is in the list */
    veh_entry_t *cur = *head;
    int found = 0;
    while (cur) {
        if (cur == entry) {
            found = 1;
            break;
        }
        cur = cur->next;
    }

    if (!found) {
        pthread_mutex_unlock(&g_veh_lock);
        return 0;
    }

    /* Unlink */
    if (entry->prev)
        entry->prev->next = entry->next;
    else
        *head = entry->next;

    if (entry->next)
        entry->next->prev = entry->prev;
    else
        *tail = entry->prev;

    pthread_mutex_unlock(&g_veh_lock);

    free(entry);
    return 1;
}

WINAPI_EXPORT PVOID AddVectoredExceptionHandler(ULONG First,
    PVECTORED_EXCEPTION_HANDLER Handler)
{
    return add_handler(&g_veh_first_head, &g_veh_first_tail, First, Handler);
}

WINAPI_EXPORT ULONG RemoveVectoredExceptionHandler(PVOID Handle)
{
    return remove_handler(&g_veh_first_head, &g_veh_first_tail, Handle);
}

WINAPI_EXPORT PVOID AddVectoredContinueHandler(ULONG First,
    PVECTORED_EXCEPTION_HANDLER Handler)
{
    return add_handler(&g_vch_head, &g_vch_tail, First, Handler);
}

WINAPI_EXPORT ULONG RemoveVectoredContinueHandler(PVOID Handle)
{
    return remove_handler(&g_vch_head, &g_vch_tail, Handle);
}

/* ----------------------------------------------------------------
 * SetUnhandledExceptionFilter (ntdll-level)
 * ---------------------------------------------------------------- */

WINAPI_EXPORT LPTOP_LEVEL_EXCEPTION_FILTER
ntdll_SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpFilter)
{
    install_signal_handlers();
    LPTOP_LEVEL_EXCEPTION_FILTER old = g_unhandled_filter;
    g_unhandled_filter = lpFilter;
    return old;
}

/* ----------------------------------------------------------------
 * RaiseException - dispatch a software exception
 * ---------------------------------------------------------------- */

WINAPI_EXPORT void ntdll_RaiseException(
    DWORD dwExceptionCode,
    DWORD dwExceptionFlags,
    DWORD nNumberOfArguments,
    const ULONG_PTR *lpArguments)
{
    install_signal_handlers();

    EXCEPTION_RECORD rec;
    memset(&rec, 0, sizeof(rec));
    rec.ExceptionCode = dwExceptionCode;
    rec.ExceptionFlags = dwExceptionFlags;
    rec.ExceptionRecord = NULL;
    rec.ExceptionAddress = __builtin_return_address(0);

    if (nNumberOfArguments > EXCEPTION_MAXIMUM_PARAMETERS)
        nNumberOfArguments = EXCEPTION_MAXIMUM_PARAMETERS;
    rec.NumberParameters = nNumberOfArguments;
    if (lpArguments && nNumberOfArguments > 0) {
        memcpy(rec.ExceptionInformation, lpArguments,
               nNumberOfArguments * sizeof(ULONG_PTR));
    }

    /* Build a minimal CONTEXT from current state */
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    /* We can't easily get all registers without inline asm,
     * but the critical one is RIP (return address) */
    ctx.Rip = (DWORD64)(uintptr_t)__builtin_return_address(0);

    EXCEPTION_POINTERS ep;
    ep.ExceptionRecord = &rec;
    ep.ContextRecord = &ctx;

    g_dispatching_exception = 1;
    LONG result = dispatch_exception(&ep);
    g_dispatching_exception = 0;

    if (result == EXCEPTION_CONTINUE_EXECUTION)
        return;

    /* No handler - check if it's a C++ exception (non-fatal by nature) */
    if (dwExceptionCode == EXCEPTION_CPP_MSC) {
        fprintf(stderr, "[ntdll] Unhandled C++ exception (0xE06D7363)\n");
        abort();
    }

    /* Non-continuable or unhandled - terminate */
    fprintf(stderr, "[ntdll] RaiseException: unhandled code=0x%08X, aborting\n",
            dwExceptionCode);
    abort();
}

/* ----------------------------------------------------------------
 * RtlUnwindEx - C++ exception unwind support (minimal stub)
 *
 * Full implementation would walk .pdata/.xdata unwind tables.
 * For now, this stub allows apps that reference it to link.
 * C++ exceptions via _CxxThrowException → RaiseException will
 * be caught by VEH handlers registered by the CRT.
 * ---------------------------------------------------------------- */

WINAPI_EXPORT void RtlUnwindEx(
    PVOID TargetFrame,
    PVOID TargetIp,
    PEXCEPTION_RECORD ExceptionRecord,
    PVOID ReturnValue,
    PCONTEXT OriginalContext,
    PVOID HistoryTable)
{
    /* Delegate to the real implementation if wired */
    if (g_pe_unwind_ex) {
        g_pe_unwind_ex(TargetFrame, TargetIp, ExceptionRecord,
                        ReturnValue, OriginalContext, HistoryTable);
        return;
    }

    /* Fallback stub */
    fprintf(stderr, "[ntdll] RtlUnwindEx called (stub) - "
            "pe_exception.c not wired\n");
}

WINAPI_EXPORT void RtlUnwind(
    PVOID TargetFrame,
    PVOID TargetIp,
    PEXCEPTION_RECORD ExceptionRecord,
    PVOID ReturnValue)
{
    /* RtlUnwind is the 32-bit compatible version; delegate to RtlUnwindEx
     * with NULL context and history table */
    if (g_pe_unwind_ex) {
        g_pe_unwind_ex(TargetFrame, TargetIp, ExceptionRecord,
                        ReturnValue, NULL, NULL);
        return;
    }
}

/* ----------------------------------------------------------------
 * RtlCaptureContext - capture current thread context
 * ---------------------------------------------------------------- */

WINAPI_EXPORT void RtlCaptureContext(PCONTEXT ctx)
{
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
    ctx->ContextFlags = CONTEXT_FULL;
    ctx->Rip = (DWORD64)(uintptr_t)__builtin_return_address(0);
    /* Other registers would need inline asm to capture precisely */
}

/* ----------------------------------------------------------------
 * __C_specific_handler / __CxxFrameHandler3 stubs
 *
 * These are the language-specific exception handlers referenced
 * in .pdata/.xdata tables. Full implementation requires parsing
 * the unwind info. For now, returning EXCEPTION_CONTINUE_SEARCH
 * lets the VEH chain handle most cases.
 * ---------------------------------------------------------------- */

typedef struct _DISPATCHER_CONTEXT {
    DWORD64              ControlPc;
    DWORD64              ImageBase;
    PVOID                FunctionEntry;
    DWORD64              EstablisherFrame;
    DWORD64              TargetIp;
    PCONTEXT             ContextRecord;
    PVOID                LanguageHandler;
    PVOID                HandlerData;
    PVOID                HistoryTable;
    DWORD                ScopeIndex;
    DWORD                Fill0;
} DISPATCHER_CONTEXT, *PDISPATCHER_CONTEXT;

WINAPI_EXPORT int __C_specific_handler(
    PEXCEPTION_RECORD ExceptionRecord,
    PVOID EstablisherFrame,
    PCONTEXT ContextRecord,
    PDISPATCHER_CONTEXT DispatcherContext)
{
    (void)ExceptionRecord;
    (void)EstablisherFrame;
    (void)ContextRecord;
    (void)DispatcherContext;
    return EXCEPTION_CONTINUE_SEARCH;
}

/* __CxxFrameHandler3/4 are MSVC CRT exports, not ntdll exports.
 * See dlls/msvcrt/msvcrt_except.c for those implementations. */

/* ----------------------------------------------------------------
 * RtlLookupFunctionEntry - runtime function table lookup
 *
 * Used by exception unwinding and stack walking. Returns NULL
 * for now (no .pdata parsing), but apps that call this will
 * get a sensible "no entry found" response.
 * ---------------------------------------------------------------- */

WINAPI_EXPORT PRUNTIME_FUNCTION RtlLookupFunctionEntry(
    DWORD64 ControlPc,
    PDWORD64 ImageBase,
    PVOID HistoryTable)
{
    /* Delegate to the real implementation if wired */
    if (g_pe_lookup_entry)
        return g_pe_lookup_entry(ControlPc, ImageBase, HistoryTable);

    /* Fallback stub */
    if (ImageBase)
        *ImageBase = 0;
    return NULL;
}

/* ----------------------------------------------------------------
 * RtlVirtualUnwind - virtual unwind for stack walking
 * ---------------------------------------------------------------- */

WINAPI_EXPORT void *RtlVirtualUnwind(
    DWORD HandlerType,
    DWORD64 ImageBase,
    DWORD64 ControlPc,
    PRUNTIME_FUNCTION FunctionEntry,
    PCONTEXT ContextRecord,
    PVOID *HandlerData,
    PDWORD64 EstablisherFrame,
    PVOID ContextPointers)
{
    /* Delegate to the real implementation if wired */
    if (g_pe_virtual_unwind) {
        return g_pe_virtual_unwind(
            HandlerType, ImageBase, ControlPc, FunctionEntry,
            ContextRecord, HandlerData, EstablisherFrame, ContextPointers);
    }

    /* Fallback stub: leaf function unwind */
    if (ContextRecord) {
        ContextRecord->Rip = *(DWORD64 *)ContextRecord->Rsp;
        ContextRecord->Rsp += 8;
    }
    if (EstablisherFrame && ContextRecord)
        *EstablisherFrame = ContextRecord->Rsp;
    return NULL;
}

/* ----------------------------------------------------------------
 * Exception initialization (called from loader startup)
 * ---------------------------------------------------------------- */

void ntdll_exception_init(void)
{
    install_signal_handlers();
}
