/*
 * pe_exception.c - High-Performance Windows x64 Structured Exception Handling
 *
 * Implements the full Windows x64 exception handling infrastructure with
 * aggressive hot-path optimization:
 *
 *   1. Module registry with cache-line-aligned entries for fast linear scan
 *   2. O(log n) binary search on sorted RUNTIME_FUNCTION tables
 *   3. UNWIND_INFO parsing and unwind code simulation (minimal branching)
 *   4. RtlLookupFunctionEntry - branchless module scan + binary search
 *   5. RtlVirtualUnwind - frame unwinding via computed slot advance
 *   6. Two-phase exception dispatch (search + unwind)
 *   7. Per-module registration with pre-allocated scratch buffers
 *   8. Dynamic function table support for JIT code
 *   9. Integration with ntdll_exception.c signal-based dispatch
 *
 * Performance design:
 *   - Hot data (base, end, table ptr, count) packed in 32 bytes per module
 *   - Module array aligned to 64 bytes (cache line boundary)
 *   - No malloc/free in the exception dispatch path
 *   - __builtin_expect() on all unlikely error/overflow paths
 *   - __attribute__((hot)) on lookup and unwind functions
 *   - Pre-allocated per-thread scratch contexts to avoid stack bloat
 *   - Lock-free module scan (atomic read of module count)
 *
 * References:
 *   - Microsoft PE/COFF Spec: Exception Handling (x64)
 *   - Windows x64 Software Conventions: Stack Usage / Unwind Data
 *   - AMD64 ABI Supplement: Unwind Table Format
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>

#include "pe/pe_header.h"
#include "pe/pe_types.h"
#include "win32/windef.h"
#include "win32/winnt.h"
#include "compat/abi_bridge.h"

#include <dlfcn.h>

#define LOG_PREFIX "[pe_exception] "

/* ================================================================
 * RUNTIME_FUNCTION and UNWIND_INFO structures
 * ================================================================ */

#pragma pack(push, 1)

typedef struct _PE_RUNTIME_FUNCTION {
    uint32_t BeginAddress;      /* RVA of function start */
    uint32_t EndAddress;        /* RVA of function end */
    uint32_t UnwindInfoAddress; /* RVA of UNWIND_INFO (or chained RUNTIME_FUNCTION) */
} PE_RUNTIME_FUNCTION;

/*
 * UNWIND_CODE - individual unwind operation.
 * Each code occupies 1 slot (2 bytes), but some operations use 2 or 3
 * slots depending on the operation code and operand size.
 */
typedef union _PE_UNWIND_CODE {
    struct {
        uint8_t CodeOffset;     /* Offset in prolog where this op takes effect */
        uint8_t UnwindOp : 4;   /* UWOP_xxx operation code */
        uint8_t OpInfo   : 4;   /* Operation-specific info */
    };
    uint16_t FrameOffset;       /* Used as a raw 16-bit value for offsets */
} PE_UNWIND_CODE;

/*
 * UNWIND_INFO header. Located at the UnwindInfoAddress RVA.
 * Variable-length: followed by UnwindCode array, then optionally
 * an exception handler RVA and language-specific data.
 */
typedef struct _PE_UNWIND_INFO {
    uint8_t Version       : 3;  /* Currently version 1 or 2 */
    uint8_t Flags         : 5;  /* UNW_FLAG_xxx */
    uint8_t SizeOfProlog;       /* Size of function prolog in bytes */
    uint8_t CountOfCodes;       /* Number of UNWIND_CODE slots */
    uint8_t FrameRegister : 4;  /* Nonzero = frame pointer register */
    uint8_t FrameOffset   : 4;  /* Scaled offset of frame pointer from RSP */
    PE_UNWIND_CODE UnwindCode[1]; /* Variable-length array [CountOfCodes] */
    /* After aligned UnwindCode array:
     *   If UNW_FLAG_EHANDLER or UNW_FLAG_UHANDLER:
     *     uint32_t ExceptionHandlerRVA;
     *     uint8_t  LanguageSpecificData[];
     *   If UNW_FLAG_CHAININFO:
     *     PE_RUNTIME_FUNCTION ChainedEntry;
     */
} PE_UNWIND_INFO;

#pragma pack(pop)

/* Unwind operation codes */
#define UWOP_PUSH_NONVOL     0   /* Push nonvolatile register */
#define UWOP_ALLOC_LARGE     1   /* Large stack allocation */
#define UWOP_ALLOC_SMALL     2   /* Small stack allocation (8-128 bytes) */
#define UWOP_SET_FPREG       3   /* Set frame pointer register */
#define UWOP_SAVE_NONVOL     4   /* Save nonvolatile register at offset */
#define UWOP_SAVE_NONVOL_FAR 5   /* Save register at large offset */
/* 6-7 are unused/reserved in version 1 */
#define UWOP_SAVE_XMM128     8   /* Save 128-bit XMM register at offset */
#define UWOP_SAVE_XMM128_FAR 9   /* Save XMM with 32-bit offset */
#define UWOP_PUSH_MACHFRAME  10  /* CPU push of machine frame (interrupt/exception) */

/* UNW_FLAG values in UNWIND_INFO.Flags */
#define UNW_FLAG_NHANDLER  0x0   /* No handler */
#define UNW_FLAG_EHANDLER  0x1   /* Has exception handler (__except) */
#define UNW_FLAG_UHANDLER  0x2   /* Has unwind/termination handler (__finally) */
#define UNW_FLAG_CHAININFO 0x4   /* Chained unwind info (large function) */

/* Exception disposition return values from language-specific handlers */
#define ExceptionContinueExecution  0
#define ExceptionContinueSearch     1
#define ExceptionNestedException    2
#define ExceptionCollidedUnwind     3

/* Exception flags */
#define PE_EXCEPTION_NONCONTINUABLE     0x01
#define PE_EXCEPTION_UNWINDING          0x02
#define PE_EXCEPTION_EXIT_UNWIND        0x04
#define PE_EXCEPTION_STACK_INVALID      0x08
#define PE_EXCEPTION_NESTED_CALL        0x10
#define PE_EXCEPTION_TARGET_UNWIND      0x20
#define PE_EXCEPTION_COLLIDED_UNWIND    0x40
#define PE_EXCEPTION_UNWIND             0x66

/* ================================================================
 * CONTEXT structure (x86-64)
 *
 * Local definition matching the layout in ntdll_exception.c.
 * ================================================================ */

typedef struct _PE_CONTEXT {
    DWORD64 P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
    DWORD   ContextFlags;
    DWORD   MxCsr;
    WORD    SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
    DWORD   EFlags;
    DWORD64 Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    DWORD64 Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
    DWORD64 R8, R9, R10, R11, R12, R13, R14, R15;
    DWORD64 Rip;
    /* XMM / floating point save area (XSAVE format) */
    uint8_t FltSave[512];
    /* Vector registers (YMM/ZMM space) */
    uint8_t VectorRegister[26 * 16];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
} PE_CONTEXT;

#define CONTEXT_AMD64               0x00100000
#define CONTEXT_CONTROL             (CONTEXT_AMD64 | 0x0001)
#define CONTEXT_INTEGER             (CONTEXT_AMD64 | 0x0002)
#define CONTEXT_SEGMENTS            (CONTEXT_AMD64 | 0x0004)
#define CONTEXT_FLOATING_POINT      (CONTEXT_AMD64 | 0x0008)
#define CONTEXT_FULL                (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)

#define EXCEPTION_MAXIMUM_PARAMETERS 15

typedef struct _PE_EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _PE_EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} PE_EXCEPTION_RECORD;

typedef struct _PE_EXCEPTION_POINTERS {
    PE_EXCEPTION_RECORD *ExceptionRecord;
    PE_CONTEXT          *ContextRecord;
} PE_EXCEPTION_POINTERS;

/* KNONVOLATILE_CONTEXT_POINTERS - tracks where registers were saved */
typedef struct _KNONVOLATILE_CONTEXT_POINTERS {
    DWORD64 *Rax, *Rcx, *Rdx, *Rbx, *Rsp, *Rbp, *Rsi, *Rdi;
    DWORD64 *R8, *R9, *R10, *R11, *R12, *R13, *R14, *R15;
    void    *Xmm0, *Xmm1, *Xmm2, *Xmm3, *Xmm4, *Xmm5, *Xmm6, *Xmm7;
    void    *Xmm8, *Xmm9, *Xmm10, *Xmm11, *Xmm12, *Xmm13, *Xmm14, *Xmm15;
} KNONVOLATILE_CONTEXT_POINTERS;

/* DISPATCHER_CONTEXT passed to language-specific handlers */
typedef struct _PE_DISPATCHER_CONTEXT {
    DWORD64              ControlPc;
    DWORD64              ImageBase;
    PE_RUNTIME_FUNCTION *FunctionEntry;
    DWORD64              EstablisherFrame;
    DWORD64              TargetIp;
    PE_CONTEXT          *ContextRecord;
    void                *LanguageHandler;
    void                *HandlerData;
    void                *HistoryTable;
    DWORD                ScopeIndex;
    DWORD                Fill0;
} PE_DISPATCHER_CONTEXT;

/*
 * Language-specific exception handler prototype.
 * __C_specific_handler, __CxxFrameHandler3, etc. match this signature.
 */
typedef int (__attribute__((ms_abi)) *PE_EXCEPTION_HANDLER)(
    PE_EXCEPTION_RECORD *ExceptionRecord,
    void *EstablisherFrame,
    PE_CONTEXT *ContextRecord,
    PE_DISPATCHER_CONTEXT *DispatcherContext);

/* ================================================================
 * 1. Module Registry - Cache-Line Optimized
 *
 * Hot-path data layout: image_base + image_end + func_table + entry_count
 * packed into 32 bytes = half a cache line. Two modules fit in one
 * 64-byte cache line, giving excellent spatial locality for the
 * linear scan in pe_lookup_function_entry().
 *
 * The module array is 64-byte aligned so the first entry starts at
 * a cache line boundary.
 * ================================================================ */

#define PE_EX_MAX_MODULES 256

/* 32 bytes: two of these fit in one 64-byte cache line */
typedef struct {
    uint64_t                  image_base;    /*  0: module base VA */
    uint64_t                  image_end;     /*  8: image_base + image_size */
    const PE_RUNTIME_FUNCTION *func_table;   /* 16: pointer to sorted .pdata */
    uint32_t                  entry_count;   /* 24: number of RUNTIME_FUNCTION entries */
    uint32_t                  _pad;          /* 28: pad to 32 bytes */
} pe_ex_module_t;

/*
 * Module array: aligned to 64 bytes for cache line start.
 * g_module_count is atomic so the hot-path lookup can read it
 * without acquiring the mutex. Writes are protected by g_module_lock.
 */
static pe_ex_module_t g_modules[PE_EX_MAX_MODULES]
    __attribute__((aligned(64)));
static atomic_int g_module_count = 0;
static pthread_mutex_t g_module_lock = PTHREAD_MUTEX_INITIALIZER;

/* ================================================================
 * Dynamic function table - for JIT code without .pdata
 * ================================================================ */

#define MAX_DYNAMIC_TABLES 64

typedef struct {
    uint64_t                  range_start;
    uint64_t                  range_end;
    const PE_RUNTIME_FUNCTION *func_table;
    uint32_t                  entry_count;
    uint32_t                  _pad;
} pe_ex_dynamic_t;

static pe_ex_dynamic_t g_dynamic_tables[MAX_DYNAMIC_TABLES]
    __attribute__((aligned(64)));
static atomic_int g_dynamic_table_count = 0;
static pthread_mutex_t g_dynamic_lock = PTHREAD_MUTEX_INITIALIZER;

/* ================================================================
 * Pre-allocated scratch buffers
 *
 * No malloc in the dispatch path. Two per-thread contexts are
 * statically allocated for the two-phase dispatch (search + unwind).
 * ================================================================ */

static __thread PE_CONTEXT g_scratch_ctx_search;
static __thread PE_CONTEXT g_scratch_ctx_unwind;
static __thread PE_DISPATCHER_CONTEXT g_scratch_dc;

/* Depth counter for nested exception dispatch. When depth > 0, stack-allocated
 * scratch contexts are used instead of the thread-local statics to avoid
 * corruption from reentrant nested exceptions. */
static __thread int g_dispatch_depth = 0;

/* Maximum frame depth for exception dispatch */
#define MAX_UNWIND_FRAMES 256

/* Maximum chain depth for chained UNWIND_INFO */
#define MAX_CHAIN_DEPTH 32

/* ================================================================
 * Register accessor helpers
 *
 * Map x64 register numbers (UNWIND_CODE.OpInfo) to CONTEXT offsets.
 * Windows x64 numbering:
 *   0=RAX 1=RCX 2=RDX 3=RBX 4=RSP 5=RBP 6=RSI 7=RDI
 *   8=R8  9=R9  10=R10 11=R11 12=R12 13=R13 14=R14 15=R15
 *
 * Uses a static lookup table for O(1) access, avoiding the switch
 * overhead that is hostile to branch prediction.
 * ================================================================ */

/*
 * Offset of each GP register within PE_CONTEXT, indexed by
 * the Windows x64 register number (0-15).
 *
 * This table is computed once at compile time. context_reg_ptr()
 * just adds the offset to the context base pointer -- no branches.
 */
static const int g_reg_offsets[16] = {
    [0]  = __builtin_offsetof(PE_CONTEXT, Rax),
    [1]  = __builtin_offsetof(PE_CONTEXT, Rcx),
    [2]  = __builtin_offsetof(PE_CONTEXT, Rdx),
    [3]  = __builtin_offsetof(PE_CONTEXT, Rbx),
    [4]  = __builtin_offsetof(PE_CONTEXT, Rsp),
    [5]  = __builtin_offsetof(PE_CONTEXT, Rbp),
    [6]  = __builtin_offsetof(PE_CONTEXT, Rsi),
    [7]  = __builtin_offsetof(PE_CONTEXT, Rdi),
    [8]  = __builtin_offsetof(PE_CONTEXT, R8),
    [9]  = __builtin_offsetof(PE_CONTEXT, R9),
    [10] = __builtin_offsetof(PE_CONTEXT, R10),
    [11] = __builtin_offsetof(PE_CONTEXT, R11),
    [12] = __builtin_offsetof(PE_CONTEXT, R12),
    [13] = __builtin_offsetof(PE_CONTEXT, R13),
    [14] = __builtin_offsetof(PE_CONTEXT, R14),
    [15] = __builtin_offsetof(PE_CONTEXT, R15),
};

static inline __attribute__((always_inline))
DWORD64 *context_reg_ptr(PE_CONTEXT *ctx, unsigned reg)
{
    if (__builtin_expect(reg > 15, 0))
        return NULL;
    return (DWORD64 *)((uint8_t *)ctx + g_reg_offsets[reg]);
}

/*
 * Context pointers: track where nonvolatile registers were saved
 * on the stack, for debuggers and unwinders.
 */
static inline void context_pointers_set_reg(
    KNONVOLATILE_CONTEXT_POINTERS *ptrs, unsigned reg, DWORD64 *location)
{
    if (__builtin_expect(!ptrs || reg > 15, 0))
        return;
    /* Integer register pointers are laid out contiguously in order */
    ((DWORD64 **)ptrs)[reg] = location;
}

static inline void context_pointers_set_xmm(
    KNONVOLATILE_CONTEXT_POINTERS *ptrs, unsigned reg, void *location)
{
    if (__builtin_expect(!ptrs || reg > 15, 0))
        return;
    /* XMM pointers start at offset 16 DWORD64* into the struct */
    ((void **)ptrs)[16 + reg] = location;
}

/* ================================================================
 * Unwind code slot count table
 *
 * Pre-computed number of UNWIND_CODE slots consumed by each
 * operation. For UWOP_ALLOC_LARGE the count depends on OpInfo,
 * so we store 0 as a sentinel and handle it inline.
 *
 * Index: UWOP code (0-10). Slots for code 6,7 are 1 (unknown/skip).
 * ================================================================ */

static const uint8_t g_uwop_base_slots[16] = {
    [UWOP_PUSH_NONVOL]     = 1,
    [UWOP_ALLOC_LARGE]     = 0,   /* sentinel: depends on OpInfo */
    [UWOP_ALLOC_SMALL]     = 1,
    [UWOP_SET_FPREG]       = 1,
    [UWOP_SAVE_NONVOL]     = 2,
    [UWOP_SAVE_NONVOL_FAR] = 3,
    [6]                     = 1,   /* reserved */
    [7]                     = 1,   /* reserved */
    [UWOP_SAVE_XMM128]     = 2,
    [UWOP_SAVE_XMM128_FAR] = 3,
    [UWOP_PUSH_MACHFRAME]  = 1,
    [11] = 1, [12] = 1, [13] = 1, [14] = 1, [15] = 1,
};

static inline __attribute__((always_inline))
int unwind_code_slots(const PE_UNWIND_CODE *code)
{
    unsigned op = code->UnwindOp;
    uint8_t base = g_uwop_base_slots[op & 0xF];
    if (__builtin_expect(base != 0, 1))
        return base;
    /* UWOP_ALLOC_LARGE: OpInfo=0 -> 2 slots, OpInfo=1 -> 3 slots */
    return (code->OpInfo == 0) ? 2 : 3;
}

/* Look up module image size from the module registry given image_base.
 * Returns 0 if no matching module is found. Lock-free read. */
static uint64_t get_module_image_size(uint64_t image_base)
{
    int count = atomic_load_explicit(&g_module_count, memory_order_acquire);
    for (int i = 0; i < count; i++) {
        if (g_modules[i].image_base == image_base)
            return g_modules[i].image_end - g_modules[i].image_base;
    }
    /* Check dynamic tables */
    int dyn_count = atomic_load_explicit(&g_dynamic_table_count, memory_order_acquire);
    for (int i = 0; i < dyn_count; i++) {
        if (g_dynamic_tables[i].range_start == image_base)
            return g_dynamic_tables[i].range_end - g_dynamic_tables[i].range_start;
    }
    return 0;
}

/* ================================================================
 * 2. Module Registration
 *
 * Writes are mutex-protected. The atomic g_module_count allows
 * the hot-path lookup to avoid locking entirely on reads.
 * ================================================================ */

__attribute__((visibility("default")))
void pe_exception_register_module(uint64_t image_base,
                                   uint64_t image_size,
                                   const void *func_table_ptr,
                                   uint32_t entry_count)
{
    const PE_RUNTIME_FUNCTION *func_table =
        (const PE_RUNTIME_FUNCTION *)func_table_ptr;

    if (__builtin_expect(!func_table || entry_count == 0, 0))
        return;

    pthread_mutex_lock(&g_module_lock);

    int count = atomic_load_explicit(&g_module_count, memory_order_relaxed);

    /* Find a free slot: check for image_base == 0 (cleared entry) */
    int slot = -1;
    for (int i = 0; i < count; i++) {
        if (g_modules[i].image_base == 0) {
            slot = i;
            break;
        }
    }

    /* No free slot found, append at end */
    if (__builtin_expect(slot < 0, 1)) {
        if (__builtin_expect(count >= PE_EX_MAX_MODULES, 0)) {
            fprintf(stderr, LOG_PREFIX "WARNING: Module table full (%d), "
                    "cannot register module at 0x%lX\n",
                    PE_EX_MAX_MODULES, (unsigned long)image_base);
            pthread_mutex_unlock(&g_module_lock);
            return;
        }
        slot = count;
    }

    /* Fill the slot. Write entry_count last with a store-release
     * so readers see the complete entry. */
    g_modules[slot].image_base  = image_base;
    g_modules[slot].image_end   = image_base + image_size;
    g_modules[slot].func_table  = func_table;
    g_modules[slot]._pad        = 0;
    /* Memory barrier: ensure fields are visible before count update */
    __atomic_store_n(&g_modules[slot].entry_count, entry_count,
                     __ATOMIC_RELEASE);

    if (slot >= count)
        atomic_store_explicit(&g_module_count, slot + 1,
                              memory_order_release);

    pthread_mutex_unlock(&g_module_lock);

    printf(LOG_PREFIX "Registered module: base=0x%lX end=0x%lX entries=%u\n",
           (unsigned long)image_base,
           (unsigned long)(image_base + image_size),
           entry_count);
}

__attribute__((visibility("default")))
void pe_exception_unregister_module(uint64_t image_base)
{
    pthread_mutex_lock(&g_module_lock);

    int count = atomic_load_explicit(&g_module_count, memory_order_relaxed);
    for (int i = 0; i < count; i++) {
        if (g_modules[i].image_base == image_base) {
            /* Zero the entry to mark it free. entry_count=0 first
             * so concurrent readers skip it immediately. */
            atomic_store_explicit(
                (_Atomic uint32_t *)&g_modules[i].entry_count, 0,
                memory_order_release);
            g_modules[i].func_table = NULL;
            g_modules[i].image_base = 0;
            g_modules[i].image_end  = 0;
            printf(LOG_PREFIX "Unregistered module at 0x%lX\n",
                   (unsigned long)image_base);
            break;
        }
    }

    pthread_mutex_unlock(&g_module_lock);
}

/* ================================================================
 * Dynamic function table management (for JIT code)
 * ================================================================ */

int pe_exception_add_dynamic_table(uint64_t range_start, uint64_t range_end,
                                    PE_RUNTIME_FUNCTION *func_table,
                                    uint32_t entry_count)
{
    pthread_mutex_lock(&g_dynamic_lock);

    int count = atomic_load_explicit(&g_dynamic_table_count,
                                     memory_order_relaxed);
    int slot = -1;

    for (int i = 0; i < count; i++) {
        if (g_dynamic_tables[i].range_start == 0) {
            slot = i;
            break;
        }
    }

    if (__builtin_expect(slot < 0, 1)) {
        if (__builtin_expect(count >= MAX_DYNAMIC_TABLES, 0)) {
            pthread_mutex_unlock(&g_dynamic_lock);
            return -1;
        }
        slot = count;
    }

    g_dynamic_tables[slot].range_start = range_start;
    g_dynamic_tables[slot].range_end   = range_end;
    g_dynamic_tables[slot].func_table  = func_table;
    g_dynamic_tables[slot]._pad        = 0;
    __atomic_store_n(&g_dynamic_tables[slot].entry_count, entry_count,
                     __ATOMIC_RELEASE);

    if (slot >= count)
        atomic_store_explicit(&g_dynamic_table_count, slot + 1,
                              memory_order_release);

    pthread_mutex_unlock(&g_dynamic_lock);
    return 0;
}

int pe_exception_remove_dynamic_table(uint64_t range_start)
{
    pthread_mutex_lock(&g_dynamic_lock);

    int count = atomic_load_explicit(&g_dynamic_table_count,
                                     memory_order_relaxed);
    for (int i = 0; i < count; i++) {
        if (g_dynamic_tables[i].range_start == range_start &&
            g_dynamic_tables[i].entry_count > 0) {
            atomic_store_explicit(
                (_Atomic uint32_t *)&g_dynamic_tables[i].entry_count, 0,
                memory_order_release);
            g_dynamic_tables[i].func_table  = NULL;
            g_dynamic_tables[i].range_start = 0;
            g_dynamic_tables[i].range_end   = 0;
            pthread_mutex_unlock(&g_dynamic_lock);
            return 0;
        }
    }

    pthread_mutex_unlock(&g_dynamic_lock);
    return -1;
}

/* ================================================================
 * 3. Binary search for RUNTIME_FUNCTION by RVA
 *
 * The .pdata table is sorted by BeginAddress (Windows guarantees
 * this). We use a standard binary search with the invariant that
 * functions do not overlap, so each RVA maps to at most one entry.
 *
 * Marked __attribute__((hot)) to keep it in the hot code section.
 * ================================================================ */

__attribute__((hot))
static PE_RUNTIME_FUNCTION *binary_search_func_table(
    const PE_RUNTIME_FUNCTION *table, uint32_t count, uint32_t rva)
{
    if (__builtin_expect(!table || count == 0, 0))
        return NULL;

    uint32_t lo = 0;
    uint32_t hi = count;

    while (lo < hi) {
        uint32_t mid = lo + ((hi - lo) >> 1);
        const PE_RUNTIME_FUNCTION *entry = &table[mid];

        if (rva < entry->BeginAddress) {
            hi = mid;
        } else if (rva >= entry->EndAddress) {
            lo = mid + 1;
        } else {
            /* rva is within [BeginAddress, EndAddress) */
            return (PE_RUNTIME_FUNCTION *)entry;
        }
    }

    return NULL;
}

/* ================================================================
 * 4. RtlLookupFunctionEntry - Hot-path module scan + binary search
 *
 * Lock-free read of the module array. The atomic g_module_count
 * ensures we see a consistent snapshot. Each entry's image_base
 * and image_end are checked with a single comparison:
 *   (rip - image_base) < (image_end - image_base)
 * which is equivalent to image_base <= rip < image_end but
 * produces one SUB + one CMP (branchless-friendly).
 *
 * We do NOT acquire g_module_lock here. The worst that can happen
 * during a concurrent register/unregister is reading a partially
 * visible entry, which we guard against by checking entry_count != 0
 * with an acquire load after the range check passes.
 * ================================================================ */

__attribute__((hot, visibility("default")))
PE_RUNTIME_FUNCTION *pe_lookup_function_entry(uint64_t control_pc,
                                               uint64_t *image_base_out,
                                               void *history_table)
{
    (void)history_table;

    /* --- Static module tables (hot path) --- */
    int count = atomic_load_explicit(&g_module_count, memory_order_acquire);

    for (int i = 0; i < count; i++) {
        /*
         * Range check: is control_pc within [image_base, image_end)?
         * Using unsigned subtraction: if control_pc < image_base,
         * the result wraps to a very large value that will be >= span.
         */
        uint64_t base = g_modules[i].image_base;
        uint64_t span = g_modules[i].image_end - base;
        uint64_t offset = control_pc - base;

        if (__builtin_expect(offset < span, 0)) {
            /* Acquire-load entry_count to see the complete entry */
            uint32_t ec = __atomic_load_n(&g_modules[i].entry_count,
                                          __ATOMIC_ACQUIRE);
            if (__builtin_expect(ec == 0, 0))
                continue; /* Entry being removed */

            uint32_t rva = (uint32_t)offset;
            PE_RUNTIME_FUNCTION *entry = binary_search_func_table(
                g_modules[i].func_table, ec, rva);

            if (__builtin_expect(entry != NULL, 1)) {
                if (image_base_out)
                    *image_base_out = base;
                return entry;
            }
            /* RVA fell in a gap between functions in this module */
        }
    }

    /* --- Dynamic function tables (cold path, JIT) --- */
    int dyn_count = atomic_load_explicit(&g_dynamic_table_count,
                                         memory_order_acquire);

    for (int i = 0; i < dyn_count; i++) {
        uint64_t start = g_dynamic_tables[i].range_start;
        uint64_t span  = g_dynamic_tables[i].range_end - start;
        uint64_t offset = control_pc - start;

        if (__builtin_expect(offset < span, 0)) {
            uint32_t ec = __atomic_load_n(&g_dynamic_tables[i].entry_count,
                                          __ATOMIC_ACQUIRE);
            if (__builtin_expect(ec == 0, 0))
                continue;

            uint32_t rva = (uint32_t)offset;
            PE_RUNTIME_FUNCTION *entry = binary_search_func_table(
                g_dynamic_tables[i].func_table, ec, rva);

            if (entry) {
                if (image_base_out)
                    *image_base_out = start;
                return entry;
            }
        }
    }

    /* No entry found: leaf function or code outside PE modules */
    if (image_base_out)
        *image_base_out = 0;
    return NULL;
}

/* ================================================================
 * 5. UNWIND_INFO accessor helpers
 * ================================================================ */

static inline __attribute__((always_inline))
PE_UNWIND_INFO *get_unwind_info(uint64_t image_base,
                                 uint64_t image_size,
                                 const PE_RUNTIME_FUNCTION *func)
{
    if (__builtin_expect(func->UnwindInfoAddress >= image_size, 0))
        return NULL;
    return (PE_UNWIND_INFO *)((uintptr_t)image_base + func->UnwindInfoAddress);
}

/*
 * Get the exception handler RVA and handler data pointer from an
 * UNWIND_INFO that has UNW_FLAG_EHANDLER or UNW_FLAG_UHANDLER.
 *
 * The handler RVA is located after the (DWORD-aligned) unwind code array.
 */
static inline int get_exception_handler_info(const PE_UNWIND_INFO *info,
                                              uint32_t *handler_rva,
                                              void **handler_data)
{
    uint8_t flags = info->Flags;
    if (__builtin_expect(!(flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)), 1))
        return -1;

    /* Round CountOfCodes up to even for DWORD alignment */
    if (info->CountOfCodes == 0xFF)
        return -1; /* Prevent overflow: 0xFF + 1 is fine but guard against pathological values */
    uint32_t aligned_count = (info->CountOfCodes + 1) & ~1u;
    const uint32_t *after_codes =
        (const uint32_t *)&info->UnwindCode[aligned_count];

    if (handler_rva)
        *handler_rva = after_codes[0];
    if (handler_data)
        *handler_data = (void *)&after_codes[1];

    return 0;
}

/*
 * Get chained RUNTIME_FUNCTION from UNW_FLAG_CHAININFO.
 */
static inline PE_RUNTIME_FUNCTION *get_chained_function_entry(
    const PE_UNWIND_INFO *info)
{
    uint32_t aligned_count = (info->CountOfCodes + 1) & ~1u;
    return (PE_RUNTIME_FUNCTION *)&info->UnwindCode[aligned_count];
}

/* ================================================================
 * 6. RtlVirtualUnwind - Frame Unwinder
 *
 * Processes UNWIND_CODEs to reverse the function prolog and recover
 * the caller's register state. Marked hot for code placement.
 *
 * Parameters:
 *   handler_type       - UNW_FLAG_EHANDLER or UNW_FLAG_UHANDLER
 *   image_base         - module base VA
 *   control_pc         - current RIP
 *   function_entry     - RUNTIME_FUNCTION for this frame
 *   context            - register context (modified in place)
 *   handler_data       - receives language-specific data pointer
 *   establisher_frame  - receives the frame pointer value
 *   context_pointers   - optional register save location tracker
 *
 * Returns: pointer to the exception handler, or NULL.
 * ================================================================ */

__attribute__((hot, visibility("default")))
PE_EXCEPTION_HANDLER pe_virtual_unwind(
    uint32_t handler_type,
    uint64_t image_base,
    uint64_t control_pc,
    PE_RUNTIME_FUNCTION *function_entry,
    PE_CONTEXT *context,
    void **handler_data,
    uint64_t *establisher_frame,
    KNONVOLATILE_CONTEXT_POINTERS *context_pointers)
{
    PE_EXCEPTION_HANDLER handler = NULL;

    if (__builtin_expect(!function_entry || !context, 0)) {
        /* Leaf function: return address is at [RSP] */
        if (context) {
            context->Rip = *(uint64_t *)(uintptr_t)context->Rsp;
            context->Rsp += 8;
        }
        if (establisher_frame)
            *establisher_frame = context ? context->Rsp : 0;
        return NULL;
    }

    uint64_t image_sz = get_module_image_size(image_base);
    PE_UNWIND_INFO *info = get_unwind_info(image_base, image_sz, function_entry);
    if (__builtin_expect(!info, 0)) {
        context->Rip = *(uint64_t *)(uintptr_t)context->Rsp;
        context->Rsp += 8;
        if (establisher_frame)
            *establisher_frame = context->Rsp;
        return NULL;
    }

    /*
     * Determine prolog offset. If control_pc is past the prolog,
     * process ALL codes. If within prolog, only process codes whose
     * CodeOffset <= our position.
     */
    uint64_t func_start = image_base + function_entry->BeginAddress;
    uint32_t prolog_offset;

    if (__builtin_expect(control_pc <= func_start + info->SizeOfProlog, 0)) {
        prolog_offset = (uint32_t)(control_pc - func_start);
    } else {
        /* Past prolog: process all codes. Use a sentinel larger than
         * any possible prolog byte offset (max 255). */
        prolog_offset = 0xFFFF;
    }

    /*
     * Frame pointer handling.
     * If FrameRegister != 0, the function established a frame pointer.
     * RSP is restored from the frame register rather than unwinding
     * stack allocations manually.
     */
    int has_frame_register = (info->FrameRegister != 0);
    uint64_t frame_base = 0;

    if (has_frame_register) {
        DWORD64 *fp_reg = context_reg_ptr(context, info->FrameRegister);
        if (__builtin_expect(fp_reg != NULL, 1)) {
            frame_base = *fp_reg - (uint64_t)info->FrameOffset * 16;
        }
    }

    /* Set the establisher frame */
    if (establisher_frame) {
        *establisher_frame = has_frame_register ? frame_base : context->Rsp;
    }

    /*
     * Process unwind codes. Walk the chain of UNWIND_INFOs if present.
     * The main info is processed first, then chained extensions.
     */
    PE_UNWIND_INFO *current_info = info;
    int chain_depth = 0;

    while (current_info && chain_depth < MAX_CHAIN_DEPTH) {
        uint8_t count = current_info->CountOfCodes;
        PE_UNWIND_CODE *codes = current_info->UnwindCode;

        int i = 0;
        while (i < count) {
            PE_UNWIND_CODE *code = &codes[i];
            int slots = unwind_code_slots(code);

            /* Skip codes that haven't been executed yet (within prolog) */
            if (code->CodeOffset > prolog_offset) {
                i += slots;
                continue;
            }

            unsigned op = code->UnwindOp;
            unsigned op_info = code->OpInfo;

            switch (op) {

            case UWOP_PUSH_NONVOL: {
                DWORD64 *reg_ptr = context_reg_ptr(context, op_info);
                DWORD64 *stack_loc = (DWORD64 *)(uintptr_t)context->Rsp;
                if (__builtin_expect(reg_ptr != NULL, 1)) {
                    *reg_ptr = *stack_loc;
                    context_pointers_set_reg(context_pointers, op_info,
                                             stack_loc);
                }
                context->Rsp += 8;
                break;
            }

            case UWOP_ALLOC_LARGE: {
                uint32_t alloc_size;
                if (op_info == 0) {
                    if (i + 1 >= count) break;
                    /* 16-bit value * 8 in next slot */
                    alloc_size = (uint32_t)codes[i + 1].FrameOffset * 8;
                } else {
                    if (i + 2 >= count) break;
                    /* 32-bit value in next two slots */
                    alloc_size = (uint32_t)codes[i + 1].FrameOffset |
                                 ((uint32_t)codes[i + 2].FrameOffset << 16);
                }
                context->Rsp += alloc_size;
                break;
            }

            case UWOP_ALLOC_SMALL: {
                /* Allocation = OpInfo * 8 + 8 (range 8..128) */
                context->Rsp += (uint32_t)op_info * 8 + 8;
                break;
            }

            case UWOP_SET_FPREG: {
                if (has_frame_register)
                    context->Rsp = frame_base;
                break;
            }

            case UWOP_SAVE_NONVOL: {
                if (i + 1 >= count) break;
                uint32_t offset = (uint32_t)codes[i + 1].FrameOffset * 8;
                uint64_t base_addr = has_frame_register
                    ? frame_base : context->Rsp;
                DWORD64 *save_loc = (DWORD64 *)(uintptr_t)(base_addr + offset);
                DWORD64 *reg_ptr = context_reg_ptr(context, op_info);
                if (__builtin_expect(reg_ptr != NULL, 1)) {
                    *reg_ptr = *save_loc;
                    context_pointers_set_reg(context_pointers, op_info,
                                             save_loc);
                }
                break;
            }

            case UWOP_SAVE_NONVOL_FAR: {
                if (i + 2 >= count) break;
                uint32_t offset = (uint32_t)codes[i + 1].FrameOffset |
                                  ((uint32_t)codes[i + 2].FrameOffset << 16);
                uint64_t base_addr = has_frame_register
                    ? frame_base : context->Rsp;
                DWORD64 *save_loc = (DWORD64 *)(uintptr_t)(base_addr + offset);
                DWORD64 *reg_ptr = context_reg_ptr(context, op_info);
                if (__builtin_expect(reg_ptr != NULL, 1)) {
                    *reg_ptr = *save_loc;
                    context_pointers_set_reg(context_pointers, op_info,
                                             save_loc);
                }
                break;
            }

            case UWOP_SAVE_XMM128: {
                if (i + 1 >= count) break;
                uint32_t offset = (uint32_t)codes[i + 1].FrameOffset * 16;
                uint64_t base_addr = has_frame_register
                    ? frame_base : context->Rsp;
                void *save_loc = (void *)(uintptr_t)(base_addr + offset);
                /* XMM regs at FltSave + 0x60 + reg*16 (FXSAVE layout) */
                uint8_t *xmm_dst = context->FltSave + 0x60 + op_info * 16;
                memcpy(xmm_dst, save_loc, 16);
                context_pointers_set_xmm(context_pointers, op_info, save_loc);
                break;
            }

            case UWOP_SAVE_XMM128_FAR: {
                if (i + 2 >= count) break;
                uint32_t offset = (uint32_t)codes[i + 1].FrameOffset |
                                  ((uint32_t)codes[i + 2].FrameOffset << 16);
                uint64_t base_addr = has_frame_register
                    ? frame_base : context->Rsp;
                void *save_loc = (void *)(uintptr_t)(base_addr + offset);
                uint8_t *xmm_dst = context->FltSave + 0x60 + op_info * 16;
                memcpy(xmm_dst, save_loc, 16);
                context_pointers_set_xmm(context_pointers, op_info, save_loc);
                break;
            }

            case UWOP_PUSH_MACHFRAME: {
                /*
                 * CPU pushed a machine frame on interrupt/exception.
                 * OpInfo=0: [RSP]=RIP, [RSP+8]=CS, [RSP+16]=EFLAGS,
                 *           [RSP+24]=old RSP, [RSP+32]=SS
                 * OpInfo=1: [RSP]=error code (skip it)
                 */
                uint64_t *frame = (uint64_t *)(uintptr_t)(
                    context->Rsp + (op_info ? 8 : 0));
                context->Rip = frame[0];
                context->Rsp = frame[3];
                context->EFlags = (DWORD)frame[2];
                i += slots;
                goto next_chain; /* RIP set directly, skip final pop */
            }

            default:
                /* Unknown opcode: skip and continue */
                break;
            }

            i += slots;
        }

        /*
         * Check for exception handler at any chain depth.
         * The Windows ABI allows handler flags to be set on any
         * UNWIND_INFO in the chain, not just the primary one.
         */
        {
            uint8_t flags = current_info->Flags;
            if ((handler_type & flags) &&
                (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER))) {
                uint32_t handler_rva = 0;
                if (get_exception_handler_info(current_info, &handler_rva,
                                                handler_data) == 0) {
                    handler = (PE_EXCEPTION_HANDLER)(
                        (uintptr_t)image_base + handler_rva);
                }
            }
        }

        /* Follow chain if present */
        if (current_info->Flags & UNW_FLAG_CHAININFO) {
            PE_RUNTIME_FUNCTION *chained =
                get_chained_function_entry(current_info);
            if (__builtin_expect(chained != NULL, 1)) {
                current_info = get_unwind_info(image_base, image_sz, chained);
                chain_depth++;
                continue;
            }
        }

        break;
    }

    /*
     * Pop return address from the stack into RIP.
     * After all prolog operations are reversed, [RSP] holds the
     * return address that was pushed by the CALL instruction.
     */
    context->Rip = *(uint64_t *)(uintptr_t)context->Rsp;
    context->Rsp += 8;

next_chain:
    return handler;
}

/* ================================================================
 * 7. Parse and register .pdata section from a PE image
 * ================================================================ */

__attribute__((visibility("default")))
int pe_exception_register_image(pe_image_t *image)
{
    if (__builtin_expect(!image || !image->mapped_base, 0))
        return -1;

    if (image->number_of_rva_and_sizes <= PE_DIR_EXCEPTION)
        return 0;

    pe_data_directory_t *exc_dir = &image->data_directory[PE_DIR_EXCEPTION];
    if (exc_dir->virtual_address == 0 || exc_dir->size == 0)
        return 0;

    PE_RUNTIME_FUNCTION *pdata = (PE_RUNTIME_FUNCTION *)pe_rva_to_ptr(
        image, exc_dir->virtual_address);
    if (__builtin_expect(!pdata, 0)) {
        fprintf(stderr, LOG_PREFIX "WARNING: .pdata RVA 0x%X out of bounds\n",
                exc_dir->virtual_address);
        return -1;
    }

    uint32_t entry_count = exc_dir->size / sizeof(PE_RUNTIME_FUNCTION);
    if (entry_count == 0)
        return 0;

    /* Validate a few entries to detect corrupted tables early */
    for (uint32_t i = 0; i < entry_count && i < 8; i++) {
        if (pdata[i].BeginAddress >= image->size_of_image ||
            pdata[i].EndAddress > image->size_of_image ||
            pdata[i].BeginAddress >= pdata[i].EndAddress) {
            fprintf(stderr, LOG_PREFIX "WARNING: Suspicious .pdata entry %u: "
                    "begin=0x%X end=0x%X\n", i,
                    pdata[i].BeginAddress, pdata[i].EndAddress);
            entry_count = i;
            break;
        }
    }

    printf(LOG_PREFIX ".pdata: %u entries at RVA 0x%X\n",
           entry_count, exc_dir->virtual_address);

    pe_exception_register_module(
        image->actual_base,
        image->mapped_size,
        pdata,
        entry_count);

    return 0;
}

/* ================================================================
 * 8. Two-Phase Exception Dispatch
 *
 * Phase 1 (Search): Walk frames looking for UNW_FLAG_EHANDLER that
 *   returns ExceptionExecuteHandler (positive disposition).
 * Phase 2 (Unwind): Unwind to the handling frame, calling
 *   UNW_FLAG_UHANDLER (__finally) handlers along the way.
 *
 * Uses pre-allocated scratch contexts to avoid stack/heap allocation.
 * ================================================================ */

__attribute__((visibility("default")))
int pe_exception_dispatch_frames(PE_EXCEPTION_RECORD *exception_record,
                                  PE_CONTEXT *context)
{
    if (__builtin_expect(!exception_record || !context, 0))
        return 0;

    /* Use stack-allocated scratch contexts for nested exceptions (depth > 0)
     * to prevent corruption of the outer dispatch's scratch state. */
    PE_CONTEXT *search_ctx, *unwind_ctx_scratch;
    PE_DISPATCHER_CONTEXT *dc_scratch;
    PE_CONTEXT local_search, local_unwind;
    PE_DISPATCHER_CONTEXT local_dc;
    if (g_dispatch_depth > 0) {
        search_ctx = &local_search;
        unwind_ctx_scratch = &local_unwind;
        dc_scratch = &local_dc;
    } else {
        search_ctx = &g_scratch_ctx_search;
        unwind_ctx_scratch = &g_scratch_ctx_unwind;
        dc_scratch = &g_scratch_dc;
    }
    g_dispatch_depth++;

    /* Phase 1: Search for a handler using the scratch context */
    memcpy(search_ctx, context, sizeof(PE_CONTEXT));

    uint64_t target_frame = 0;
    PE_RUNTIME_FUNCTION *target_func = NULL;
    uint64_t target_image_base = 0;
    int target_scope_index = 0;
    int handler_found = 0;

    for (int frame = 0; frame < MAX_UNWIND_FRAMES; frame++) {
        uint64_t image_base = 0;
        PE_RUNTIME_FUNCTION *func_entry = pe_lookup_function_entry(
            search_ctx->Rip, &image_base, NULL);

        if (__builtin_expect(!func_entry, 0)) {
            if (image_base == 0)
                break; /* Not in any registered PE module */
            /* Leaf function: pop return address */
            search_ctx->Rip = *(uint64_t *)(uintptr_t)search_ctx->Rsp;
            search_ctx->Rsp += 8;
            continue;
        }

        uint64_t img_sz = get_module_image_size(image_base);
        PE_UNWIND_INFO *info = get_unwind_info(image_base, img_sz, func_entry);
        if (__builtin_expect(!info, 0)) {
            search_ctx->Rip = *(uint64_t *)(uintptr_t)search_ctx->Rsp;
            search_ctx->Rsp += 8;
            continue;
        }

        void *handler_data_ptr = NULL;
        uint64_t frame_ptr = 0;

        /* Save RIP before pe_virtual_unwind modifies search_ctx */
        uint64_t control_pc = search_ctx->Rip;

        PE_EXCEPTION_HANDLER lang_handler = pe_virtual_unwind(
            UNW_FLAG_EHANDLER,
            image_base,
            control_pc,
            func_entry,
            search_ctx,
            &handler_data_ptr,
            &frame_ptr,
            NULL);

        if (lang_handler && (info->Flags & UNW_FLAG_EHANDLER)) {
            /* Build DISPATCHER_CONTEXT on the scratch buffer */
            PE_DISPATCHER_CONTEXT *dc = dc_scratch;
            dc->ControlPc       = control_pc;
            dc->ImageBase        = image_base;
            dc->FunctionEntry    = func_entry;
            dc->EstablisherFrame = frame_ptr;
            dc->TargetIp         = 0;
            dc->ContextRecord    = search_ctx;
            dc->LanguageHandler  = (void *)lang_handler;
            dc->HandlerData      = handler_data_ptr;
            dc->HistoryTable     = NULL;
            dc->ScopeIndex       = 0;
            dc->Fill0            = 0;

            /* Call the language-specific handler in search mode */
            int disposition = (int)abi_call_win64_4(
                (void *)lang_handler,
                (uint64_t)(uintptr_t)exception_record,
                (uint64_t)frame_ptr,
                (uint64_t)(uintptr_t)context,
                (uint64_t)(uintptr_t)dc);

            switch (disposition) {
            case ExceptionContinueExecution:
                g_dispatch_depth--;
                return 1;

            case ExceptionContinueSearch:
            case ExceptionNestedException:
            case ExceptionCollidedUnwind:
                break;

            default:
                if (__builtin_expect(disposition > 0, 1)) {
                    target_frame      = frame_ptr;
                    target_func       = func_entry;
                    target_image_base = image_base;
                    target_scope_index = dc->ScopeIndex;
                    handler_found     = 1;
                }
                break;
            }

            if (handler_found)
                break;
        }
    }

    if (__builtin_expect(!handler_found, 1)) {
        g_dispatch_depth--;
        return 0;
    }

    /*
     * Phase 2: Unwind to the target frame.
     * Use the second scratch context for the unwind pass.
     */
    PE_CONTEXT *unwind_ctx = unwind_ctx_scratch;
    memcpy(unwind_ctx, context, sizeof(PE_CONTEXT));

    exception_record->ExceptionFlags |= PE_EXCEPTION_UNWINDING;

    for (int frame = 0; frame < MAX_UNWIND_FRAMES; frame++) {
        uint64_t image_base = 0;
        PE_RUNTIME_FUNCTION *func_entry = pe_lookup_function_entry(
            unwind_ctx->Rip, &image_base, NULL);

        if (__builtin_expect(!func_entry, 0)) {
            if (image_base == 0)
                break;
            unwind_ctx->Rip = *(uint64_t *)(uintptr_t)unwind_ctx->Rsp;
            unwind_ctx->Rsp += 8;
            continue;
        }

        void *handler_data_ptr = NULL;
        uint64_t frame_ptr = 0;

        /* Save RIP before pe_virtual_unwind modifies unwind_ctx */
        uint64_t unwind_control_pc = unwind_ctx->Rip;

        PE_EXCEPTION_HANDLER lang_handler = pe_virtual_unwind(
            UNW_FLAG_UHANDLER,
            image_base,
            unwind_control_pc,
            func_entry,
            unwind_ctx,
            &handler_data_ptr,
            &frame_ptr,
            NULL);

        /* Check if this is the target frame */
        int is_target = (frame_ptr == target_frame &&
                         func_entry == target_func &&
                         image_base == target_image_base);

        if (is_target)
            exception_record->ExceptionFlags |= PE_EXCEPTION_TARGET_UNWIND;

        /* Call __finally handlers */
        uint64_t img_sz2 = get_module_image_size(image_base);
        PE_UNWIND_INFO *info = get_unwind_info(image_base, img_sz2, func_entry);
        if (lang_handler && info && (info->Flags & UNW_FLAG_UHANDLER)) {
            PE_DISPATCHER_CONTEXT *dc = dc_scratch;
            dc->ControlPc        = unwind_control_pc;
            dc->ImageBase         = image_base;
            dc->FunctionEntry     = func_entry;
            dc->EstablisherFrame  = frame_ptr;
            dc->TargetIp          = 0;
            dc->ContextRecord     = unwind_ctx;
            dc->LanguageHandler   = (void *)lang_handler;
            dc->HandlerData       = handler_data_ptr;
            dc->HistoryTable      = NULL;
            dc->ScopeIndex        = target_scope_index;
            dc->Fill0             = 0;

            abi_call_win64_4(
                (void *)lang_handler,
                (uint64_t)(uintptr_t)exception_record,
                (uint64_t)frame_ptr,
                (uint64_t)(uintptr_t)unwind_ctx,
                (uint64_t)(uintptr_t)dc);
        }

        if (__builtin_expect(is_target, 0)) {
            memcpy(context, unwind_ctx, sizeof(PE_CONTEXT));
            g_dispatch_depth--;
            return 1;
        }
    }

    fprintf(stderr, LOG_PREFIX "WARNING: Failed to reach target frame "
            "during unwind (target=0x%lX)\n", (unsigned long)target_frame);
    g_dispatch_depth--;
    return 0;
}

/* ================================================================
 * 9. Context helpers: fill from / apply to ucontext_t
 * ================================================================ */

void pe_exception_fill_context(PE_CONTEXT *ctx, ucontext_t *uc)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->ContextFlags = CONTEXT_FULL;

    if (__builtin_expect(!uc, 0))
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

    /* Copy XMM/FPU state if available */
    if (uc->uc_mcontext.fpregs) {
        size_t copy_sz = sizeof(ctx->FltSave);
        if (sizeof(*uc->uc_mcontext.fpregs) < copy_sz)
            copy_sz = sizeof(*uc->uc_mcontext.fpregs);
        memcpy(ctx->FltSave, uc->uc_mcontext.fpregs, copy_sz);
    }
}

void pe_exception_apply_context(const PE_CONTEXT *ctx, ucontext_t *uc)
{
    if (__builtin_expect(!uc, 0))
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

/* ================================================================
 * 10. Initialization and ntdll wiring
 * ================================================================ */

static int g_exception_system_initialized = 0;

/* Forward declarations for the ms_abi wrappers */
__attribute__((ms_abi, visibility("default")))
PE_RUNTIME_FUNCTION *pe_RtlLookupFunctionEntry(DWORD64, DWORD64 *, void *);
__attribute__((ms_abi, visibility("default")))
void *pe_RtlVirtualUnwind(DWORD, DWORD64, DWORD64, PE_RUNTIME_FUNCTION *,
                           PE_CONTEXT *, void **, DWORD64 *,
                           KNONVOLATILE_CONTEXT_POINTERS *);
__attribute__((ms_abi, visibility("default")))
void pe_RtlUnwindEx(void *, void *, PE_EXCEPTION_RECORD *, void *,
                     PE_CONTEXT *, void *);

/*
 * Wire real implementations into ntdll's stub functions.
 */
static void wire_ntdll_exception(void)
{
    void *ntdll = dlopen("libpe_ntdll.so", RTLD_NOW | RTLD_NOLOAD);
    if (!ntdll)
        ntdll = dlopen("./dlls/libpe_ntdll.so", RTLD_NOW | RTLD_NOLOAD);
    if (__builtin_expect(!ntdll, 0)) {
        printf(LOG_PREFIX "ntdll not yet loaded, will wire via "
               "-rdynamic exports\n");
        return;
    }

    typedef void (*wire_fn)(void *, void *, void *, void *);
    wire_fn wire = (wire_fn)dlsym(ntdll, "ntdll_exception_wire_pe");
    if (__builtin_expect(wire != NULL, 1)) {
        wire((void *)pe_RtlLookupFunctionEntry,
             (void *)pe_RtlVirtualUnwind,
             (void *)pe_RtlUnwindEx,
             (void *)pe_exception_dispatch_frames);
        printf(LOG_PREFIX "Wired real SEH implementations into ntdll\n");
    } else {
        printf(LOG_PREFIX "WARNING: ntdll_exception_wire_pe not found\n");
    }

    dlclose(ntdll);
}

__attribute__((visibility("default")))
void pe_exception_init(void)
{
    if (__builtin_expect(g_exception_system_initialized, 1))
        return;

    memset(g_modules, 0, sizeof(g_modules));
    atomic_store_explicit(&g_module_count, 0, memory_order_relaxed);

    memset(g_dynamic_tables, 0, sizeof(g_dynamic_tables));
    atomic_store_explicit(&g_dynamic_table_count, 0, memory_order_relaxed);

    g_exception_system_initialized = 1;

    wire_ntdll_exception();

    printf(LOG_PREFIX "Exception handling system initialized "
           "(max %d modules, %d dynamic tables, "
           "module entry=%zu bytes)\n",
           PE_EX_MAX_MODULES, MAX_DYNAMIC_TABLES,
           sizeof(pe_ex_module_t));
}

/* ================================================================
 * 11. Exported ntdll-compatible API wrappers (ms_abi)
 *
 * Called from PE code via the ntdll stub DLL.
 * ================================================================ */

__attribute__((ms_abi, hot, visibility("default")))
PE_RUNTIME_FUNCTION *pe_RtlLookupFunctionEntry(
    DWORD64 ControlPc,
    DWORD64 *ImageBase,
    void *HistoryTable)
{
    uint64_t base = 0;
    PE_RUNTIME_FUNCTION *entry = pe_lookup_function_entry(
        (uint64_t)ControlPc, &base, HistoryTable);
    if (ImageBase)
        *ImageBase = (DWORD64)base;
    return entry;
}

__attribute__((ms_abi, hot, visibility("default")))
void *pe_RtlVirtualUnwind(
    DWORD HandlerType,
    DWORD64 ImageBase,
    DWORD64 ControlPc,
    PE_RUNTIME_FUNCTION *FunctionEntry,
    PE_CONTEXT *ContextRecord,
    void **HandlerData,
    DWORD64 *EstablisherFrame,
    KNONVOLATILE_CONTEXT_POINTERS *ContextPointers)
{
    return (void *)pe_virtual_unwind(
        HandlerType,
        (uint64_t)ImageBase,
        (uint64_t)ControlPc,
        FunctionEntry,
        ContextRecord,
        HandlerData,
        (uint64_t *)EstablisherFrame,
        ContextPointers);
}

/*
 * RtlUnwindEx - targeted exception unwind.
 * Walks frames from the current position to TargetFrame, calling
 * __finally handlers on each intermediate frame. When the target
 * is reached, sets ReturnValue in RAX and jumps to TargetIp.
 */
__attribute__((ms_abi, visibility("default")))
void pe_RtlUnwindEx(
    void *TargetFrame,
    void *TargetIp,
    PE_EXCEPTION_RECORD *ExceptionRecord,
    void *ReturnValue,
    PE_CONTEXT *OriginalContext,
    void *HistoryTable)
{
    (void)HistoryTable;

    if (__builtin_expect(!OriginalContext, 0)) {
        fprintf(stderr, LOG_PREFIX "RtlUnwindEx: NULL context\n");
        return;
    }

    PE_EXCEPTION_RECORD local_rec;
    PE_EXCEPTION_RECORD *rec = ExceptionRecord;
    if (__builtin_expect(!rec, 0)) {
        memset(&local_rec, 0, sizeof(local_rec));
        local_rec.ExceptionCode = 0; /* STATUS_UNWIND */
        rec = &local_rec;
    }
    rec->ExceptionFlags |= PE_EXCEPTION_UNWINDING;
    if (!TargetFrame)
        rec->ExceptionFlags |= PE_EXCEPTION_EXIT_UNWIND;

    /*
     * Use stack-local scratch when nested (g_dispatch_depth > 0) to avoid
     * corrupting the outer dispatch's thread-local scratch buffers.
     */
    PE_CONTEXT *ctx;
    PE_DISPATCHER_CONTEXT *dc_scratch;
    PE_CONTEXT local_ctx;
    PE_DISPATCHER_CONTEXT local_dc;
    if (g_dispatch_depth > 0) {
        ctx = &local_ctx;
        dc_scratch = &local_dc;
    } else {
        ctx = &g_scratch_ctx_unwind;
        dc_scratch = &g_scratch_dc;
    }
    g_dispatch_depth++;
    memcpy(ctx, OriginalContext, sizeof(PE_CONTEXT));

    uint64_t target_fp = (uint64_t)(uintptr_t)TargetFrame;

    for (int frame = 0; frame < MAX_UNWIND_FRAMES; frame++) {
        uint64_t image_base = 0;
        PE_RUNTIME_FUNCTION *func_entry = pe_lookup_function_entry(
            ctx->Rip, &image_base, NULL);

        if (__builtin_expect(!func_entry, 0)) {
            if (image_base == 0)
                break;
            ctx->Rip = *(uint64_t *)(uintptr_t)ctx->Rsp;
            ctx->Rsp += 8;
            continue;
        }

        void *handler_data_ptr = NULL;
        uint64_t frame_ptr = 0;

        /* Save RIP before pe_virtual_unwind modifies ctx */
        uint64_t unwindex_control_pc = ctx->Rip;

        PE_EXCEPTION_HANDLER lang_handler = pe_virtual_unwind(
            UNW_FLAG_UHANDLER,
            image_base,
            unwindex_control_pc,
            func_entry,
            ctx,
            &handler_data_ptr,
            &frame_ptr,
            NULL);

        int is_target = (TargetFrame && frame_ptr == target_fp);
        if (is_target)
            rec->ExceptionFlags |= PE_EXCEPTION_TARGET_UNWIND;

        /* Call __finally handlers */
        uint64_t img_sz3 = get_module_image_size(image_base);
        PE_UNWIND_INFO *info = get_unwind_info(image_base, img_sz3, func_entry);
        if (lang_handler && info && (info->Flags & UNW_FLAG_UHANDLER)) {
            PE_DISPATCHER_CONTEXT *dc = dc_scratch;
            dc->ControlPc        = unwindex_control_pc;
            dc->ImageBase         = image_base;
            dc->FunctionEntry     = func_entry;
            dc->EstablisherFrame  = frame_ptr;
            dc->TargetIp          = (DWORD64)(uintptr_t)TargetIp;
            dc->ContextRecord     = ctx;
            dc->LanguageHandler   = (void *)lang_handler;
            dc->HandlerData       = handler_data_ptr;
            dc->HistoryTable      = NULL;
            dc->ScopeIndex        = 0;
            dc->Fill0             = 0;

            abi_call_win64_4(
                (void *)lang_handler,
                (uint64_t)(uintptr_t)rec,
                (uint64_t)frame_ptr,
                (uint64_t)(uintptr_t)ctx,
                (uint64_t)(uintptr_t)dc);
        }

        if (__builtin_expect(is_target, 0)) {
            ctx->Rax = (DWORD64)(uintptr_t)ReturnValue;
            if (TargetIp)
                ctx->Rip = (DWORD64)(uintptr_t)TargetIp;
            memcpy(OriginalContext, ctx, sizeof(PE_CONTEXT));
            g_dispatch_depth--;
            return;
        }
    }

    if (!TargetFrame) {
        /* Exit unwind: copy final context */
        memcpy(OriginalContext, ctx, sizeof(PE_CONTEXT));
        g_dispatch_depth--;
        return;
    }

    fprintf(stderr, LOG_PREFIX "RtlUnwindEx: could not reach "
            "target frame 0x%lX\n", (unsigned long)target_fp);
    g_dispatch_depth--;
}

/*
 * RtlCaptureContext - snapshot current CPU register state.
 *
 * LIMITATION: RSP is approximated from the frame pointer (RBP + 16).
 * This is inherently unreliable with compiler intrinsics because:
 *   1. The compiler may omit frame pointers (-fomit-frame-pointer)
 *   2. The stack layout between caller and callee varies with optimization
 *   3. ms_abi and sysv_abi have different red zone / shadow space rules
 * A proper implementation would require inline assembly to read RSP directly.
 * For most use cases (unwinding, SetUnhandledExceptionFilter) this is adequate.
 */
__attribute__((ms_abi, visibility("default")))
void pe_RtlCaptureContext(PE_CONTEXT *ctx)
{
    if (__builtin_expect(!ctx, 0))
        return;

    memset(ctx, 0, sizeof(*ctx));
    ctx->ContextFlags = CONTEXT_FULL;
    ctx->Rip = (DWORD64)(uintptr_t)__builtin_return_address(0);
    ctx->Rbp = (DWORD64)(uintptr_t)__builtin_frame_address(0);
    ctx->Rsp = ctx->Rbp + 16; /* Approximate; see limitation note above */
}

/*
 * RtlAddFunctionTable - register a dynamic function table for JIT code.
 */
__attribute__((ms_abi, visibility("default")))
BOOL pe_RtlAddFunctionTable(PE_RUNTIME_FUNCTION *FunctionTable,
                              DWORD EntryCount,
                              DWORD64 BaseAddress)
{
    if (__builtin_expect(!FunctionTable || EntryCount == 0, 0))
        return FALSE;

    uint64_t range_start = BaseAddress + FunctionTable[0].BeginAddress;
    uint64_t range_end = BaseAddress + FunctionTable[EntryCount - 1].EndAddress;

    if (pe_exception_add_dynamic_table(range_start, range_end,
                                        FunctionTable, EntryCount) == 0) {
        printf(LOG_PREFIX "RtlAddFunctionTable: %u entries at 0x%lX\n",
               EntryCount, (unsigned long)BaseAddress);
        return TRUE;
    }

    return FALSE;
}

/*
 * RtlDeleteFunctionTable - remove a dynamic function table.
 */
__attribute__((ms_abi, visibility("default")))
BOOL pe_RtlDeleteFunctionTable(PE_RUNTIME_FUNCTION *FunctionTable)
{
    if (__builtin_expect(!FunctionTable, 0))
        return FALSE;

    pthread_mutex_lock(&g_dynamic_lock);

    int count = atomic_load_explicit(&g_dynamic_table_count,
                                     memory_order_relaxed);
    for (int i = 0; i < count; i++) {
        if (g_dynamic_tables[i].func_table == FunctionTable &&
            g_dynamic_tables[i].entry_count > 0) {
            atomic_store_explicit(
                (_Atomic uint32_t *)&g_dynamic_tables[i].entry_count, 0,
                memory_order_release);
            g_dynamic_tables[i].func_table  = NULL;
            g_dynamic_tables[i].range_start = 0;
            g_dynamic_tables[i].range_end   = 0;
            pthread_mutex_unlock(&g_dynamic_lock);
            return TRUE;
        }
    }

    pthread_mutex_unlock(&g_dynamic_lock);
    return FALSE;
}

/*
 * RtlInstallFunctionTableCallback - callback-based dynamic table.
 * Stub: returns TRUE to prevent caller failure.
 */
__attribute__((ms_abi, visibility("default")))
BOOL pe_RtlInstallFunctionTableCallback(
    DWORD64 TableIdentifier,
    DWORD64 BaseAddress,
    DWORD Length,
    void *Callback,
    void *Context,
    LPCWSTR OutOfProcessCallbackDll)
{
    (void)TableIdentifier;
    (void)BaseAddress;
    (void)Length;
    (void)Callback;
    (void)Context;
    (void)OutOfProcessCallbackDll;

    printf(LOG_PREFIX "RtlInstallFunctionTableCallback: stub "
           "(base=0x%lX len=%u)\n",
           (unsigned long)BaseAddress, Length);
    return TRUE;
}

/* ================================================================
 * 12. Stack Walker Utility
 *
 * Walks the call stack using .pdata unwind information.
 * Used by RtlCaptureStackBackTrace and debug utilities.
 * ================================================================ */

__attribute__((visibility("default")))
int pe_exception_walk_stack(PE_CONTEXT *context, uint64_t *frames,
                             int max_frames)
{
    if (__builtin_expect(!context || !frames || max_frames <= 0, 0))
        return 0;

    PE_CONTEXT ctx;
    memcpy(&ctx, context, sizeof(PE_CONTEXT));

    int count = 0;

    for (int i = 0; i < max_frames && i < MAX_UNWIND_FRAMES; i++) {
        frames[count++] = ctx.Rip;

        uint64_t image_base = 0;
        PE_RUNTIME_FUNCTION *func_entry = pe_lookup_function_entry(
            ctx.Rip, &image_base, NULL);

        if (__builtin_expect(!func_entry, 0)) {
            if (image_base == 0)
                break;
            if (__builtin_expect(ctx.Rsp == 0, 0))
                break;
            ctx.Rip = *(uint64_t *)(uintptr_t)ctx.Rsp;
            ctx.Rsp += 8;
        } else {
            uint64_t frame_ptr = 0;
            pe_virtual_unwind(0, image_base, ctx.Rip, func_entry,
                              &ctx, NULL, &frame_ptr, NULL);
        }

        if (__builtin_expect(ctx.Rip == 0 || ctx.Rsp == 0, 0))
            break;
    }

    return count;
}

/*
 * RtlCaptureStackBackTrace - capture a stack backtrace.
 */
__attribute__((ms_abi, visibility("default")))
WORD pe_RtlCaptureStackBackTrace(DWORD FramesToSkip, DWORD FramesToCapture,
                                   void **BackTrace, DWORD *BackTraceHash)
{
    PE_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.Rip = (DWORD64)(uintptr_t)__builtin_return_address(0);
    ctx.Rbp = (DWORD64)(uintptr_t)__builtin_frame_address(0);
    ctx.Rsp = ctx.Rbp + 16;

    /* Pre-allocated frame buffer on stack (no malloc) */
    uint64_t all_frames[256];
    int max = (int)(FramesToSkip + FramesToCapture);
    if (max > 256) max = 256;

    int total = pe_exception_walk_stack(&ctx, all_frames, max);

    int captured = 0;
    for (int i = (int)FramesToSkip;
         i < total && captured < (int)FramesToCapture; i++) {
        BackTrace[captured] = (void *)(uintptr_t)all_frames[i];
        captured++;
    }

    if (BackTraceHash) {
        DWORD hash = 0;
        for (int i = 0; i < captured; i++) {
            hash ^= (DWORD)(uintptr_t)BackTrace[i];
            hash = (hash << 7) | (hash >> 25);
        }
        *BackTraceHash = hash;
    }

    return (WORD)captured;
}
