/*
 * msvcrt_stdio.c - Microsoft C Runtime stdio stubs
 *
 * Standard libc functions (fopen, fread, fwrite, printf, etc.) are
 * resolved directly from libc by the PE import resolver. This file
 * only provides MSVCRT-specific functions that don't exist in libc.
 *
 * GCC 15 rejects redeclaration of standard libc functions due to
 * attribute mismatches, so we do NOT redefine them here.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <wchar.h>
#include <time.h>

#include "common/dll_common.h"
#include "compat/ms_abi_format.h"

/* _snprintf is the MSVC name for snprintf.
 * NOTE: MS _snprintf returns the number that WOULD have been written when
 * the buffer is too small (same as C99 snprintf), but it does NOT guarantee
 * NUL-termination on truncation.  ms_abi_vformat always NUL-terminates when
 * size>0; we don't "fix" that here because apps that check the return value
 * still behave identically.  (If size==0, we route through the NULL-buf
 * branch to avoid the bufsz-1 underflow inside the format engine.) */
WINAPI_EXPORT int _snprintf(char *str, size_t size, const char *format, ...)
{
    __builtin_ms_va_list args;
    __builtin_ms_va_start(args, format);
    int ret;
    if (!str || size == 0)
        ret = ms_abi_vformat(NULL, NULL, 0, format, args);
    else
        ret = ms_abi_vformat(NULL, str, size, format, args);
    __builtin_ms_va_end(args);
    return ret;
}

WINAPI_EXPORT int _vsnprintf(char *str, size_t size, const char *format, __builtin_ms_va_list ap)
{
    if (!str || size == 0)
        return ms_abi_vformat(NULL, NULL, 0, format, ap);
    return ms_abi_vformat(NULL, str, size, format, ap);
}

/* Standard streams - MSVCRT exports these as functions */
WINAPI_EXPORT FILE **__iob_func(void)
{
    static FILE *iob[3];
    iob[0] = stdin;
    iob[1] = stdout;
    iob[2] = stderr;
    return iob;
}

/* ================================================================
 * Windows errno mapping.
 *
 * Linux and Windows define disjoint numeric values for several errno
 * codes (EILSEQ, ENAMETOOLONG, ENOTEMPTY, EDEADLK, ENOLCK, ENOSYS).
 * PE apps that compare *_errno() to a numeric constant from their
 * MSVC errno.h will misidentify errors unless we translate here.
 *
 * We keep a thread-local mapped int; every call to _errno / _errno_func
 * / _o__errno refreshes it from the live libc errno so that subsequent
 * libc calls still report through the real TLS location.
 * ================================================================ */

/* Windows errno values (from MSVC errno.h) */
#define W_EPERM         1
#define W_ENOENT        2
#define W_ESRCH         3
#define W_EINTR         4
#define W_EIO           5
#define W_ENXIO         6
#define W_E2BIG         7
#define W_ENOEXEC       8
#define W_EBADF         9
#define W_ECHILD        10
#define W_EAGAIN        11
#define W_ENOMEM        12
#define W_EACCES        13
#define W_EFAULT        14
#define W_EBUSY         16
#define W_EEXIST        17
#define W_EXDEV         18
#define W_ENODEV        19
#define W_ENOTDIR       20
#define W_EISDIR        21
#define W_EINVAL        22
#define W_ENFILE        23
#define W_EMFILE        24
#define W_ENOTTY        25
#define W_EFBIG         27
#define W_ENOSPC        28
#define W_ESPIPE        29
#define W_EROFS         30
#define W_EMLINK        31
#define W_EPIPE         32
#define W_EDOM          33
#define W_ERANGE        34
#define W_EDEADLK       36
#define W_ENAMETOOLONG  38
#define W_ENOLCK        39
#define W_ENOSYS        40
#define W_ENOTEMPTY     41
#define W_EILSEQ        42
#define W_STRUNCATE     80

/* Forward translation: libc (Linux) errno -> MSVC errno. */
int pe_map_errno_linux_to_win(int e)
{
    switch (e) {
    case 0:             return 0;
    case EPERM:         return W_EPERM;
    case ENOENT:        return W_ENOENT;
    case ESRCH:         return W_ESRCH;
    case EINTR:         return W_EINTR;
    case EIO:           return W_EIO;
    case ENXIO:         return W_ENXIO;
    case E2BIG:         return W_E2BIG;
    case ENOEXEC:       return W_ENOEXEC;
    case EBADF:         return W_EBADF;
    case ECHILD:        return W_ECHILD;
    case EAGAIN:        return W_EAGAIN;
    case ENOMEM:        return W_ENOMEM;
    case EACCES:        return W_EACCES;
    case EFAULT:        return W_EFAULT;
    case EBUSY:         return W_EBUSY;
    case EEXIST:        return W_EEXIST;
    case EXDEV:         return W_EXDEV;
    case ENODEV:        return W_ENODEV;
    case ENOTDIR:       return W_ENOTDIR;
    case EISDIR:        return W_EISDIR;
    case EINVAL:        return W_EINVAL;
    case ENFILE:        return W_ENFILE;
    case EMFILE:        return W_EMFILE;
    case ENOTTY:        return W_ENOTTY;
    case EFBIG:         return W_EFBIG;
    case ENOSPC:        return W_ENOSPC;
    case ESPIPE:        return W_ESPIPE;
    case EROFS:         return W_EROFS;
    case EMLINK:        return W_EMLINK;
    case EPIPE:         return W_EPIPE;
    case EDOM:          return W_EDOM;
    case ERANGE:        return W_ERANGE;
    case EDEADLK:       return W_EDEADLK;
    case ENAMETOOLONG:  return W_ENAMETOOLONG;
    case ENOLCK:        return W_ENOLCK;
    case ENOSYS:        return W_ENOSYS;
    case ENOTEMPTY:     return W_ENOTEMPTY;
    case EILSEQ:        return W_EILSEQ;
    default:            return e;  /* passthrough for unmapped codes */
    }
}

/* Reverse translation: MSVC errno -> libc (Linux) errno.
 * Used by _set_errno so subsequent libc calls see the right errno. */
int pe_map_errno_win_to_linux(int e)
{
    switch (e) {
    case 0:               return 0;
    case W_EPERM:         return EPERM;
    case W_ENOENT:        return ENOENT;
    case W_ESRCH:         return ESRCH;
    case W_EINTR:         return EINTR;
    case W_EIO:           return EIO;
    case W_ENXIO:         return ENXIO;
    case W_E2BIG:         return E2BIG;
    case W_ENOEXEC:       return ENOEXEC;
    case W_EBADF:         return EBADF;
    case W_ECHILD:        return ECHILD;
    case W_EAGAIN:        return EAGAIN;
    case W_ENOMEM:        return ENOMEM;
    case W_EACCES:        return EACCES;
    case W_EFAULT:        return EFAULT;
    case W_EBUSY:         return EBUSY;
    case W_EEXIST:        return EEXIST;
    case W_EXDEV:         return EXDEV;
    case W_ENODEV:        return ENODEV;
    case W_ENOTDIR:       return ENOTDIR;
    case W_EISDIR:        return EISDIR;
    case W_EINVAL:        return EINVAL;
    case W_ENFILE:        return ENFILE;
    case W_EMFILE:        return EMFILE;
    case W_ENOTTY:        return ENOTTY;
    case W_EFBIG:         return EFBIG;
    case W_ENOSPC:        return ENOSPC;
    case W_ESPIPE:        return ESPIPE;
    case W_EROFS:         return EROFS;
    case W_EMLINK:        return EMLINK;
    case W_EPIPE:         return EPIPE;
    case W_EDOM:          return EDOM;
    case W_ERANGE:        return ERANGE;
    case W_EDEADLK:       return EDEADLK;
    case W_ENAMETOOLONG:  return ENAMETOOLONG;
    case W_ENOLCK:        return ENOLCK;
    case W_ENOSYS:        return ENOSYS;
    case W_ENOTEMPTY:     return ENOTEMPTY;
    case W_EILSEQ:        return EILSEQ;
    default:              return e;  /* passthrough */
    }
}

/* Thread-local Windows-space errno buffer. GCC __thread suffices
 * for libpe_msvcrt.so (glibc TLS, no static linking quirks). */
static __thread int g_win_errno = 0;

/* MSVCRT _errno.  MSVC apps read *_errno(); we translate from live
 * libc errno on each call so the value is always fresh.  Writes
 * through the returned pointer only update g_win_errno (the next
 * _errno() call will overwrite it from libc errno anyway — the
 * "correct" way for apps to set errno is _set_errno()). */
WINAPI_EXPORT int *_errno(void)
{
    g_win_errno = pe_map_errno_linux_to_win(errno);
    return &g_win_errno;
}

/* _get_errno(int *) — return current errno in Windows space. */
WINAPI_EXPORT int _get_errno(int *pValue)
{
    if (!pValue) return W_EINVAL;
    *pValue = pe_map_errno_linux_to_win(errno);
    return 0;
}

/* _set_errno(int) — accept Windows-space errno, translate to libc. */
WINAPI_EXPORT int _set_errno(int value)
{
    errno = pe_map_errno_win_to_linux(value);
    g_win_errno = value;
    return 0;
}

/* MSVCRT exit functions */
WINAPI_EXPORT void _exit_msvcrt(int status)
{
    _exit(status);
}

WINAPI_EXPORT void _cexit(void)
{
    /* Clean up C runtime but don't terminate */
    fflush(stdout);
    fflush(stderr);
}

WINAPI_EXPORT int _set_app_type(int type)
{
    (void)type;
    return 0;
}

/* String functions that MSVCRT exports */
WINAPI_EXPORT int _stricmp(const char *s1, const char *s2)
{
    return strcasecmp(s1, s2);
}

WINAPI_EXPORT int _strnicmp(const char *s1, const char *s2, size_t n)
{
    return strncasecmp(s1, s2, n);
}

WINAPI_EXPORT char *_strdup(const char *s)
{
    return strdup(s);
}

/* MSVCRT _fopen with path translation */
WINAPI_EXPORT FILE *_fopen(const char *filename, const char *mode)
{
    char linux_path[4096];
    win_path_to_linux(filename, linux_path, sizeof(linux_path));
    return fopen(linux_path, mode);
}

/* ----------------------------------------------------------------
 * CRT Startup / Initialization Functions
 * Required by virtually all MSVC-compiled applications.
 * ---------------------------------------------------------------- */

#include <pthread.h>

/* ----------------------------------------------------------------
 * LIFO atexit stack for Windows-compatible exit handler ordering.
 *
 * Windows CRT calls atexit/onexit handlers in LIFO (reverse registration)
 * order, but glibc's atexit() also executes in LIFO order within a single
 * block of 32 entries.  However, to guarantee correct ordering regardless
 * of the C library implementation and to keep our handlers isolated from
 * any host-registered handlers, we maintain our own explicit LIFO stack
 * and register a single flusher with the real atexit() that drains it.
 * ---------------------------------------------------------------- */
#define PE_ATEXIT_MAX 256

static void (*g_pe_atexit_stack[PE_ATEXIT_MAX])(void);
static int    g_pe_atexit_count = 0;
static int    g_pe_atexit_flusher_registered = 0;
static pthread_mutex_t g_pe_atexit_lock = PTHREAD_MUTEX_INITIALIZER;

/* Called by the real atexit — drains our stack in LIFO order */
static void pe_atexit_flush(void)
{
    pthread_mutex_lock(&g_pe_atexit_lock);
    /* Walk from top of stack (most recently registered) to bottom */
    for (int i = g_pe_atexit_count - 1; i >= 0; i--) {
        void (*fn)(void) = g_pe_atexit_stack[i];
        pthread_mutex_unlock(&g_pe_atexit_lock);
        if (fn) fn();
        pthread_mutex_lock(&g_pe_atexit_lock);
    }
    g_pe_atexit_count = 0;
    pthread_mutex_unlock(&g_pe_atexit_lock);
}

/* Register a PE exit handler on our LIFO stack.  Returns 0 on success. */
static int pe_atexit_register(void (*func)(void))
{
    if (!func) return -1;

    pthread_mutex_lock(&g_pe_atexit_lock);

    /* Lazily register the flusher with the real atexit exactly once */
    if (!g_pe_atexit_flusher_registered) {
        g_pe_atexit_flusher_registered = 1;
        atexit(pe_atexit_flush);
    }

    if (g_pe_atexit_count >= PE_ATEXIT_MAX) {
        pthread_mutex_unlock(&g_pe_atexit_lock);
        return -1; /* stack full */
    }

    g_pe_atexit_stack[g_pe_atexit_count++] = func;
    pthread_mutex_unlock(&g_pe_atexit_lock);
    return 0;
}

/*
 * _initterm / _initterm_e — C++ static initializer dispatch.
 *
 * The CRT startup code calls _initterm to run all global constructors
 * (C++ objects with static storage duration). The function table is
 * a NULL-terminated array of function pointers between [first, last).
 */
typedef void (*_PVFV)(void);
typedef int  (*_PIFV)(void);

WINAPI_EXPORT void _initterm(_PVFV *pfbegin, _PVFV *pfend)
{
    while (pfbegin < pfend) {
        if (*pfbegin != NULL)
            (**pfbegin)();
        pfbegin++;
    }
}

WINAPI_EXPORT int _initterm_e(_PIFV *pfbegin, _PIFV *pfend)
{
    int ret = 0;
    while (pfbegin < pfend) {
        if (*pfbegin != NULL) {
            ret = (**pfbegin)();
            if (ret != 0)
                return ret;
        }
        pfbegin++;
    }
    return 0;
}

/*
 * __getmainargs / __wgetmainargs — CRT argument parsing.
 *
 * Older MSVCRT uses these to get argc/argv before calling main().
 * We store the values set by the loader in env_setup.
 */
static int    g_argc = 0;
static char **g_argv = NULL;
static char **g_envp = NULL;

/* Forward declarations for CRT global variables defined below */
extern char *_acmdln;
extern uint16_t *_wcmdln;

/* Called by the PE loader's main() to set up args before calling entry point */
void __pe_set_main_args(int argc, char **argv, char **envp)
{
    g_argc = argc;
    g_argv = argv;
    g_envp = envp;

    /* Build _acmdln (narrow command line) and _wcmdln (wide command line)
     * from argv so CRT code that imports these DATA symbols gets the real values */
    extern char g_acmdln_buf[32768];
    extern uint16_t g_wcmdln_buf[32768];
    size_t pos = 0;
    for (int i = 0; i < argc && pos < sizeof(g_acmdln_buf) - 2; i++) {
        if (i > 0 && pos < sizeof(g_acmdln_buf) - 1)
            g_acmdln_buf[pos++] = ' ';
        size_t len = strlen(argv[i]);
        if (pos + len < sizeof(g_acmdln_buf) - 1) {
            memcpy(g_acmdln_buf + pos, argv[i], len);
            pos += len;
        }
    }
    g_acmdln_buf[pos] = '\0';
    _acmdln = g_acmdln_buf;

    /* Build wide version */
    for (size_t j = 0; j <= pos && j < 32767; j++)
        g_wcmdln_buf[j] = (uint16_t)(unsigned char)g_acmdln_buf[j];
    _wcmdln = g_wcmdln_buf;
}

typedef struct {
    int newmode;
} _startupinfo;

WINAPI_EXPORT int __getmainargs(int *_Argc, char ***_Argv, char ***_Env,
                                  int _DoWildCard, _startupinfo *_StartInfo)
{
    (void)_DoWildCard;
    (void)_StartInfo;
    *_Argc = g_argc;
    *_Argv = g_argv;
    *_Env = g_envp;
    return 0;
}

WINAPI_EXPORT int __wgetmainargs(int *_Argc, uint16_t ***_Argv, uint16_t ***_Env,
                                   int _DoWildCard, _startupinfo *_StartInfo)
{
    (void)_DoWildCard;
    (void)_StartInfo;
    /* Minimal: return zero-length wide arrays */
    static uint16_t *empty_wargv[] = { NULL };
    static uint16_t *empty_wenvp[] = { NULL };
    *_Argc = 0;
    *_Argv = empty_wargv;
    *_Env = empty_wenvp;
    return 0;
}

/*
 * _beginthread / _beginthreadex / _endthread / _endthreadex
 *
 * MSVCRT thread creation functions. _beginthreadex is the preferred one
 * (returns a handle, sets errno correctly). We map to pthreads and
 * return a proper HANDLE backed by thread_data_t so that
 * WaitForSingleObject / GetExitCodeThread work on the returned value.
 */
#include "kernel32/kernel32_internal.h"

typedef unsigned int (__attribute__((ms_abi)) *_beginthreadex_proc)(void *);
typedef void (__attribute__((ms_abi)) *_beginthread_proc)(void *);

struct thread_trampoline_data {
    _beginthreadex_proc func;
    void *arg;
    thread_data_t *tdata; /* back-pointer for finish signaling */
};

static void *thread_trampoline(void *raw)
{
    struct thread_trampoline_data *data = (struct thread_trampoline_data *)raw;
    _beginthreadex_proc func = data->func;
    void *arg = data->arg;
    thread_data_t *tdata = data->tdata;
    free(data);

    unsigned int ret = func(arg);

    /* Signal completion so WaitForSingleObject on our handle works */
    pthread_mutex_lock(&tdata->finish_lock);
    tdata->exit_code = (DWORD)ret;
    tdata->finished = 1;
    pthread_cond_broadcast(&tdata->finish_cond);
    pthread_mutex_unlock(&tdata->finish_lock);

    return (void *)(uintptr_t)ret;
}

WINAPI_EXPORT uintptr_t _beginthreadex(
    void *security,
    unsigned stack_size,
    _beginthreadex_proc start_address,
    void *arglist,
    unsigned initflag,
    unsigned *thrdaddr)
{
    (void)security;
    (void)initflag;

    /* Allocate thread_data_t so the handle table / WaitForSingleObject
     * can track this thread's lifetime identically to CreateThread */
    thread_data_t *tdata = calloc(1, sizeof(thread_data_t));
    if (!tdata) return 0;

    tdata->start_routine = NULL; /* not used by our trampoline */
    tdata->parameter = arglist;
    tdata->suspended = 0;
    tdata->finished = 0;
    tdata->exit_code = 0;
    pthread_mutex_init(&tdata->suspend_lock, NULL);
    pthread_cond_init(&tdata->suspend_cond, NULL);
    pthread_mutex_init(&tdata->finish_lock, NULL);
    pthread_cond_init(&tdata->finish_cond, NULL);

    struct thread_trampoline_data *data = malloc(sizeof(*data));
    if (!data) { free(tdata); return 0; }
    data->func = start_address;
    data->arg = arglist;
    data->tdata = tdata;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    if (stack_size > 0)
        pthread_attr_setstacksize(&attr, stack_size);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    int ret = pthread_create(&tdata->pthread, &attr, thread_trampoline, data);
    pthread_attr_destroy(&attr);

    if (ret != 0) {
        free(data);
        free(tdata);
        return 0;
    }

    if (thrdaddr)
        *thrdaddr = (unsigned)(uintptr_t)tdata->pthread;

    /* Return a proper Windows HANDLE backed by thread_data_t,
     * so WaitForSingleObject / GetExitCodeThread work correctly */
    HANDLE h = handle_alloc(HANDLE_TYPE_THREAD, -1, tdata);
    return (uintptr_t)h;
}

struct beginthread_trampoline_data {
    _beginthread_proc func;
    void *arg;
    thread_data_t *tdata;
};

static void *beginthread_trampoline(void *raw)
{
    struct beginthread_trampoline_data *data = (struct beginthread_trampoline_data *)raw;
    _beginthread_proc func = data->func;
    void *arg = data->arg;
    thread_data_t *tdata = data->tdata;
    free(data);
    func(arg);
    /* Signal finish so WaitForSingleObject on the returned HANDLE works. */
    pthread_mutex_lock(&tdata->finish_lock);
    tdata->exit_code = 0;
    tdata->finished = 1;
    pthread_cond_broadcast(&tdata->finish_cond);
    pthread_mutex_unlock(&tdata->finish_lock);
    return NULL;
}

WINAPI_EXPORT uintptr_t _beginthread(
    _beginthread_proc start_address,
    unsigned stack_size,
    void *arglist)
{
    /* MS _beginthread returns an opaque handle that can be passed to
     * WaitForSingleObject / CloseHandle.  Previous implementation returned
     * the raw pthread_t which is meaningless to Win32 handle consumers and
     * prevented apps from synchronising on thread exit. */
    thread_data_t *tdata = calloc(1, sizeof(thread_data_t));
    if (!tdata) return (uintptr_t)-1;
    pthread_mutex_init(&tdata->suspend_lock, NULL);
    pthread_cond_init(&tdata->suspend_cond, NULL);
    pthread_mutex_init(&tdata->finish_lock, NULL);
    pthread_cond_init(&tdata->finish_cond, NULL);

    struct beginthread_trampoline_data *data = malloc(sizeof(*data));
    if (!data) { free(tdata); return (uintptr_t)-1; }
    data->func = start_address;
    data->arg = arglist;
    data->tdata = tdata;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    if (stack_size > 0)
        pthread_attr_setstacksize(&attr, stack_size);
    /* Must be joinable so the HANDLE can observe exit via pthread_join. */
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    int ret = pthread_create(&tdata->pthread, &attr, beginthread_trampoline, data);
    pthread_attr_destroy(&attr);

    if (ret != 0) {
        free(data);
        free(tdata);
        return (uintptr_t)-1;
    }

    HANDLE h = handle_alloc(HANDLE_TYPE_THREAD, -1, tdata);
    return (uintptr_t)h;
}

WINAPI_EXPORT void _endthread(void)
{
    pthread_exit(NULL);
}

WINAPI_EXPORT void _endthreadex(unsigned retval)
{
    pthread_exit((void *)(uintptr_t)retval);
}

/*
 * _onexit — register a function to be called at exit.
 */
typedef int (*_onexit_t)(void);

WINAPI_EXPORT _onexit_t _onexit(_onexit_t func)
{
    if (pe_atexit_register((void (*)(void))func) == 0)
        return func;
    return NULL;
}

/*
 * _controlfp / _controlfp_s — FPU control word manipulation.
 * We mostly ignore these since x86-64 SSE doesn't use the x87 CW.
 */
WINAPI_EXPORT unsigned int _controlfp(unsigned int new_val, unsigned int mask)
{
    (void)new_val;
    (void)mask;
    return 0x0009001F; /* Default CW: precision, round-to-nearest */
}

WINAPI_EXPORT int _controlfp_s(unsigned int *currentControl,
                                unsigned int newControl,
                                unsigned int mask)
{
    (void)newControl;
    (void)mask;
    if (currentControl)
        *currentControl = 0x0009001F;
    return 0;
}

/*
 * ucrtbase / api-ms-win-crt compatibility functions.
 * VS2015+ uses these "__stdio_common_*" functions instead of direct printf.
 *
 * CRITICAL ABI NOTE: These are ms_abi functions receiving ms_abi va_list
 * (which is just a char* pointer on Windows). We CANNOT forward directly
 * to sysv_abi vfprintf/vsnprintf because sysv va_list is a 24-byte struct.
 *
 * Solution: ms_abi_vformat / ms_abi_vscan in the shared header handle this.
 */

/* ms_abi_format.h included at top of file (needed by _snprintf et al.) */

WINAPI_EXPORT int __stdio_common_vfprintf(
    uint64_t options, FILE *stream,
    const char *format, void *locale, __builtin_ms_va_list argptr)
{
    (void)options; (void)locale;
    return ms_abi_vformat(stream, NULL, 0, format, argptr);
}

WINAPI_EXPORT int __stdio_common_vfprintf_s(
    uint64_t options, FILE *stream,
    const char *format, void *locale, __builtin_ms_va_list argptr)
{
    (void)options; (void)locale;
    return ms_abi_vformat(stream, NULL, 0, format, argptr);
}

WINAPI_EXPORT int __stdio_common_vsprintf(
    uint64_t options, char *buffer, size_t bufferCount,
    const char *format, void *locale, __builtin_ms_va_list argptr)
{
    (void)options; (void)locale;
    /* When buffer is NULL or bufferCount is 0 UCRT acts as size query. */
    if (!buffer || bufferCount == 0)
        return ms_abi_vformat(NULL, NULL, 0, format, argptr);
    buffer[0] = '\0';
    return ms_abi_vformat(NULL, buffer, bufferCount, format, argptr);
}

WINAPI_EXPORT int __stdio_common_vsprintf_s(
    uint64_t options, char *buffer, size_t bufferCount,
    const char *format, void *locale, __builtin_ms_va_list argptr)
{
    (void)options; (void)locale;
    if (!buffer || bufferCount == 0)
        return ms_abi_vformat(NULL, NULL, 0, format, argptr);
    buffer[0] = '\0';
    return ms_abi_vformat(NULL, buffer, bufferCount, format, argptr);
}

WINAPI_EXPORT int __stdio_common_vfscanf(
    uint64_t options, FILE *stream,
    const char *format, void *locale, __builtin_ms_va_list argptr)
{
    (void)options; (void)locale;
    return ms_abi_vscan(stream, NULL, format, argptr);
}

WINAPI_EXPORT int __stdio_common_vsscanf(
    uint64_t options, const char *buffer, size_t bufferCount,
    const char *format, void *locale, __builtin_ms_va_list argptr)
{
    (void)options; (void)bufferCount; (void)locale;
    return ms_abi_vscan(NULL, buffer, format, argptr);
}

/* ucrtbase __acrt_iob_func — replacement for __iob_func in VS2015+ */
WINAPI_EXPORT FILE *__acrt_iob_func(unsigned index)
{
    switch (index) {
    case 0: return stdin;
    case 1: return stdout;
    case 2: return stderr;
    default: return NULL;
    }
}

/* ucrtbase invalid parameter handlers */
WINAPI_EXPORT void _invalid_parameter_noinfo(void)
{
    /* Silently ignore — many apps trigger this with benign CRT parameter errors */
}

WINAPI_EXPORT void _invalid_parameter_noinfo_noreturn(void)
{
    abort();
}

/*
 * _configthreadlocale — configure thread-local locale behavior.
 * Returns the previous setting. We always use per-thread locale.
 */
#define _ENABLE_PER_THREAD_LOCALE 1
WINAPI_EXPORT int _configthreadlocale(int per_thread_locale)
{
    (void)per_thread_locale;
    return _ENABLE_PER_THREAD_LOCALE;
}

/*
 * _set_new_mode — set behavior of malloc on failure.
 * Returns previous mode. We always return 0 (standard behavior).
 */
WINAPI_EXPORT int _set_new_mode(int newhandlermode)
{
    (void)newhandlermode;
    return 0;
}

/*
 * _CRT lock/unlock — internal CRT synchronization.
 * Used by stdio functions for thread safety.
 */
#define _LOCK_MAX 32
static pthread_mutex_t g_crt_locks[_LOCK_MAX] = {
    [0 ... (_LOCK_MAX - 1)] = PTHREAD_MUTEX_INITIALIZER
};

WINAPI_EXPORT void _lock(int locknum)
{
    if (locknum >= 0 && locknum < _LOCK_MAX)
        pthread_mutex_lock(&g_crt_locks[locknum]);
}

WINAPI_EXPORT void _unlock(int locknum)
{
    if (locknum >= 0 && locknum < _LOCK_MAX)
        pthread_mutex_unlock(&g_crt_locks[locknum]);
}

/*
 * _amsg_exit — abort with a CRT runtime error message.
 */
WINAPI_EXPORT void _amsg_exit(int retcode)
{
    fprintf(stderr, "MSVCRT runtime error R%04d\n", retcode);
    _exit(retcode);
}

/*
 * _XcptFilter / _set_invalid_parameter_handler — exception infrastructure
 * stubs for apps that reference but don't critically depend on them.
 */
typedef void (*_invalid_parameter_handler)(
    const uint16_t *, const uint16_t *, const uint16_t *,
    unsigned int, uintptr_t);

static _invalid_parameter_handler g_iph = NULL;

WINAPI_EXPORT _invalid_parameter_handler _set_invalid_parameter_handler(
    _invalid_parameter_handler pNew)
{
    _invalid_parameter_handler old = g_iph;
    g_iph = pNew;
    return old;
}

WINAPI_EXPORT _invalid_parameter_handler _get_invalid_parameter_handler(void)
{
    return g_iph;
}

/* ----------------------------------------------------------------
 * Additional UCRT wide-char stdio functions
 * ---------------------------------------------------------------- */

#include <wctype.h>

/* Wide-char format variants — also use ms_va_list.
 * Minimal implementations: convert format to narrow and use ms_abi_vformat.
 *
 * NOTE: All wide-char parameters use uint16_t (2-byte UTF-16LE) instead of
 * wchar_t because PE binaries use 2-byte wchar_t while Linux wchar_t is 4 bytes. */

WINAPI_EXPORT int __stdio_common_vfwprintf(
    uint64_t options, FILE *stream,
    const uint16_t *format, void *locale, __builtin_ms_va_list argptr)
{
    (void)options; (void)locale;
    /* Convert uint16_t format to narrow */
    char narrow[2048];
    int i = 0;
    while (*format && i < (int)sizeof(narrow)-1) {
        narrow[i++] = (*format < 128) ? (char)*format : '?';
        format++;
    }
    narrow[i] = '\0';
    return ms_abi_vformat(stream, NULL, 0, narrow, argptr);
}

WINAPI_EXPORT int __stdio_common_vfwprintf_s(
    uint64_t options, FILE *stream,
    const uint16_t *format, void *locale, __builtin_ms_va_list argptr)
{
    return __stdio_common_vfwprintf(options, stream, format, locale, argptr);
}

WINAPI_EXPORT int __stdio_common_vswprintf(
    uint64_t options, uint16_t *buffer, size_t bufferCount,
    const uint16_t *format, void *locale, __builtin_ms_va_list argptr)
{
    (void)options; (void)locale;
    if (!format) return -1;
    /* Format to narrow buffer, then widen each byte to uint16_t */
    char narrow_fmt[2048], narrow_out[4096];
    int i = 0;
    while (*format && i < (int)sizeof(narrow_fmt)-1) {
        narrow_fmt[i++] = (*format < 128) ? (char)*format : '?';
        format++;
    }
    narrow_fmt[i] = '\0';
    int len = ms_abi_vformat(NULL, narrow_out, sizeof(narrow_out), narrow_fmt, argptr);
    /* bufferCount==0 ==> measure-only.  bufferCount==1 ==> only NUL fits. */
    if (buffer && bufferCount > 0) {
        size_t max_out = bufferCount - 1;
        size_t j;
        for (j = 0; j < max_out && narrow_out[j]; j++)
            buffer[j] = (uint16_t)(unsigned char)narrow_out[j];
        buffer[j] = 0;
    }
    return len;
}

WINAPI_EXPORT int __stdio_common_vswprintf_s(
    uint64_t options, uint16_t *buffer, size_t bufferCount,
    const uint16_t *format, void *locale, __builtin_ms_va_list argptr)
{
    return __stdio_common_vswprintf(options, buffer, bufferCount, format, locale, argptr);
}

/*
 * u16_to_wcs - expand uint16_t (Windows 2-byte wchar) to wchar_t (Linux 4-byte).
 * Returns number of wchar_t written (excluding NUL).
 */
static size_t u16_to_wcs(wchar_t *dst, size_t dst_max,
                         const uint16_t *src, size_t src_max)
{
    size_t i = 0;
    while (i < dst_max - 1 && i < src_max && src[i]) {
        dst[i] = (wchar_t)src[i];
        i++;
    }
    dst[i] = L'\0';
    return i;
}

/*
 * wcs_to_u16 - shrink wchar_t back to uint16_t for PE callers.
 * Handles surrogate-range clamping (values > 0xFFFF become '?').
 */
static void wcs_to_u16(uint16_t *dst, const wchar_t *src, size_t max)
{
    size_t i;
    for (i = 0; i < max - 1 && src[i]; i++)
        dst[i] = (src[i] <= 0xFFFF) ? (uint16_t)src[i] : (uint16_t)'?';
    dst[i] = 0;
}

/*
 * u16fmt_to_wcsfmt - convert a uint16_t format string to wchar_t, remapping
 * %s → %ls and %c → %lc (MSVCRT wide scanf reads wide chars for these;
 * glibc wide scanf reads narrow by default).
 * Records which arg slots received the 'l' upgrade so callers can
 * post-convert wchar_t output buffers back to uint16_t.
 *
 * Returns the number of format specifiers that target wide string/char
 * output slots (stored in wide_arg_indices[], max wide_max entries).
 */
static int u16fmt_to_wcsfmt(wchar_t *dst, size_t dst_max,
                            const uint16_t *src,
                            int *wide_arg_indices, int wide_max)
{
    size_t di = 0;
    int wide_count = 0, arg_idx = 0;
    for (size_t si = 0; src[si] && di < dst_max - 2; si++) {
        if (src[si] == '%') {
            dst[di++] = L'%';
            si++;
            if (!src[si]) break;
            /* Handle %% */
            if (src[si] == '%') { dst[di++] = L'%'; continue; }
            /* Handle '*' (suppress) — doesn't consume an arg */
            int suppressed = 0;
            if (src[si] == '*') { suppressed = 1; dst[di++] = L'*'; si++; }
            /* Copy flags/width */
            while (src[si] && ((src[si] >= '0' && src[si] <= '9') ||
                   src[si] == '-' || src[si] == '+' || src[si] == ' ' ||
                   src[si] == '#')) {
                dst[di++] = (wchar_t)src[si++];
            }
            /* Skip existing length modifiers (h, l, ll, etc.) */
            int has_l = 0;
            while (src[si] == 'h' || src[si] == 'l' || src[si] == 'L' ||
                   src[si] == 'z' || src[si] == 'j' || src[si] == 't' ||
                   src[si] == 'I' || src[si] == 'w') {
                if (src[si] == 'l') has_l = 1;
                dst[di++] = (wchar_t)src[si++];
            }
            if (!src[si]) break;
            /* Conversion specifier */
            wchar_t conv = (wchar_t)src[si];
            if ((conv == 's' || conv == 'c' || conv == '[') && !has_l) {
                /* MSVCRT wide scanf: %s reads wide, glibc: %s reads narrow.
                   Insert 'l' modifier so glibc reads wide chars. */
                dst[di++] = L'l';
                if (!suppressed && wide_count < wide_max)
                    wide_arg_indices[wide_count++] = arg_idx;
            }
            dst[di++] = conv;
            if (!suppressed) arg_idx++;
        } else {
            dst[di++] = (wchar_t)src[si];
        }
    }
    dst[di] = L'\0';
    return wide_count;
}

WINAPI_EXPORT int __stdio_common_vswscanf(
    uint64_t options, const uint16_t *buffer, size_t bufferCount,
    const uint16_t *format, void *locale, __builtin_ms_va_list argptr)
{
    (void)options; (void)locale;

    /* Expand uint16_t buffer and format to native wchar_t */
    wchar_t wbuf[4096], wfmt[1024];
    size_t buf_max = bufferCount ? bufferCount : 4096;
    if (buf_max > 4096) buf_max = 4096;
    u16_to_wcs(wbuf, buf_max, buffer, buf_max);

    /* Convert format, remapping %s→%ls, %c→%lc for glibc wide scanf.
       Track which arg slots target wide string/char output. */
    int wide_args[16];
    int wide_count = u16fmt_to_wcsfmt(wfmt, 1024, format, wide_args, 16);

    /*
     * For %ls/%lc args, glibc swscanf writes wchar_t (4 bytes each) but
     * the PE caller's buffer expects uint16_t (2 bytes). We use temp wchar_t
     * buffers and post-convert.
     *
     * Extract all 16 arg pointers, substitute temp buffers for wide args,
     * run swscanf, then convert results back.
     */
    void *args[16];
    for (int i = 0; i < 16; i++)
        args[i] = MS_VA_ARG(argptr, void*);

    /* Temp wchar_t buffers for wide string args (up to 512 wchars each) */
    wchar_t wtemp[16][512];
    void *orig_ptrs[16] = {0};
    for (int w = 0; w < wide_count; w++) {
        int idx = wide_args[w];
        if (idx < 16) {
            orig_ptrs[idx] = args[idx];
            memset(wtemp[idx], 0, sizeof(wtemp[idx]));
            args[idx] = wtemp[idx];
        }
    }

    int ret = swscanf(wbuf, wfmt,
        args[0], args[1], args[2],  args[3],  args[4],  args[5],  args[6],  args[7],
        args[8], args[9], args[10], args[11], args[12], args[13], args[14], args[15]);

    /* Convert wchar_t results back to uint16_t in the caller's buffers */
    for (int w = 0; w < wide_count; w++) {
        int idx = wide_args[w];
        if (idx < 16 && orig_ptrs[idx]) {
            wcs_to_u16((uint16_t*)orig_ptrs[idx], wtemp[idx], 512);
        }
    }

    return ret;
}

WINAPI_EXPORT int __stdio_common_vfwscanf(
    uint64_t options, FILE *stream,
    const uint16_t *format, void *locale, __builtin_ms_va_list argptr)
{
    (void)options; (void)locale;

    wchar_t wfmt[1024];
    int wide_args[16];
    int wide_count = u16fmt_to_wcsfmt(wfmt, 1024, format, wide_args, 16);

    void *args[16];
    for (int i = 0; i < 16; i++)
        args[i] = MS_VA_ARG(argptr, void*);

    wchar_t wtemp[16][512];
    void *orig_ptrs[16] = {0};
    for (int w = 0; w < wide_count; w++) {
        int idx = wide_args[w];
        if (idx < 16) {
            orig_ptrs[idx] = args[idx];
            memset(wtemp[idx], 0, sizeof(wtemp[idx]));
            args[idx] = wtemp[idx];
        }
    }

    int ret = fwscanf(stream, wfmt,
        args[0], args[1], args[2],  args[3],  args[4],  args[5],  args[6],  args[7],
        args[8], args[9], args[10], args[11], args[12], args[13], args[14], args[15]);

    for (int w = 0; w < wide_count; w++) {
        int idx = wide_args[w];
        if (idx < 16 && orig_ptrs[idx]) {
            wcs_to_u16((uint16_t*)orig_ptrs[idx], wtemp[idx], 512);
        }
    }

    return ret;
}

/* ----------------------------------------------------------------
 * File descriptor / OS handle bridge
 * ---------------------------------------------------------------- */

WINAPI_EXPORT intptr_t _get_osfhandle(int fd)
{
    return (intptr_t)fd;
}

WINAPI_EXPORT int _open_osfhandle(intptr_t osfhandle, int flags)
{
    (void)flags;
    return (int)osfhandle;
}

WINAPI_EXPORT int _setmode(int fd, int mode)
{
    (void)fd;
    return mode; /* No-op on Linux - no text/binary mode distinction */
}

WINAPI_EXPORT int _fileno(FILE *stream)
{
    return fileno(stream);
}

WINAPI_EXPORT int _isatty(int fd)
{
    return isatty(fd);
}

WINAPI_EXPORT int _dup(int fd)
{
    return dup(fd);
}

WINAPI_EXPORT int _dup2(int fd1, int fd2)
{
    return dup2(fd1, fd2);
}

/* ----------------------------------------------------------------
 * Process and pipe functions
 * ---------------------------------------------------------------- */

WINAPI_EXPORT FILE *_popen(const char *command, const char *mode)
{
    return popen(command, mode);
}

WINAPI_EXPORT int _pclose(FILE *stream)
{
    return pclose(stream);
}

WINAPI_EXPORT int _getpid(void)
{
    return (int)getpid();
}

/* ----------------------------------------------------------------
 * Program name accessors
 * ---------------------------------------------------------------- */

WINAPI_EXPORT int _get_pgmptr(char **pValue)
{
    if (!pValue) return 22; /* EINVAL */
    *pValue = g_argv ? g_argv[0] : (char *)"/unknown";
    return 0;
}

WINAPI_EXPORT int _get_wpgmptr(uint16_t **pValue)
{
    static uint16_t wbuf[1024];
    if (!pValue) return 22;
    const char *pgm = g_argv ? g_argv[0] : "/unknown";
    size_t i;
    for (i = 0; pgm[i] && i < 1023; i++)
        wbuf[i] = (uint16_t)(unsigned char)pgm[i];
    wbuf[i] = 0;
    *pValue = wbuf;
    return 0;
}

/* ----------------------------------------------------------------
 * Temporary file secure variants
 * ---------------------------------------------------------------- */

WINAPI_EXPORT int tmpnam_s(char *str, size_t sizeInChars)
{
    if (!str || sizeInChars < 16) return 22;
    char *tmp = tmpnam(NULL);
    if (tmp) {
        size_t len = strlen(tmp);
        if (len >= sizeInChars) len = sizeInChars - 1;
        memcpy(str, tmp, len);
        str[len] = '\0';
        return 0;
    }
    str[0] = '\0';
    return 22;
}

WINAPI_EXPORT int tmpfile_s(FILE **pFilePtr)
{
    if (!pFilePtr) return 22;
    *pFilePtr = tmpfile();
    return *pFilePtr ? 0 : 22;
}

/* ----------------------------------------------------------------
 * UCRT initialize/configure functions
 * ---------------------------------------------------------------- */

WINAPI_EXPORT int _initialize_narrow_environment(void)
{
    return 0;
}

WINAPI_EXPORT int _initialize_wide_environment(void)
{
    return 0;
}

WINAPI_EXPORT int _configure_narrow_argv(int mode)
{
    (void)mode;
    return 0;
}

WINAPI_EXPORT int _configure_wide_argv(int mode)
{
    (void)mode;
    return 0;
}

WINAPI_EXPORT char ***__p___argv(void)
{
    return &g_argv;
}

WINAPI_EXPORT int *__p___argc(void)
{
    return &g_argc;
}

WINAPI_EXPORT char ***__p__environ(void)
{
    extern char **environ;
    return &environ;
}

/* ----------------------------------------------------------------
 * Additional MSVC CRT compat
 * ---------------------------------------------------------------- */

WINAPI_EXPORT int _crt_atexit(void (*func)(void))
{
    return pe_atexit_register(func);
}

WINAPI_EXPORT int _register_onexit_function(void *table, void (*func)(void))
{
    (void)table;
    return pe_atexit_register(func);
}

WINAPI_EXPORT void __setusermatherr(void *handler)
{
    (void)handler;
}

WINAPI_EXPORT int _set_fmode(int mode)
{
    (void)mode;
    return 0;
}

WINAPI_EXPORT int _get_fmode(int *pmode)
{
    if (pmode) *pmode = 0; /* O_TEXT */
    return 0;
}

WINAPI_EXPORT int _seh_filter_dll(int a, void *b)
{
    (void)a; (void)b;
    return 1; /* EXCEPTION_EXECUTE_HANDLER */
}

WINAPI_EXPORT int _seh_filter_exe(int a, void *b)
{
    (void)a; (void)b;
    return 1;
}

/* __p__commode moved after _commode variable definition below */

WINAPI_EXPORT void _set_app_type_ucrt(int type)
{
    (void)type;
}

/* ----------------------------------------------------------------
 * CRT Global Variables
 *
 * Many MSVC-compiled apps import these as DATA symbols from msvcrt.dll.
 * They must be exported as visible global variables.
 * ---------------------------------------------------------------- */

/* Wide command line string (uint16_t for PE 2-byte wchar_t compatibility) */
uint16_t g_wcmdln_buf[32768];
__attribute__((visibility("default"))) uint16_t *_wcmdln = g_wcmdln_buf;

/* Narrow command line string — some CRT code imports _acmdln as a DATA symbol */
char g_acmdln_buf[32768];
__attribute__((visibility("default"))) char *_acmdln = g_acmdln_buf;

/* Default file translation mode (O_TEXT=0x4000, O_BINARY=0x8000) */
__attribute__((visibility("default"))) int _fmode = 0;

/* Commit mode for fopen (0 = no-commit) */
__attribute__((visibility("default"))) int _commode = 0;

/* __p_ accessor functions — return pointers to CRT globals */
WINAPI_EXPORT int *__p__fmode(void) { return &_fmode; }
WINAPI_EXPORT int *__p__commode(void) { return &_commode; }
WINAPI_EXPORT char **__p__acmdln(void) { return &_acmdln; }
WINAPI_EXPORT uint16_t **__p__wcmdln(void) { return &_wcmdln; }

/*
 * __security_cookie / __security_init_cookie — GS stack canary.
 *
 * MSVC /GS inserts a stack cookie check on function entry/exit.
 * mainCRTStartup calls __security_init_cookie() to randomize the
 * cookie before anything else.  We export the cookie as a DATA symbol
 * and provide an init function that sets it to a pseudo-random value.
 */
__attribute__((visibility("default"))) uintptr_t __security_cookie = 0x00002B992DDFA232ULL;

WINAPI_EXPORT void __security_init_cookie(void)
{
    /* Mix several entropy sources the same way the real CRT does */
    uintptr_t cookie = 0;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    cookie ^= (uintptr_t)ts.tv_sec;
    cookie ^= (uintptr_t)ts.tv_nsec;
    cookie ^= (uintptr_t)getpid();
    cookie ^= (uintptr_t)&cookie; /* ASLR stack address */
    /* Ensure the cookie is never the default constant */
    if (cookie == 0x00002B992DDFA232ULL || cookie == 0)
        cookie = 0x00002B992DDFA232ULL ^ 0xDEADBEEFCAFEBABEULL;
    __security_cookie = cookie;
}

/* __security_check_cookie — called by /GS epilogue; aborts on mismatch */
WINAPI_EXPORT void __security_check_cookie(uintptr_t cookie)
{
    if (cookie != __security_cookie) {
        fprintf(stderr, "[msvcrt] FATAL: Stack buffer overrun detected!\n");
        abort();
    }
}

/* __report_gsfailure — called when /GS detects corruption */
WINAPI_EXPORT void __report_gsfailure(uintptr_t cookie)
{
    (void)cookie;
    fprintf(stderr, "[msvcrt] FATAL: __report_gsfailure\n");
    abort();
}

/* __set_app_type — double-underscore variant used by newer CRT */
WINAPI_EXPORT int __set_app_type(int type)
{
    (void)type;
    return 0;
}

/* ----------------------------------------------------------------
 * C++ terminate / exception support
 * ---------------------------------------------------------------- */

/*
 * ?terminate@@YAXXZ — MSVC-mangled name for std::terminate().
 * ELF linker treats @@ as symbol versioning, so we can't export this
 * symbol directly. Instead, pe_import.c resolves it via mangled name table.
 * This is the backing implementation.
 */
WINAPI_EXPORT void msvcrt_terminate_impl(void)
{
    fprintf(stderr, "[msvcrt] terminate() called\n");
    abort();
}

/* C++ operator new/delete — mangled names resolved via pe_import.c table */
WINAPI_EXPORT void *msvcrt_operator_new(size_t size)
{
    void *p = malloc(size ? size : 1);
    if (!p) { fprintf(stderr, "[msvcrt] operator new: out of memory\n"); abort(); }
    return p;
}

WINAPI_EXPORT void *msvcrt_operator_new_array(size_t size)
{
    return msvcrt_operator_new(size);
}

WINAPI_EXPORT void msvcrt_operator_delete(void *ptr)
{
    free(ptr);
}

WINAPI_EXPORT void msvcrt_operator_delete_array(void *ptr)
{
    free(ptr);
}

/* __C_specific_handler — apps may import this from msvcrt.dll.
 * Forward to the actual implementation (also in ntdll_exception.c). */
typedef struct _EXCEPTION_RECORD_MSVCRT {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD_MSVCRT *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
} EXCEPTION_RECORD_MSVCRT;

typedef struct _CONTEXT_MSVCRT {
    BYTE data[1232]; /* Full CONTEXT is 1232 bytes */
} CONTEXT_MSVCRT;

typedef struct _DISPATCHER_CONTEXT_MSVCRT {
    BYTE data[128];
} DISPATCHER_CONTEXT_MSVCRT;

WINAPI_EXPORT int __C_specific_handler(
    EXCEPTION_RECORD_MSVCRT *ExceptionRecord,
    PVOID EstablisherFrame,
    CONTEXT_MSVCRT *ContextRecord,
    DISPATCHER_CONTEXT_MSVCRT *DispatcherContext)
{
    (void)ExceptionRecord;
    (void)EstablisherFrame;
    (void)ContextRecord;
    (void)DispatcherContext;
    return 0; /* EXCEPTION_CONTINUE_SEARCH */
}

/* _c_exit — clean up CRT and terminate */
WINAPI_EXPORT void _c_exit(void)
{
    fflush(stdout);
    fflush(stderr);
}

/* _register_thread_local_exe_atexit_callback */
WINAPI_EXPORT int _register_thread_local_exe_atexit_callback(void *callback)
{
    (void)callback;
    return 0;
}

/* _get_wide_winmain_command_line - for WinMain apps */
WINAPI_EXPORT uint16_t *_get_wide_winmain_command_line(void)
{
    return g_wcmdln_buf;
}

/* _initialize_onexit_table / _register_onexit_function / _execute_onexit_table */
typedef struct {
    void **_first;
    void **_last;
    void **_end;
} _onexit_table_t;

WINAPI_EXPORT int _initialize_onexit_table(_onexit_table_t *table)
{
    if (!table) return -1;
    table->_first = NULL;
    table->_last = NULL;
    table->_end = NULL;
    return 0;
}

/* ----------------------------------------------------------------
 * _o_ prefixed UCRT "private" functions
 *
 * api-ms-win-crt-private-l1-1-0.dll exports these _o_ prefixed
 * versions that forward to the standard implementations.
 * ---------------------------------------------------------------- */

WINAPI_EXPORT void *_o_malloc(size_t size) { return malloc(size); }
WINAPI_EXPORT void _o_free(void *ptr) { free(ptr); }
WINAPI_EXPORT void _o_exit(int status) { exit(status); }
WINAPI_EXPORT void _o__exit(int status) { _exit(status); }
WINAPI_EXPORT void _o__cexit(void) { fflush(stdout); fflush(stderr); }
extern long wcstol16(const uint16_t *s, uint16_t **endptr, int base);
WINAPI_EXPORT int _o__wcsicmp(const uint16_t *s1, const uint16_t *s2) {
    while (*s1 && *s2) {
        uint16_t c1 = *s1, c2 = *s2;
        if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
        if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
        if (c1 != c2) return (int)c1 - (int)c2;
        s1++; s2++;
    }
    return (int)*s1 - (int)*s2;
}
WINAPI_EXPORT long _o__wtol(const uint16_t *str) { return wcstol16(str, NULL, 10); }
WINAPI_EXPORT int _o_iswdigit(wint_t c) { return (c >= '0' && c <= '9'); }
WINAPI_EXPORT void _o_terminate(void) { abort(); }
WINAPI_EXPORT int _o__set_app_type(int type) { (void)type; return 0; }
WINAPI_EXPORT int _o__set_fmode(int mode) { (void)mode; return 0; }
WINAPI_EXPORT int _o__set_new_mode(int mode) { (void)mode; return 0; }
WINAPI_EXPORT void _o__invalid_parameter_noinfo(void) { }
WINAPI_EXPORT int _o__purecall(void) { fprintf(stderr, "[msvcrt] pure virtual call\n"); abort(); return 0; }
WINAPI_EXPORT int _o__configthreadlocale(int type) { (void)type; return 1; }
WINAPI_EXPORT int *_o__errno(void) { return _errno(); }
WINAPI_EXPORT int _o__get_errno(int *p) { return _get_errno(p); }
WINAPI_EXPORT int _o__set_errno(int v) { return _set_errno(v); }
WINAPI_EXPORT int _o__callnewh(size_t size) { (void)size; return 0; }
WINAPI_EXPORT int _o__crt_atexit(void (*f)(void)) { return pe_atexit_register(f); }

WINAPI_EXPORT int _o__seh_filter_exe(int a, void *b) { (void)a; (void)b; return 1; }

WINAPI_EXPORT uint16_t *_o__get_wide_winmain_command_line(void) { return g_wcmdln_buf; }

WINAPI_EXPORT int _o__initialize_onexit_table(_onexit_table_t *t) {
    if (!t) return -1;
    t->_first = t->_last = t->_end = NULL;
    return 0;
}
WINAPI_EXPORT int _o__register_onexit_function(void *table, void (*func)(void)) {
    (void)table; return pe_atexit_register(func);
}
WINAPI_EXPORT int _o__initialize_wide_environment(void) { return 0; }
WINAPI_EXPORT int _o__configure_wide_argv(int m) { (void)m; return 0; }
WINAPI_EXPORT int *_o___p__commode(void) { return &_commode; }

WINAPI_EXPORT uintptr_t _o__beginthreadex(
    void *sec, unsigned stack, _beginthreadex_proc start, void *arg,
    unsigned flags, unsigned *id)
{
    return _beginthreadex(sec, stack, start, arg, flags, id);
}

/* __current_exception / __current_exception_context - thread-local exception state */
static __thread void *g_current_exception = NULL;
static __thread void *g_current_exception_context = NULL;

WINAPI_EXPORT void **__current_exception(void) { return &g_current_exception; }
WINAPI_EXPORT void **__current_exception_context(void) { return &g_current_exception_context; }

/* _o_ prefixed stdio functions */
WINAPI_EXPORT int _o___stdio_common_vswprintf(
    uint64_t options, uint16_t *buf, size_t count,
    const uint16_t *fmt, void *locale, __builtin_ms_va_list ap)
{
    return __stdio_common_vswprintf(options, buf, count, fmt, locale, ap);
}

/* __std_exception_copy/destroy with _o_ prefix */
WINAPI_EXPORT void _o___std_exception_copy(const void *src, void *dst) {
    if (src && dst) memcpy(dst, src, sizeof(void*) * 2);
}
WINAPI_EXPORT void _o___std_exception_destroy(void *exc) {
    /*
     * Match the DoFree-flag-aware implementation in msvcrt_except.c.
     * Original code called free(p[0]) on the What pointer unconditionally,
     * which corrupts the heap when What is a string literal (DoFree==false).
     */
    if (!exc) return;
    struct { const char *what; unsigned char do_free; } *data = exc;
    if (data->do_free && data->what) {
        free((void *)data->what);
        data->what = NULL;
        data->do_free = 0;
    }
}

/* Additional _o_ prefixed UCRT private aliases for stdio/runtime functions */
WINAPI_EXPORT int _o___stdio_common_vfprintf(
    uint64_t opt, FILE *s, const char *f, void *l, __builtin_ms_va_list a) {
    return __stdio_common_vfprintf(opt, s, f, l, a);
}
WINAPI_EXPORT int _o___stdio_common_vfprintf_s(
    uint64_t opt, FILE *s, const char *f, void *l, __builtin_ms_va_list a) {
    return __stdio_common_vfprintf_s(opt, s, f, l, a);
}
WINAPI_EXPORT int _o___stdio_common_vsprintf(
    uint64_t opt, char *b, size_t n, const char *f, void *l, __builtin_ms_va_list a) {
    return __stdio_common_vsprintf(opt, b, n, f, l, a);
}
WINAPI_EXPORT int _o___stdio_common_vsprintf_s(
    uint64_t opt, char *b, size_t n, const char *f, void *l, __builtin_ms_va_list a) {
    return __stdio_common_vsprintf_s(opt, b, n, f, l, a);
}
WINAPI_EXPORT FILE *_o___acrt_iob_func(unsigned i) { return __acrt_iob_func(i); }
WINAPI_EXPORT void _o__invalid_parameter_noinfo_noreturn(void) { abort(); }
WINAPI_EXPORT int _o__initialize_narrow_environment(void) { return 0; }
WINAPI_EXPORT int _o__configure_narrow_argv(int m) { (void)m; return 0; }
WINAPI_EXPORT void _o__c_exit(void) { }
WINAPI_EXPORT int _o__register_thread_local_exe_atexit_callback(void *cb) { (void)cb; return 0; }
WINAPI_EXPORT int *_o___p___argc(void) { return &g_argc; }
WINAPI_EXPORT char ***_o___p___argv(void) { return &g_argv; }
WINAPI_EXPORT int _o__get_fmode(int *m) { if (m) *m = 0; return 0; }
WINAPI_EXPORT void _o__initterm(void (**s)(void), void (**e)(void)) { _initterm(s, e); }
WINAPI_EXPORT int _o__initterm_e(int (**s)(void), int (**e)(void)) { return _initterm_e(s, e); }
WINAPI_EXPORT int _o___setusermatherr(void *h) { (void)h; return 0; }
WINAPI_EXPORT void *_o___current_exception(void) { return NULL; }
WINAPI_EXPORT void *_o___current_exception_context(void) { return NULL; }

/* ----------------------------------------------------------------
 * 64-bit file I/O and low-level fd functions
 *
 * Required by DXVK d3d9.dll and other modern Win32 apps that import
 * from api-ms-win-crt-stdio-l1-1-0.dll.
 * ---------------------------------------------------------------- */

#include <sys/types.h>
#include <fcntl.h>

/*
 * _fseeki64 — 64-bit fseek for large files.
 * Maps directly to POSIX fseeko which accepts off_t (64-bit on LP64).
 */
WINAPI_EXPORT int _fseeki64(FILE *f, int64_t offset, int whence)
{
    if (!f) return -1;
    return fseeko(f, (off_t)offset, whence);
}

/*
 * _ftelli64 — 64-bit ftell.
 * Maps to POSIX ftello which returns off_t.
 */
WINAPI_EXPORT int64_t _ftelli64(FILE *f)
{
    if (!f) return -1;
    return (int64_t)ftello(f);
}

/*
 * _lseeki64 — 64-bit lseek on raw file descriptor.
 */
WINAPI_EXPORT int64_t _lseeki64(int fd, int64_t offset, int whence)
{
    return (int64_t)lseek(fd, (off_t)offset, whence);
}

/*
 * _write — write to file descriptor (MSVCRT low-level I/O).
 */
WINAPI_EXPORT int _write(int fd, const void *buf, unsigned int cnt)
{
    return (int)write(fd, buf, cnt);
}

/*
 * _read — read from file descriptor (MSVCRT low-level I/O).
 */
WINAPI_EXPORT int _read(int fd, void *buf, unsigned int cnt)
{
    return (int)read(fd, buf, cnt);
}

/*
 * _fdopen — associate a stream with an existing file descriptor.
 */
WINAPI_EXPORT FILE *_fdopen(int fd, const char *mode)
{
    return fdopen(fd, mode);
}

/*
 * _lock_file / _unlock_file — per-file stream locking.
 * Maps to POSIX flockfile/funlockfile.
 */
WINAPI_EXPORT void _lock_file(FILE *f)
{
    if (f) flockfile(f);
}

WINAPI_EXPORT void _unlock_file(FILE *f)
{
    if (f) funlockfile(f);
}

/* ----------------------------------------------------------------
 * _fstat64 — 64-bit file stat by file descriptor.
 *
 * Required by DXVK d3d9.dll which imports this from
 * api-ms-win-crt-filesystem-l1-1-0.dll.
 *
 * Calls POSIX fstat() and translates the Linux struct stat into
 * the Windows struct _stat64 layout.
 * ---------------------------------------------------------------- */

#include <sys/stat.h>

/*
 * Windows _stat64 structure (MSVC x64 layout, 56 bytes).
 * Use win_ prefix to avoid conflict with POSIX st_atime macro.
 */
typedef struct {
    uint32_t win_st_dev;        /* offset 0  */
    uint16_t win_st_ino;        /* offset 4  */
    uint16_t win_st_mode;       /* offset 6  */
    int16_t  win_st_nlink;      /* offset 8  */
    int16_t  win_st_uid;        /* offset 10 */
    int16_t  win_st_gid;        /* offset 12 */
    uint16_t win_pad0;          /* offset 14 */
    uint32_t win_st_rdev;       /* offset 16 */
    uint32_t win_pad1;          /* offset 20 */
    int64_t  win_st_size;       /* offset 24 */
    int64_t  win_st_atime;      /* offset 32 */
    int64_t  win_st_mtime;      /* offset 40 */
    int64_t  win_st_ctime;      /* offset 48 */
} win_stat64_t;  /* total 56 bytes */

/* Map Linux S_IF* mode bits to Windows _S_IF* equivalents */
#define WIN_S_IFREG  0x8000
#define WIN_S_IFDIR  0x4000
#define WIN_S_IFCHR  0x2000
#define WIN_S_IFIFO  0x1000
#define WIN_S_IREAD  0x0100
#define WIN_S_IWRITE 0x0080
#define WIN_S_IEXEC  0x0040

static uint16_t linux_mode_to_win(mode_t m)
{
    uint16_t wm = 0;

    if (S_ISREG(m))       wm |= WIN_S_IFREG;
    else if (S_ISDIR(m))  wm |= WIN_S_IFDIR;
    else if (S_ISCHR(m))  wm |= WIN_S_IFCHR;
    else if (S_ISFIFO(m)) wm |= WIN_S_IFIFO;
    else                  wm |= WIN_S_IFREG; /* fallback */

    if (m & S_IRUSR) wm |= WIN_S_IREAD;
    if (m & S_IWUSR) wm |= WIN_S_IWRITE;
    if (m & S_IXUSR) wm |= WIN_S_IEXEC;

    return wm;
}

/* ---- Low-level POSIX-style CRT file I/O ---- */

WINAPI_EXPORT int _open(const char *filename, int oflag, ...)
{
    /* Map common MSVC oflag bits to POSIX */
#define WIN_O_RDONLY  0x0000
#define WIN_O_WRONLY  0x0001
#define WIN_O_RDWR    0x0002
#define WIN_O_APPEND  0x0008
#define WIN_O_CREAT   0x0100
#define WIN_O_TRUNC   0x0200
#define WIN_O_EXCL    0x0400
#define WIN_O_BINARY  0x8000
    int flags = 0;
    int acc = oflag & 3;
    if (acc == WIN_O_RDONLY) flags = O_RDONLY;
    else if (acc == WIN_O_WRONLY) flags = O_WRONLY;
    else flags = O_RDWR;
    if (oflag & WIN_O_APPEND) flags |= O_APPEND;
    if (oflag & WIN_O_CREAT)  flags |= O_CREAT;
    if (oflag & WIN_O_TRUNC)  flags |= O_TRUNC;
    if (oflag & WIN_O_EXCL)   flags |= O_EXCL;
    __builtin_ms_va_list ap; __builtin_ms_va_start(ap, oflag);
    int mode = (oflag & WIN_O_CREAT) ? *(int *)ap : 0666;
    __builtin_ms_va_end(ap);
    return open(filename, flags, mode);
}

WINAPI_EXPORT int _wopen(const uint16_t *filename, int oflag, ...)
{
    if (!filename) { errno = EINVAL; return -1; }
    char path[4096] = {0};
    for (int i = 0; filename[i] && i < 4095; i++)
        path[i] = (char)filename[i];
    __builtin_ms_va_list ap; __builtin_ms_va_start(ap, oflag);
    /* Only consume a mode argument when O_CREAT is set — reading an
     * unset va_list slot is UB.  _open below re-parses ap for mode. */
    int mode = (oflag & WIN_O_CREAT) ? *(int *)ap : 0666;
    __builtin_ms_va_end(ap);
    return _open(path, oflag, mode);
}

WINAPI_EXPORT int _close(int fd) { return close(fd); }
WINAPI_EXPORT long _lseek(int fd, long offset, int whence) { return (long)lseek(fd, offset, whence); }
WINAPI_EXPORT long _tell(int fd) { return (long)lseek(fd, 0, SEEK_CUR); }
WINAPI_EXPORT int _eof(int fd)
{
    off_t cur = lseek(fd, 0, SEEK_CUR);
    off_t end = lseek(fd, 0, SEEK_END);
    lseek(fd, cur, SEEK_SET);
    return (cur >= end) ? 1 : 0;
}

WINAPI_EXPORT int _stat(const char *path, void *buffer)
{
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    /* Copy into Win32-compatible _stat32 struct (approximate) */
    int32_t *buf = (int32_t*)buffer;
    if (!buf) return -1;
    buf[0] = (int32_t)st.st_dev;   /* st_dev */
    buf[1] = (int32_t)st.st_ino;   /* st_ino */
    buf[2] = (int32_t)linux_mode_to_win(st.st_mode);  /* st_mode */
    buf[3] = (int32_t)st.st_nlink; /* st_nlink */
    buf[4] = (int32_t)st.st_uid;   /* st_uid */
    buf[5] = (int32_t)st.st_gid;   /* st_gid */
    buf[6] = (int32_t)st.st_rdev;  /* st_rdev */
    buf[7] = (int32_t)st.st_size;  /* st_size */
    buf[8] = (int32_t)st.st_atim.tv_sec;  /* st_atime */
    buf[9] = (int32_t)st.st_mtim.tv_sec;  /* st_mtime */
    buf[10]= (int32_t)st.st_ctim.tv_sec;  /* st_ctime */
    return 0;
}

WINAPI_EXPORT int _stat64(const char *path, void *buffer)
{
    /* Use a file descriptor version via open */
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    int r = fstat(fd, &st);
    close(fd);
    if (r != 0 || !buffer) return -1;
    /* Fill win_stat64_t */
    typedef struct { uint32_t d; uint16_t ino; uint16_t mode; int16_t nl,uid,gid; uint32_t rdev; int64_t size; int64_t at,mt,ct; } w64st;
    w64st *b = (w64st*)buffer;
    memset(b, 0, sizeof(*b));
    b->d    = (uint32_t)st.st_dev;
    b->ino  = (uint16_t)st.st_ino;
    b->mode = linux_mode_to_win(st.st_mode);
    b->nl   = (int16_t)st.st_nlink;
    b->uid  = (int16_t)st.st_uid;
    b->gid  = (int16_t)st.st_gid;
    b->rdev = (uint32_t)st.st_rdev;
    b->size = (int64_t)st.st_size;
    b->at   = (int64_t)st.st_atim.tv_sec;
    b->mt   = (int64_t)st.st_mtim.tv_sec;
    b->ct   = (int64_t)st.st_ctim.tv_sec;
    return 0;
}

WINAPI_EXPORT int _stati64(const char *path, void *buffer)
{
    return _stat(path, buffer);
}

WINAPI_EXPORT int _fstat(int fd, void *buffer)
{
    if (!buffer || fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0) return -1;
    int32_t *buf = (int32_t*)buffer;
    buf[0] = (int32_t)st.st_dev;
    buf[1] = (int32_t)st.st_ino;
    buf[2] = (int32_t)linux_mode_to_win(st.st_mode);
    buf[3] = (int32_t)st.st_nlink;
    buf[4] = (int32_t)st.st_uid;
    buf[5] = (int32_t)st.st_gid;
    buf[6] = (int32_t)st.st_rdev;
    buf[7] = (int32_t)st.st_size;
    buf[8] = (int32_t)st.st_atim.tv_sec;
    buf[9] = (int32_t)st.st_mtim.tv_sec;
    buf[10]= (int32_t)st.st_ctim.tv_sec;
    return 0;
}

WINAPI_EXPORT int _access(const char *path, int mode)
{
    return access(path, mode);
}

WINAPI_EXPORT int _waccess_s(const uint16_t *path, int mode)
{
    char narrow[4096]={0};
    for (int i = 0; path && path[i] && i < 4095; i++) narrow[i] = (char)path[i];
    return access(narrow, mode);
}

WINAPI_EXPORT int _mkdir(const char *path)
{
    return mkdir(path, 0777);
}

WINAPI_EXPORT int _rmdir(const char *path)
{
    return rmdir(path);
}

WINAPI_EXPORT char *_getcwd(char *buf, int size)
{
    return getcwd(buf, (size_t)size);
}

WINAPI_EXPORT int _chdir(const char *path)
{
    return chdir(path);
}

WINAPI_EXPORT int _fstat64(int fd, void *buffer)
{
    if (!buffer) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0)
        return -1;

    win_stat64_t *buf = (win_stat64_t *)buffer;
    memset(buf, 0, sizeof(*buf));

    buf->win_st_dev   = (uint32_t)st.st_dev;
    buf->win_st_ino   = (uint16_t)st.st_ino;
    buf->win_st_mode  = linux_mode_to_win(st.st_mode);
    buf->win_st_nlink = (int16_t)st.st_nlink;
    buf->win_st_uid   = (int16_t)st.st_uid;
    buf->win_st_gid   = (int16_t)st.st_gid;
    buf->win_st_rdev  = (uint32_t)st.st_rdev;
    buf->win_st_size  = (int64_t)st.st_size;
    buf->win_st_atime = (int64_t)st.st_atim.tv_sec;
    buf->win_st_mtime = (int64_t)st.st_mtim.tv_sec;
    buf->win_st_ctime = (int64_t)st.st_ctim.tv_sec;

    return 0;
}

/* _o_ aliases for the new low-level file ops */
WINAPI_EXPORT int _o__open(const char *f, int fl, ...) { return _open(f, fl, 0666); }
WINAPI_EXPORT int _o__close(int fd) { return _close(fd); }
WINAPI_EXPORT long _o__lseek(int fd, long o, int w) { return _lseek(fd, o, w); }
WINAPI_EXPORT long _o__tell(int fd) { return _tell(fd); }
WINAPI_EXPORT int _o__eof(int fd) { return _eof(fd); }
WINAPI_EXPORT int _o__stat(const char *p, void *b) { return _stat(p, b); }
WINAPI_EXPORT int _o__stat64(const char *p, void *b) { return _stat64(p, b); }
WINAPI_EXPORT int _o__stati64(const char *p, void *b) { return _stati64(p, b); }
WINAPI_EXPORT int _o__fstat(int fd, void *b) { return _fstat(fd, b); }
WINAPI_EXPORT int _o__fstat64(int fd, void *b) { return _fstat64(fd, b); }
WINAPI_EXPORT int _o__access(const char *p, int m) { return _access(p, m); }
WINAPI_EXPORT int _o__mkdir(const char *p) { return _mkdir(p); }
WINAPI_EXPORT int _o__rmdir(const char *p) { return _rmdir(p); }
WINAPI_EXPORT char *_o__getcwd(char *b, int n) { return _getcwd(b, n); }
WINAPI_EXPORT int _o__chdir(const char *p) { return _chdir(p); }
