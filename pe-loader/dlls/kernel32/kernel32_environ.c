/*
 * kernel32_environ.c - Environment and command-line functions
 *
 * GetCommandLineA/W, GetEnvironmentVariableA/W, SetEnvironmentVariableA,
 * GetStartupInfoA/W.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "common/dll_common.h"
#include "compat/env_setup.h"

/* Forward declaration */
static void seed_windows_env_vars(void);

/* Cache the command line for the lifetime of the process.
 * kernel32_set_command_line() is called by the loader/loader_init.c bridge
 * before the PE entry point runs, so the buffer is pre-populated with
 * the PE binary's actual command line rather than peloader's argv. */
static char g_command_line[32768] = "";
static WCHAR g_command_line_w[32768] = {0};
static int g_cmdline_set = 0;   /* 1 = set explicitly by loader */
static int g_cmdline_init = 0;

/* Called by the loader bridge to provide the PE command line */
void kernel32_set_command_line(const char *cmdline)
{
    if (cmdline) {
        strncpy(g_command_line, cmdline, sizeof(g_command_line) - 1);
        g_command_line[sizeof(g_command_line) - 1] = '\0';
        g_cmdline_set = 1;
        g_cmdline_init = 0; /* Force re-init of wide string */
    }
}

/* Called by the loader bridge to provide the module filename */
static char g_module_filename[4096] = "";

void kernel32_set_module_filename(const char *filename)
{
    if (filename) {
        strncpy(g_module_filename, filename, sizeof(g_module_filename) - 1);
        g_module_filename[sizeof(g_module_filename) - 1] = '\0';
    }
}

static void ensure_cmdline(void)
{
    if (g_cmdline_init) return;
    g_cmdline_init = 1;

    /* If the loader already set the command line, just build the wide version */
    if (!g_cmdline_set) {
        /* Fallback: read from /proc/self/cmdline */
        FILE *f = fopen("/proc/self/cmdline", "r");
        if (f) {
            size_t pos = 0;
            int c;
            int first = 1;
            while ((c = fgetc(f)) != EOF && pos < sizeof(g_command_line) - 2) {
                if (c == '\0') {
                    if (first) first = 0;
                    g_command_line[pos++] = ' ';
                } else {
                    g_command_line[pos++] = (char)c;
                }
            }
            if (pos > 0 && g_command_line[pos - 1] == ' ')
                pos--;
            g_command_line[pos] = '\0';
            fclose(f);
        }
    }

    /* Convert to wide */
    size_t i;
    for (i = 0; g_command_line[i] && i < sizeof(g_command_line_w) / sizeof(WCHAR) - 1; i++)
        g_command_line_w[i] = (WCHAR)(unsigned char)g_command_line[i];
    g_command_line_w[i] = 0;
}

WINAPI_EXPORT LPSTR GetCommandLineA(void)
{
    ensure_cmdline();
    return g_command_line;
}

WINAPI_EXPORT LPWSTR GetCommandLineW(void)
{
    ensure_cmdline();
    return g_command_line_w;
}

WINAPI_EXPORT DWORD GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize)
{
    if (!lpName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    seed_windows_env_vars();
    const char *val = getenv(lpName);
    if (!val) {
        set_last_error(ERROR_ENVVAR_NOT_FOUND);
        return 0;
    }

    size_t len = strlen(val);
    /* If caller passes NULL buffer OR a buffer too small, return required size
     * (incl. NUL).  Guards against strcpy into NULL when nSize > 0 but the
     * caller gave no buffer — a valid real-Windows probing pattern. */
    if (!lpBuffer || (DWORD)(len + 1) > nSize) {
        return (DWORD)(len + 1);
    }

    strcpy(lpBuffer, val);
    return (DWORD)len;
}

WINAPI_EXPORT DWORD GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize)
{
    if (!lpName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    seed_windows_env_vars();

    /* Convert name to narrow */
    char narrow_name[512];
    int i = 0;
    while (lpName[i] && i < 511) {
        narrow_name[i] = (char)(lpName[i] & 0xFF);
        i++;
    }
    narrow_name[i] = '\0';

    const char *val = getenv(narrow_name);
    if (!val) {
        set_last_error(ERROR_ENVVAR_NOT_FOUND);
        return 0;
    }

    size_t len = strlen(val);
    /* NULL buffer probing: return required length (incl. NUL) instead of
     * writing into a NULL pointer. */
    if (!lpBuffer || (DWORD)(len + 1) > nSize)
        return (DWORD)(len + 1);

    for (DWORD j = 0; j < (DWORD)len; j++)
        lpBuffer[j] = (WCHAR)(unsigned char)val[j];
    lpBuffer[len] = 0;
    return (DWORD)len;
}

WINAPI_EXPORT BOOL SetEnvironmentVariableA(LPCSTR lpName, LPCSTR lpValue)
{
    if (!lpName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (lpValue)
        return setenv(lpName, lpValue, 1) == 0;
    else
        return unsetenv(lpName) == 0;
}

WINAPI_EXPORT BOOL SetEnvironmentVariableW(LPCWSTR lpName, LPCWSTR lpValue)
{
    if (!lpName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    char name_narrow[512];
    int i = 0;
    while (lpName[i] && i < 511) {
        name_narrow[i] = (char)(lpName[i] & 0xFF);
        i++;
    }
    name_narrow[i] = '\0';

    if (!lpValue)
        return unsetenv(name_narrow) == 0;

    char val_narrow[32768];
    i = 0;
    while (lpValue[i] && i < 32767) {
        val_narrow[i] = (char)(lpValue[i] & 0xFF);
        i++;
    }
    val_narrow[i] = '\0';

    return setenv(name_narrow, val_narrow, 1) == 0;
}

WINAPI_EXPORT LPCH GetEnvironmentStrings(void)
{
    extern char **environ;
    /* Build a double-null-terminated block: "VAR=VALUE\0VAR=VALUE\0\0" */
    size_t total = 0;
    for (int i = 0; environ[i]; i++)
        total += strlen(environ[i]) + 1;
    total++; /* Final null */

    char *block = malloc(total);
    if (!block) return NULL;

    char *p = block;
    for (int i = 0; environ[i]; i++) {
        size_t len = strlen(environ[i]);
        memcpy(p, environ[i], len);
        p[len] = '\0';
        p += len + 1;
    }
    *p = '\0'; /* Double null */

    return block;
}

WINAPI_EXPORT LPWCH GetEnvironmentStringsW(void)
{
    extern char **environ;
    /* Calculate total length */
    size_t total = 0;
    for (int i = 0; environ[i]; i++)
        total += strlen(environ[i]) + 1;
    total++; /* Final null */

    WCHAR *block = malloc(total * sizeof(WCHAR));
    if (!block) return NULL;

    WCHAR *p = block;
    for (int i = 0; environ[i]; i++) {
        const char *s = environ[i];
        while (*s)
            *p++ = (WCHAR)(unsigned char)*s++;
        *p++ = 0;
    }
    *p = 0; /* Double null */

    return block;
}

WINAPI_EXPORT BOOL FreeEnvironmentStringsA(LPCH penv)
{
    free(penv);
    return TRUE;
}

WINAPI_EXPORT BOOL FreeEnvironmentStringsW(LPWCH penv)
{
    free(penv);
    return TRUE;
}

WINAPI_EXPORT void GetStartupInfoA(void *lpStartupInfo)
{
    typedef struct {
        DWORD  cb;
        LPSTR  lpReserved;
        LPSTR  lpDesktop;
        LPSTR  lpTitle;
        DWORD  dwX, dwY;
        DWORD  dwXSize, dwYSize;
        DWORD  dwXCountChars, dwYCountChars;
        DWORD  dwFillAttribute;
        DWORD  dwFlags;
        WORD   wShowWindow;
        WORD   cbReserved2;
        LPBYTE lpReserved2;
        HANDLE hStdInput;
        HANDLE hStdOutput;
        HANDLE hStdError;
    } STARTUPINFOA;

    STARTUPINFOA *si = (STARTUPINFOA *)lpStartupInfo;
    memset(si, 0, sizeof(STARTUPINFOA));
    si->cb = sizeof(STARTUPINFOA);
    si->hStdInput  = get_std_handle(STD_INPUT_HANDLE);
    si->hStdOutput = get_std_handle(STD_OUTPUT_HANDLE);
    si->hStdError  = get_std_handle(STD_ERROR_HANDLE);
}

WINAPI_EXPORT void GetStartupInfoW(void *lpStartupInfo)
{
    /* Same layout, just zero it + set cb */
    memset(lpStartupInfo, 0, 104); /* sizeof(STARTUPINFOW) on x64 */
    *(DWORD *)lpStartupInfo = 104;
}

WINAPI_EXPORT LPSTR GetEnvironmentStringsA(void)
{
    return GetEnvironmentStrings();
}

/* ---------- ExpandEnvironmentStrings ---------- */

/*
 * Seed standard Windows environment variables into the Linux environment
 * so that ExpandEnvironmentStrings and GetEnvironmentVariable work for
 * %USERPROFILE%, %APPDATA%, %LOCALAPPDATA%, %PROGRAMFILES%, etc.
 * Called once on first use. Uses ~/.pe-compat/drives/c/ as the root.
 */
static void seed_windows_env_vars(void)
{
    static int seeded = 0;
    if (seeded) return;
    seeded = 1;

    const char *home = getenv("HOME");
    if (!home) home = "/tmp";

    char buf[4096];
    const char *user = "user";
    struct passwd *pw = getpwuid(getuid());
    if (pw) user = pw->pw_name;

    /* Helper: set env var only if not already present */
    #define SEEDV(name, val) do { if (!getenv(name)) setenv(name, val, 0); } while(0)

    snprintf(buf, sizeof(buf), "%s/.pe-compat/drives/c/Users/%s", home, user);
    SEEDV("USERPROFILE", buf);

    snprintf(buf, sizeof(buf), "%s/.pe-compat/drives/c/Users/%s/AppData/Roaming", home, user);
    SEEDV("APPDATA", buf);

    snprintf(buf, sizeof(buf), "%s/.pe-compat/drives/c/Users/%s/AppData/Local", home, user);
    SEEDV("LOCALAPPDATA", buf);

    snprintf(buf, sizeof(buf), "%s/.pe-compat/drives/c/ProgramData", home);
    SEEDV("PROGRAMDATA", buf);
    SEEDV("ALLUSERSPROFILE", buf);

    snprintf(buf, sizeof(buf), "%s/.pe-compat/drives/c/Program Files", home);
    SEEDV("PROGRAMFILES", buf);
    SEEDV("ProgramFiles(x86)", buf);

    snprintf(buf, sizeof(buf), "%s/.pe-compat/drives/c/Program Files/Common Files", home);
    SEEDV("COMMONPROGRAMFILES", buf);

    snprintf(buf, sizeof(buf), "%s/.pe-compat/drives/c/Windows", home);
    SEEDV("SYSTEMROOT", buf);
    SEEDV("WINDIR", buf);

    SEEDV("SYSTEMDRIVE", "C:");
    SEEDV("HOMEDRIVE", "C:");

    snprintf(buf, sizeof(buf), "%s/.pe-compat/drives/c/Users/%s/AppData/Local/Temp", home, user);
    SEEDV("TEMP", buf);
    SEEDV("TMP", buf);

    snprintf(buf, sizeof(buf), "\\Users\\%s", user);
    SEEDV("HOMEPATH", buf);

    snprintf(buf, sizeof(buf), "%s/.pe-compat/drives/c/Users/Public", home);
    SEEDV("PUBLIC", buf);

    SEEDV("USERNAME", user);
    SEEDV("OS", "Windows_NT");

    snprintf(buf, sizeof(buf), "%ld", sysconf(_SC_NPROCESSORS_ONLN));
    SEEDV("NUMBER_OF_PROCESSORS", buf);

    /* COMPUTERNAME from actual hostname */
    if (!getenv("COMPUTERNAME")) {
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0)
            setenv("COMPUTERNAME", hostname, 0);
        else
            setenv("COMPUTERNAME", "ARCHLINUX", 0);
    }

    #undef SEEDV
}

WINAPI_EXPORT DWORD ExpandEnvironmentStringsA(LPCSTR lpSrc, LPSTR lpDst, DWORD nSize)
{
    seed_windows_env_vars();
    if (!lpSrc) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    char result[32768];
    size_t pos = 0;
    const char *p = lpSrc;

    while (*p && pos < sizeof(result) - 1) {
        if (*p == '%') {
            const char *end = strchr(p + 1, '%');
            if (end && end > p + 1) {
                size_t var_len = end - p - 1;
                char var_name[512];
                if (var_len < sizeof(var_name)) {
                    memcpy(var_name, p + 1, var_len);
                    var_name[var_len] = '\0';

                    const char *val = getenv(var_name);
                    if (val) {
                        size_t vl = strlen(val);
                        if (pos + vl < sizeof(result)) {
                            memcpy(result + pos, val, vl);
                            pos += vl;
                        }
                        p = end + 1;
                        continue;
                    }
                }
                /* Variable not found, keep literal */
                result[pos++] = *p++;
            } else {
                result[pos++] = *p++;
            }
        } else {
            result[pos++] = *p++;
        }
    }
    result[pos] = '\0';

    DWORD needed = (DWORD)(pos + 1);
    if (lpDst && nSize > 0) {
        if (nSize >= needed)
            memcpy(lpDst, result, needed);
        else
            memcpy(lpDst, result, nSize - 1);
        lpDst[nSize < needed ? nSize - 1 : needed - 1] = '\0';
    }

    return needed;
}

WINAPI_EXPORT DWORD ExpandEnvironmentStringsW(LPCWSTR lpSrc, LPWSTR lpDst, DWORD nSize)
{
    if (!lpSrc) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    /* Convert to narrow, expand, convert back */
    char narrow[32768];
    int i = 0;
    while (lpSrc[i] && i < 32767) {
        narrow[i] = (char)(lpSrc[i] & 0xFF);
        i++;
    }
    narrow[i] = '\0';

    char expanded[32768];
    DWORD len = ExpandEnvironmentStringsA(narrow, expanded, sizeof(expanded));
    if (len == 0) return 0;

    /* 'len' is the required buffer size (includes null terminator). */
    if (lpDst && nSize > 0) {
        DWORD copy = len < nSize ? len : nSize;
        /* Copy characters including the trailing NUL if it fits. */
        for (DWORD j = 0; j < copy; j++)
            lpDst[j] = (WCHAR)(unsigned char)expanded[j];
        /* Ensure NUL termination when truncated. */
        lpDst[copy - 1] = 0;
    }

    return len;
}

/* ---------- GetComputerName ---------- */

WINAPI_EXPORT BOOL GetComputerNameA(LPSTR lpBuffer, LPDWORD nSize)
{
    if (!lpBuffer || !nSize) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        strncpy(hostname, "ARCHLINUX", sizeof(hostname));
    }
    /* POSIX gethostname() may not NUL-terminate if truncated. */
    hostname[sizeof(hostname) - 1] = '\0';

    DWORD len = (DWORD)strlen(hostname);
    if (*nSize < len + 1) {
        *nSize = len + 1;
        set_last_error(ERROR_BUFFER_OVERFLOW);
        return FALSE;
    }

    strcpy(lpBuffer, hostname);
    *nSize = len;
    return TRUE;
}

WINAPI_EXPORT BOOL GetComputerNameW(LPWSTR lpBuffer, LPDWORD nSize)
{
    char narrow[256];
    DWORD narrow_size = sizeof(narrow);
    if (!GetComputerNameA(narrow, &narrow_size))
        return FALSE;

    DWORD len = (DWORD)strlen(narrow);
    if (!lpBuffer || !nSize || *nSize < len + 1) {
        if (nSize) *nSize = len + 1;
        set_last_error(ERROR_BUFFER_OVERFLOW);
        return FALSE;
    }

    for (DWORD i = 0; i <= len; i++)
        lpBuffer[i] = (WCHAR)(unsigned char)narrow[i];
    *nSize = len;
    return TRUE;
}

/* ---------- GetComputerNameEx ---------- */

WINAPI_EXPORT BOOL GetComputerNameExA(int NameType, LPSTR lpBuffer, LPDWORD nSize)
{
    (void)NameType; /* Treat all types the same */
    return GetComputerNameA(lpBuffer, nSize);
}

WINAPI_EXPORT BOOL GetComputerNameExW(int NameType, LPWSTR lpBuffer, LPDWORD nSize)
{
    (void)NameType;
    return GetComputerNameW(lpBuffer, nSize);
}

