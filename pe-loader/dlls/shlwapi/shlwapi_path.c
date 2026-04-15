/*
 * shlwapi_path.c - shlwapi.dll stubs (Path utilities, string helpers)
 *
 * PathFileExistsA/W, PathIsDirectoryA, PathIsRelativeA,
 * PathCombineA, PathRemoveFileSpecA, PathFindFileNameA,
 * PathFindExtensionA, PathAddExtensionA, PathRemoveExtensionA,
 * PathAppendA, PathStripPathA, PathCanonicalizeA,
 * StrStrIA, StrCmpIA, StrCmpNIA, wvnsprintfA,
 * SHDeleteKeyA, PathIsURLW.
 *
 * Many Windows applications use these path manipulation and string
 * helper functions from shlwapi.dll.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>

#include "common/dll_common.h"
#include "compat/ms_abi_format.h"

/*
 * Debug logging gate. Session 30: shlwapi path helpers were hit thousands
 * of times per frame (Qt/.NET apps iterate PathFindFileName etc. in loops);
 * unconditional fprintf on every call dominated the profile. Now opt-in via
 * PE_SHLWAPI_TRACE=1. fprintf to stderr is otherwise a no-op.
 */
static int shlwapi_trace_on(void)
{
    static int probed = -1;
    if (probed == -1) {
        const char *env = getenv("PE_SHLWAPI_TRACE");
        probed = (env && env[0] && env[0] != '0') ? 1 : 0;
    }
    return probed;
}
#define SHLW_TRACE(...) do { if (__builtin_expect(shlwapi_trace_on(), 0)) \
    fprintf(stderr, __VA_ARGS__); } while (0)

/* ------------------------------------------------------------------ */
/*  Path existence / type                                              */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT BOOL PathFileExistsA(LPCSTR pszPath)
{
    SHLW_TRACE("[shlwapi] PathFileExistsA(\"%s\")\n",
            pszPath ? pszPath : "(null)");

    if (!pszPath)
        return FALSE;

    char linux_path[4096];
    win_path_to_linux(pszPath, linux_path, sizeof(linux_path));

    return (access(linux_path, F_OK) == 0) ? TRUE : FALSE;
}

WINAPI_EXPORT BOOL PathFileExistsW(LPCWSTR pszPath)
{
    SHLW_TRACE("[shlwapi] PathFileExistsW(...)\n");

    if (!pszPath)
        return FALSE;

    /* Convert wide to narrow (ASCII subset) */
    char narrow[4096];
    int i;
    for (i = 0; pszPath[i] && i < 4095; i++)
        narrow[i] = (char)(pszPath[i] & 0xFF);
    narrow[i] = '\0';

    return PathFileExistsA(narrow);
}

WINAPI_EXPORT BOOL PathIsDirectoryA(LPCSTR pszPath)
{
    SHLW_TRACE("[shlwapi] PathIsDirectoryA(\"%s\")\n",
            pszPath ? pszPath : "(null)");

    if (!pszPath)
        return FALSE;

    char linux_path[4096];
    win_path_to_linux(pszPath, linux_path, sizeof(linux_path));

    struct stat st;
    if (stat(linux_path, &st) < 0)
        return FALSE;

    return S_ISDIR(st.st_mode) ? TRUE : FALSE;
}

WINAPI_EXPORT BOOL PathIsRelativeA(LPCSTR pszPath)
{
    SHLW_TRACE("[shlwapi] PathIsRelativeA(\"%s\")\n",
            pszPath ? pszPath : "(null)");

    if (!pszPath || pszPath[0] == '\0')
        return TRUE;

    /* Absolute if it starts with a backslash or a drive letter (e.g. C:\) */
    if (pszPath[0] == '\\' || pszPath[0] == '/')
        return FALSE;
    if (isalpha((unsigned char)pszPath[0]) && pszPath[1] == ':')
        return FALSE;

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Path combination / manipulation                                    */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT LPSTR PathCombineA(LPSTR pszDest, LPCSTR pszDir, LPCSTR pszFile)
{
    SHLW_TRACE("[shlwapi] PathCombineA(\"%s\", \"%s\")\n",
            pszDir ? pszDir : "(null)",
            pszFile ? pszFile : "(null)");

    if (!pszDest)
        return NULL;

    if (!pszDir && !pszFile) {
        pszDest[0] = '\0';
        return NULL;
    }

    if (!pszDir) {
        strncpy(pszDest, pszFile, MAX_PATH - 1);
        pszDest[MAX_PATH - 1] = '\0';
        return pszDest;
    }

    if (!pszFile) {
        strncpy(pszDest, pszDir, MAX_PATH - 1);
        pszDest[MAX_PATH - 1] = '\0';
        return pszDest;
    }

    /* If pszFile is an absolute path, use it directly */
    if (!PathIsRelativeA(pszFile)) {
        strncpy(pszDest, pszFile, MAX_PATH - 1);
        pszDest[MAX_PATH - 1] = '\0';
        return pszDest;
    }

    /* Combine: dir + separator + file */
    size_t dir_len = strlen(pszDir);
    if (dir_len > 0 && pszDir[dir_len - 1] != '\\' && pszDir[dir_len - 1] != '/')
        snprintf(pszDest, MAX_PATH, "%s\\%s", pszDir, pszFile);
    else
        snprintf(pszDest, MAX_PATH, "%s%s", pszDir, pszFile);

    return pszDest;
}

WINAPI_EXPORT BOOL PathRemoveFileSpecA(LPSTR pszPath)
{
    SHLW_TRACE("[shlwapi] PathRemoveFileSpecA(\"%s\")\n",
            pszPath ? pszPath : "(null)");

    if (!pszPath)
        return FALSE;

    /* Find last separator */
    char *last_sep = NULL;
    for (char *p = pszPath; *p; p++) {
        if (*p == '\\' || *p == '/')
            last_sep = p;
    }

    if (last_sep) {
        /* Keep the root separator for paths like "C:\" or "\" */
        if (last_sep == pszPath || (last_sep == pszPath + 2 && pszPath[1] == ':'))
            last_sep[1] = '\0';
        else
            *last_sep = '\0';
        return TRUE;
    }

    return FALSE;
}

WINAPI_EXPORT LPSTR PathFindFileNameA(LPCSTR pszPath)
{
    SHLW_TRACE("[shlwapi] PathFindFileNameA(\"%s\")\n",
            pszPath ? pszPath : "(null)");

    if (!pszPath)
        return (LPSTR)pszPath;

    const char *last = pszPath;
    for (const char *p = pszPath; *p; p++) {
        if (*p == '\\' || *p == '/')
            last = p + 1;
    }

    return (LPSTR)last;
}

WINAPI_EXPORT LPSTR PathFindExtensionA(LPCSTR pszPath)
{
    SHLW_TRACE("[shlwapi] PathFindExtensionA(\"%s\")\n",
            pszPath ? pszPath : "(null)");

    if (!pszPath)
        return (LPSTR)pszPath;

    /* Search from the filename portion only */
    const char *filename = PathFindFileNameA(pszPath);
    const char *dot = NULL;
    for (const char *p = filename; *p; p++) {
        if (*p == '.')
            dot = p;
    }

    /* Return pointer to the dot, or to the null terminator */
    if (dot)
        return (LPSTR)dot;
    return (LPSTR)(pszPath + strlen(pszPath));
}

WINAPI_EXPORT BOOL PathAddExtensionA(LPSTR pszPath, LPCSTR pszExt)
{
    SHLW_TRACE("[shlwapi] PathAddExtensionA(\"%s\", \"%s\")\n",
            pszPath ? pszPath : "(null)",
            pszExt ? pszExt : "(null)");

    if (!pszPath)
        return FALSE;

    /* Only add if there is no existing extension */
    LPSTR existing = PathFindExtensionA(pszPath);
    if (existing && *existing != '\0')
        return FALSE;

    if (!pszExt)
        pszExt = ".exe";

    size_t path_len = strlen(pszPath);
    size_t ext_len = strlen(pszExt);

    if (path_len + ext_len >= MAX_PATH)
        return FALSE;

    strcat(pszPath, pszExt);
    return TRUE;
}

WINAPI_EXPORT void PathRemoveExtensionA(LPSTR pszPath)
{
    SHLW_TRACE("[shlwapi] PathRemoveExtensionA(\"%s\")\n",
            pszPath ? pszPath : "(null)");

    if (!pszPath)
        return;

    LPSTR ext = PathFindExtensionA(pszPath);
    if (ext && *ext == '.')
        *ext = '\0';
}

WINAPI_EXPORT BOOL PathAppendA(LPSTR pszPath, LPCSTR pszMore)
{
    SHLW_TRACE("[shlwapi] PathAppendA(\"%s\", \"%s\")\n",
            pszPath ? pszPath : "(null)",
            pszMore ? pszMore : "(null)");

    if (!pszPath || !pszMore)
        return FALSE;

    size_t path_len = strlen(pszPath);

    /* Add separator if needed */
    if (path_len > 0 && pszPath[path_len - 1] != '\\' && pszPath[path_len - 1] != '/') {
        if (path_len + 1 >= MAX_PATH)
            return FALSE;
        pszPath[path_len] = '\\';
        pszPath[path_len + 1] = '\0';
        path_len++;
    }

    /* Skip leading separators in pszMore */
    while (*pszMore == '\\' || *pszMore == '/')
        pszMore++;

    if (path_len + strlen(pszMore) >= MAX_PATH)
        return FALSE;

    strcat(pszPath, pszMore);
    return TRUE;
}

WINAPI_EXPORT void PathStripPathA(LPSTR pszPath)
{
    SHLW_TRACE("[shlwapi] PathStripPathA(\"%s\")\n",
            pszPath ? pszPath : "(null)");

    if (!pszPath)
        return;

    LPSTR filename = PathFindFileNameA(pszPath);
    if (filename != pszPath)
        memmove(pszPath, filename, strlen(filename) + 1);
}

WINAPI_EXPORT BOOL PathCanonicalizeA(LPSTR pszDest, LPCSTR pszSrc)
{
    SHLW_TRACE("[shlwapi] PathCanonicalizeA(\"%s\")\n",
            pszSrc ? pszSrc : "(null)");

    if (!pszDest || !pszSrc)
        return FALSE;

    /* Simple canonicalization: copy and resolve . and .. components */
    char buf[MAX_PATH];
    strncpy(buf, pszSrc, MAX_PATH - 1);
    buf[MAX_PATH - 1] = '\0';

    /* Convert forward slashes to backslashes for consistency */
    for (char *p = buf; *p; p++) {
        if (*p == '/')
            *p = '\\';
    }

    /* Split into components, resolve . and .. */
    char *components[MAX_PATH];
    int count = 0;

    /* Handle prefix (drive letter or leading backslash) */
    char prefix[4] = {0};
    char *start = buf;
    if (isalpha((unsigned char)buf[0]) && buf[1] == ':') {
        prefix[0] = buf[0];
        prefix[1] = ':';
        start = buf + 2;
        if (*start == '\\')
            start++;
    } else if (buf[0] == '\\') {
        start = buf + 1;
    }

    /* Tokenize by backslash */
    char *saveptr = NULL;
    char *token = strtok_r(start, "\\", &saveptr);
    while (token) {
        if (strcmp(token, ".") == 0) {
            /* Skip current dir */
        } else if (strcmp(token, "..") == 0) {
            if (count > 0)
                count--;
        } else {
            components[count++] = token;
        }
        token = strtok_r(NULL, "\\", &saveptr);
    }

    /* Reassemble with bounds checking */
    int pos = 0;
    if (prefix[0]) {
        pos = snprintf(pszDest, MAX_PATH, "%s\\", prefix);
        if (pos < 0 || pos >= MAX_PATH) { pszDest[0] = '\0'; return FALSE; }
    } else if (pszSrc[0] == '\\' || pszSrc[0] == '/') {
        pos = snprintf(pszDest, MAX_PATH, "\\");
        if (pos < 0 || pos >= MAX_PATH) { pszDest[0] = '\0'; return FALSE; }
    } else {
        pszDest[0] = '\0';
    }

    for (int i = 0; i < count; i++) {
        pos += snprintf(pszDest + pos, MAX_PATH - pos, "%s%s",
                        (i > 0) ? "\\" : "", components[i]);
        if (pos >= MAX_PATH) { pszDest[MAX_PATH - 1] = '\0'; return TRUE; }
    }

    if (pszDest[0] == '\0')
        strcpy(pszDest, ".");

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  String helpers                                                     */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT LPSTR StrStrIA(LPCSTR pszFirst, LPCSTR pszSrch)
{
    SHLW_TRACE("[shlwapi] StrStrIA(\"%s\", \"%s\")\n",
            pszFirst ? pszFirst : "(null)",
            pszSrch ? pszSrch : "(null)");

    if (!pszFirst || !pszSrch)
        return NULL;

    return (LPSTR)strcasestr(pszFirst, pszSrch);
}

WINAPI_EXPORT int StrCmpIA(LPCSTR psz1, LPCSTR psz2)
{
    SHLW_TRACE("[shlwapi] StrCmpIA(\"%s\", \"%s\")\n",
            psz1 ? psz1 : "(null)",
            psz2 ? psz2 : "(null)");

    if (!psz1 && !psz2) return 0;
    if (!psz1) return -1;
    if (!psz2) return 1;

    return strcasecmp(psz1, psz2);
}

WINAPI_EXPORT int StrCmpNIA(LPCSTR psz1, LPCSTR psz2, int nChar)
{
    SHLW_TRACE("[shlwapi] StrCmpNIA(\"%s\", \"%s\", %d)\n",
            psz1 ? psz1 : "(null)",
            psz2 ? psz2 : "(null)",
            nChar);

    if (!psz1 && !psz2) return 0;
    if (!psz1) return -1;
    if (!psz2) return 1;

    return strncasecmp(psz1, psz2, (size_t)nChar);
}

WINAPI_EXPORT int wvnsprintfA(LPSTR pszDest, int cchDest, LPCSTR pszFmt, __builtin_ms_va_list arglist)
{
    SHLW_TRACE("[shlwapi] wvnsprintfA(...)\n");

    if (!pszDest || cchDest <= 0)
        return -1;

    return ms_abi_vformat(NULL, pszDest, (size_t)cchDest, pszFmt, arglist);
}

/* ------------------------------------------------------------------ */
/*  Registry helper stub                                               */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT LONG SHDeleteKeyA(HKEY hKey, LPCSTR pszSubKey)
{
    (void)hKey;

    SHLW_TRACE("[shlwapi] SHDeleteKeyA(\"%s\")\n",
            pszSubKey ? pszSubKey : "(null)");

    return ERROR_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  URL detection                                                      */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/*  Wide-char path helpers                                              */
/* ------------------------------------------------------------------ */

/* Helper: narrow wchar string for path ops */
static void w_to_narrow(const uint16_t *ws, char *buf, size_t bufsz)
{
    size_t i = 0;
    while (ws && ws[i] && i < bufsz - 1) { buf[i] = (char)ws[i]; i++; }
    buf[i] = '\0';
}

/* Helper: fill wide output from narrow */
static void narrow_to_w(const char *s, uint16_t *buf, size_t bufsz)
{
    size_t i = 0;
    while (s && s[i] && i < bufsz - 1) { buf[i] = (uint16_t)(uint8_t)s[i]; i++; }
    buf[i] = 0;
}

/* Wide char path length */
static size_t wcslen16(const uint16_t *s)
{
    size_t n = 0; while (s && s[n]) n++; return n;
}

WINAPI_EXPORT BOOL PathIsDirectoryW(LPCWSTR pszPath)
{
    char path[4096]; w_to_narrow(pszPath, path, sizeof(path));
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) ? TRUE : FALSE;
}

WINAPI_EXPORT BOOL PathIsRelativeW(LPCWSTR pszPath)
{
    if (!pszPath || !pszPath[0]) return TRUE;
    /* Relative if not starting with backslash, forward slash, or X:\ */
    if (pszPath[0] == '/' || pszPath[0] == '\\') return FALSE;
    if (((pszPath[0] >= 'A' && pszPath[0] <= 'Z') ||
         (pszPath[0] >= 'a' && pszPath[0] <= 'z')) && pszPath[1] == ':')
        return FALSE;
    return TRUE;
}

WINAPI_EXPORT uint16_t *PathCombineW(uint16_t *pszDest, LPCWSTR pszDir, LPCWSTR pszFile)
{
    if (!pszDest) return NULL;
    char dir[2048]={0}, file[2048]={0}, out[4096]={0};
    if (pszDir)  w_to_narrow(pszDir,  dir,  sizeof(dir));
    if (pszFile) w_to_narrow(pszFile, file, sizeof(file));
    if (!file[0])        { strncpy(out, dir,  sizeof(out)-1); }
    else if (!dir[0] || file[0]=='/' || file[0]=='\\' || (file[1]==':'))
                         { strncpy(out, file, sizeof(out)-1); }
    else {
        size_t dlen = strlen(dir);
        if (dlen > 0 && (dir[dlen-1] == '\\' || dir[dlen-1] == '/'))
            snprintf(out, sizeof(out), "%s%s", dir, file);
        else
            snprintf(out, sizeof(out), "%s\\%s", dir, file);
    }
    /* pszDest is contractually MAX_PATH wide chars; cap copy to that. */
    narrow_to_w(out, pszDest, MAX_PATH);
    return pszDest;
}

WINAPI_EXPORT BOOL PathRemoveFileSpecW(uint16_t *pszPath)
{
    if (!pszPath) return FALSE;
    size_t len = wcslen16(pszPath);
    for (size_t i = len; i > 0; i--) {
        if (pszPath[i-1] == '\\' || pszPath[i-1] == '/') {
            /* Keep the root separator for paths like "C:\" or "\" */
            if (i - 1 == 0 || (i - 1 == 2 && pszPath[1] == ':'))
                pszPath[i] = 0;
            else
                pszPath[i-1] = 0;
            return TRUE;
        }
    }
    pszPath[0] = 0;
    return FALSE;
}

WINAPI_EXPORT uint16_t *PathFindFileNameW(LPCWSTR pszPath)
{
    if (!pszPath) return (uint16_t*)pszPath;
    const uint16_t *last = pszPath;
    for (const uint16_t *p = pszPath; *p; p++)
        if (*p == '\\' || *p == '/') last = p + 1;
    return (uint16_t*)last;
}

WINAPI_EXPORT uint16_t *PathFindExtensionW(LPCWSTR pszPath)
{
    const uint16_t *fn = PathFindFileNameW(pszPath);
    const uint16_t *dot = NULL;
    for (const uint16_t *p = fn; *p; p++)
        if (*p == '.') dot = p;
    if (dot) return (uint16_t*)dot;
    /* Return pointer to the NUL */
    const uint16_t *end = pszPath;
    while (*end) end++;
    return (uint16_t*)end;
}

WINAPI_EXPORT void PathRemoveExtensionW(uint16_t *pszPath)
{
    uint16_t *ext = PathFindExtensionW(pszPath);
    if (ext && *ext == '.') *ext = 0;
}

WINAPI_EXPORT BOOL PathAppendW(uint16_t *pszPath, LPCWSTR pszMore)
{
    if (!pszPath || !pszMore) return FALSE;
    size_t len = wcslen16(pszPath);
    /* pszPath is contractually MAX_PATH wide chars; cap to leave room for NUL. */
    const uint16_t *src = pszMore;
    while (*src == '\\' || *src == '/') src++;
    /* Add separator if dir is non-empty and doesn't already end in one */
    int need_sep = (len > 0 && pszPath[len-1] != '\\' && pszPath[len-1] != '/');
    if (need_sep) {
        if (len >= MAX_PATH - 1) return FALSE;
        pszPath[len++] = '\\';
    }
    while (*src && len < MAX_PATH - 1) pszPath[len++] = *src++;
    if (*src) return FALSE; /* Truncated, signal failure per Win32 contract */
    pszPath[len] = 0;
    return TRUE;
}

WINAPI_EXPORT void PathStripPathW(uint16_t *pszPath)
{
    uint16_t *fn = PathFindFileNameW(pszPath);
    if (fn != pszPath) {
        uint16_t *dst = pszPath;
        while (*fn) *dst++ = *fn++;
        *dst = 0;
    }
}

WINAPI_EXPORT BOOL PathAddExtensionW(uint16_t *pszPath, LPCWSTR pszExt)
{
    if (!pszPath || !pszExt) return FALSE;
    uint16_t *ext = PathFindExtensionW(pszPath);
    if (!ext || !*ext) {
        /* No extension, append. pszPath contractually MAX_PATH wide chars. */
        size_t len = wcslen16(pszPath);
        size_t i = 0;
        for (; pszExt[i] && len < MAX_PATH - 1; i++)
            pszPath[len++] = pszExt[i];
        if (pszExt[i]) return FALSE; /* Truncated */
        pszPath[len] = 0;
        return TRUE;
    }
    return FALSE; /* Already has extension */
}

WINAPI_EXPORT BOOL PathCanonicalizeW(uint16_t *pszDest, LPCWSTR pszSrc)
{
    char src[4096]={0}, dst[4096]={0};
    w_to_narrow(pszSrc, src, sizeof(src));
    /* Simple canonicalization: resolve ./ and ../ */
    char *parts[256]; int np = 0;
    char tmp[4096]; strncpy(tmp, src, sizeof(tmp)-1);

    /* Handle prefix (drive letter or leading separator) */
    char prefix[4] = {0};
    char *start = tmp;
    int has_root_sep = 0;
    if (isalpha((unsigned char)tmp[0]) && tmp[1] == ':') {
        prefix[0] = tmp[0];
        prefix[1] = ':';
        start = tmp + 2;
        if (*start == '\\' || *start == '/') { has_root_sep = 1; start++; }
    } else if (tmp[0] == '\\' || tmp[0] == '/') {
        has_root_sep = 1;
        start = tmp + 1;
    }

    char *saveptr = NULL;
    char *tok = strtok_r(start, "/\\", &saveptr);
    while (tok && np < 255) {
        if (strcmp(tok, ".") == 0) {}
        else if (strcmp(tok, "..") == 0) { if (np > 0) np--; }
        else parts[np++] = tok;
        tok = strtok_r(NULL, "/\\", &saveptr);
    }
    int pos = 0;
    if (prefix[0]) {
        pos = snprintf(dst, sizeof(dst), "%s\\", prefix);
        if (pos < 0 || pos >= (int)sizeof(dst)) { dst[0] = '\0'; return FALSE; }
    } else if (has_root_sep) {
        pos = snprintf(dst, sizeof(dst), "\\");
        if (pos < 0 || pos >= (int)sizeof(dst)) { dst[0] = '\0'; return FALSE; }
    } else {
        dst[0] = '\0';
    }
    for (int i = 0; i < np; i++) {
        pos += snprintf(dst + pos, sizeof(dst) - pos, "%s%s",
                        (i > 0) ? "\\" : "", parts[i]);
        if (pos >= (int)sizeof(dst)) { dst[sizeof(dst) - 1] = '\0'; break; }
    }
    if (!dst[0]) strcpy(dst, ".");
    /* pszDest is contractually MAX_PATH wide chars; cap copy to that. */
    narrow_to_w(dst, pszDest, MAX_PATH);
    return TRUE;
}

WINAPI_EXPORT uint16_t *StrStrIW(LPCWSTR pszFirst, LPCWSTR pszSrch)
{
    if (!pszFirst || !pszSrch) return NULL;
    size_t slen = wcslen16(pszSrch);
    if (slen == 0) return (uint16_t*)pszFirst;
    for (size_t i = 0; pszFirst[i]; i++) {
        size_t j = 0;
        while (j < slen && pszFirst[i+j]) {
            uint16_t a = pszFirst[i+j], b = pszSrch[j];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) break;
            j++;
        }
        if (j == slen) return (uint16_t*)(pszFirst + i);
    }
    return NULL;
}

WINAPI_EXPORT int StrCmpIW(LPCWSTR psz1, LPCWSTR psz2)
{
    char a[4096]={0}, b[4096]={0};
    w_to_narrow(psz1, a, sizeof(a));
    w_to_narrow(psz2, b, sizeof(b));
    return strcasecmp(a, b);
}

WINAPI_EXPORT int StrCmpNIW(LPCWSTR psz1, LPCWSTR psz2, int nChar)
{
    char a[4096]={0}, b[4096]={0};
    w_to_narrow(psz1, a, sizeof(a));
    w_to_narrow(psz2, b, sizeof(b));
    return strncasecmp(a, b, (size_t)nChar);
}

WINAPI_EXPORT int wnsprintfW(uint16_t *pszDest, int cchDest, LPCWSTR pszFmt, ...)
{
    /* Narrow-convert format, use ms_abi_vformat, convert back */
    char fmt[2048]={0}; w_to_narrow(pszFmt, fmt, sizeof(fmt));
    char out[4096]={0};
    __builtin_ms_va_list ap; __builtin_ms_va_start(ap, pszFmt);
    ms_abi_vformat(NULL, out, sizeof(out), fmt, ap);
    __builtin_ms_va_end(ap);
    narrow_to_w(out, pszDest, (size_t)cchDest);
    return (int)wcslen16(pszDest);
}

WINAPI_EXPORT int wvnsprintfW(uint16_t *pszDest, int cchDest, LPCWSTR pszFmt, __builtin_ms_va_list arglist)
{
    char fmt[2048]={0}; w_to_narrow(pszFmt, fmt, sizeof(fmt));
    char out[4096]={0};
    ms_abi_vformat(NULL, out, sizeof(out), fmt, arglist);
    narrow_to_w(out, pszDest, (size_t)cchDest);
    return (int)wcslen16(pszDest);
}

/*
 * Helper: case-insensitive prefix match for uint16_t URL scheme strings.
 * Returns TRUE if pszPath starts with the given scheme prefix.
 */
static BOOL url_prefix_match(LPCWSTR pszPath, const uint16_t *prefix)
{
    int i;
    for (i = 0; prefix[i]; i++) {
        if (!pszPath[i]) return FALSE;
        uint16_t c = pszPath[i];
        if (c >= 'A' && c <= 'Z')
            c += 'a' - 'A';
        if (c != prefix[i])
            return FALSE;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL PathIsURLW(LPCWSTR pszPath)
{
    SHLW_TRACE("[shlwapi] PathIsURLW(...)\n");

    if (!pszPath)
        return FALSE;

    /* Check known URL schemes (case-insensitive, UTF-16LE) */
    static const uint16_t http[]  = {'h','t','t','p',':','/','/','\0'};
    static const uint16_t https[] = {'h','t','t','p','s',':','/','/','\0'};
    static const uint16_t ftp[]   = {'f','t','p',':','/','/','\0'};
    static const uint16_t file[]  = {'f','i','l','e',':','/','/','\0'};

    if (url_prefix_match(pszPath, https)) return TRUE;
    if (url_prefix_match(pszPath, http))  return TRUE;
    if (url_prefix_match(pszPath, ftp))   return TRUE;
    if (url_prefix_match(pszPath, file))  return TRUE;

    return FALSE;
}

/* ------------------------------------------------------------------ */
/*  HRESULT codes (not defined in our win32 headers yet)               */
/* ------------------------------------------------------------------ */
#ifndef S_OK
#define S_OK           ((HRESULT)0)
#endif
#ifndef E_POINTER
#define E_POINTER      ((HRESULT)0x80004003L)
#endif
#ifndef E_INVALIDARG
#define E_INVALIDARG   ((HRESULT)0x80070057L)
#endif

/* StrToIntEx flags (shlwapi.h) */
#ifndef STIF_DEFAULT
#define STIF_DEFAULT        0x00000000L
#endif
#ifndef STIF_SUPPORT_HEX
#define STIF_SUPPORT_HEX    0x00000001L
#endif

/* ------------------------------------------------------------------ */
/*  PathMatchSpec — Windows-style wildcard matching                    */
/* ------------------------------------------------------------------ */

/*
 * Case-insensitive ASCII lower.  Wildcards are ASCII, so this is fine
 * for the match itself; comparison of non-ASCII bytes falls through
 * as byte-exact which matches the Win32 semantics for non-locale match.
 */
static inline int lc_ascii(int c)
{
    if (c >= 'A' && c <= 'Z') return c + ('a' - 'A');
    return c;
}

/*
 * Recursive glob matcher for a single spec.  '*' matches any run of
 * characters (including none).  '?' matches exactly one character.
 * All other characters match themselves, case-insensitively.
 *
 * Returns 1 on match, 0 otherwise.  Both buffers are NUL-terminated.
 */
static int glob_match_a(const char *path, const char *spec)
{
    while (*spec) {
        if (*spec == '*') {
            /* Collapse runs of '*' */
            while (*spec == '*') spec++;
            if (!*spec) return 1; /* trailing * matches anything */
            /* Try to match the rest at every remaining position */
            while (*path) {
                if (glob_match_a(path, spec)) return 1;
                path++;
            }
            /* Also test the empty tail */
            return glob_match_a(path, spec);
        } else if (*spec == '?') {
            if (!*path) return 0;
            path++;
            spec++;
        } else {
            if (!*path) return 0;
            if (lc_ascii((unsigned char)*path) != lc_ascii((unsigned char)*spec))
                return 0;
            path++;
            spec++;
        }
    }
    return *path == '\0';
}

WINAPI_EXPORT BOOL PathMatchSpecA(LPCSTR path, LPCSTR spec)
{
    SHLW_TRACE("[shlwapi] PathMatchSpecA(\"%s\", \"%s\")\n",
            path ? path : "(null)", spec ? spec : "(null)");

    if (!path || !spec) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Multiple specs can be separated by ';'; match on any */
    char buf[1024];
    size_t sl = strlen(spec);
    if (sl >= sizeof(buf)) sl = sizeof(buf) - 1;
    memcpy(buf, spec, sl);
    buf[sl] = '\0';

    char *saveptr = NULL;
    for (char *tok = strtok_r(buf, ";", &saveptr); tok;
         tok = strtok_r(NULL, ";", &saveptr)) {
        /* Skip leading spaces */
        while (*tok == ' ') tok++;
        if (!*tok) continue;
        if (glob_match_a(path, tok)) return TRUE;
    }
    return FALSE;
}

WINAPI_EXPORT BOOL PathMatchSpecW(LPCWSTR path, LPCWSTR spec)
{
    SHLW_TRACE("[shlwapi] PathMatchSpecW(...)\n");

    if (!path || !spec) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    char p[4096], s[1024];
    w_to_narrow(path, p, sizeof(p));
    w_to_narrow(spec, s, sizeof(s));
    return PathMatchSpecA(p, s);
}

WINAPI_EXPORT BOOL PathMatchSpecExA(LPCSTR path, LPCSTR spec, DWORD flags)
{
    (void)flags;
    return PathMatchSpecA(path, spec);
}

WINAPI_EXPORT BOOL PathMatchSpecExW(LPCWSTR path, LPCWSTR spec, DWORD flags)
{
    (void)flags;
    return PathMatchSpecW(path, spec);
}

/* ------------------------------------------------------------------ */
/*  PathSkipRoot / PathGetDriveNumber                                  */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT LPSTR PathSkipRootA(LPCSTR path)
{
    SHLW_TRACE("[shlwapi] PathSkipRootA(\"%s\")\n",
            path ? path : "(null)");

    if (!path) return NULL;

    /* UNC path: \\server\share\... -> pointer past the share separator */
    if ((path[0] == '\\' && path[1] == '\\') ||
        (path[0] == '/'  && path[1] == '/')) {
        const char *p = path + 2;
        /* Server name must be non-empty */
        if (!*p || *p == '\\' || *p == '/') return NULL;
        /* Skip server */
        while (*p && *p != '\\' && *p != '/') p++;
        if (!*p) return NULL; /* just \\server, no share */
        p++; /* past server-sep */
        /* Share name must be non-empty */
        if (!*p || *p == '\\' || *p == '/') return NULL;
        /* Skip share */
        while (*p && *p != '\\' && *p != '/') p++;
        if (!*p) return (LPSTR)p; /* \\server\share with no trailing sep */
        return (LPSTR)(p + 1);
    }

    /* Drive letter: X:\ or X:/  */
    if (isalpha((unsigned char)path[0]) && path[1] == ':' &&
        (path[2] == '\\' || path[2] == '/')) {
        return (LPSTR)(path + 3);
    }

    /* Root-only absolute: \  or /  */
    if (path[0] == '\\' || path[0] == '/')
        return (LPSTR)(path + 1);

    return NULL;
}

WINAPI_EXPORT LPWSTR PathSkipRootW(LPCWSTR path)
{
    SHLW_TRACE("[shlwapi] PathSkipRootW(...)\n");

    if (!path) return NULL;

    if ((path[0] == '\\' && path[1] == '\\') ||
        (path[0] == '/'  && path[1] == '/')) {
        const uint16_t *p = path + 2;
        /* Server name must be non-empty */
        if (!*p || *p == '\\' || *p == '/') return NULL;
        while (*p && *p != '\\' && *p != '/') p++;
        if (!*p) return NULL;
        p++;
        /* Share name must be non-empty */
        if (!*p || *p == '\\' || *p == '/') return NULL;
        while (*p && *p != '\\' && *p != '/') p++;
        if (!*p) return (LPWSTR)p;
        return (LPWSTR)(p + 1);
    }

    if (((path[0] >= 'A' && path[0] <= 'Z') ||
         (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' &&
        (path[2] == '\\' || path[2] == '/')) {
        return (LPWSTR)(path + 3);
    }

    if (path[0] == '\\' || path[0] == '/')
        return (LPWSTR)(path + 1);

    return NULL;
}

WINAPI_EXPORT int PathGetDriveNumberA(LPCSTR path)
{
    SHLW_TRACE("[shlwapi] PathGetDriveNumberA(\"%s\")\n",
            path ? path : "(null)");

    if (!path) return -1;
    if (!isalpha((unsigned char)path[0]) || path[1] != ':')
        return -1;
    int c = path[0];
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= 'A' && c <= 'Z') return c - 'A';
    return -1;
}

WINAPI_EXPORT int PathGetDriveNumberW(LPCWSTR path)
{
    SHLW_TRACE("[shlwapi] PathGetDriveNumberW(...)\n");

    if (!path) return -1;
    uint16_t c = path[0];
    /* Empty string: path[1] would be OOB; bail out on empty. */
    if (c == 0) return -1;
    if (path[1] != ':') return -1;
    if (c >= 'a' && c <= 'z') return (int)(c - 'a');
    if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
    return -1;
}

/* ------------------------------------------------------------------ */
/*  StrFormatByteSize — pretty-print a byte count                      */
/* ------------------------------------------------------------------ */

/*
 * Windows' StrFormatByteSize uses base-1024 units and switches based on
 * magnitude.  Our implementation picks the largest unit under which
 * the value is >= 1.0 and prints up to 2 decimal places (3 sig figs
 * total).  Below 1 KB we print raw bytes with no decimals.
 */
static int format_byte_size(LONGLONG bytes, char *buf, size_t buflen)
{
    if (!buf || buflen == 0) return -1;

    /* Negative values: render as-is with minus sign.  Windows treats
     * negative LONGLONG here as a signed quantity. Guard against
     * LLONG_MIN where -v would overflow (UB for signed). */
    int neg = 0;
    LONGLONG v = bytes;
    if (v < 0) {
        neg = 1;
        /* (uint64_t)v then negate as unsigned is well-defined. */
        v = (LONGLONG)(~(uint64_t)v + 1ULL);
        /* If v is still negative after negation (LLONG_MIN case), its
         * absolute value doesn't fit in a signed 64-bit. Clamp to max. */
        if (v < 0) v = 0x7FFFFFFFFFFFFFFFLL;
    }

    static const char *units[] = { "bytes", "KB", "MB", "GB", "TB", "PB", "EB" };
    int u = 0;
    double d = (double)v;

    /* < 1 KB: integer bytes */
    if (v < 1024) {
        return snprintf(buf, buflen, "%s%lld %s",
                        neg ? "-" : "",
                        (long long)v, units[0]);
    }

    d = (double)v / 1024.0;
    u = 1;
    while (d >= 1024.0 && u < (int)(sizeof(units)/sizeof(units[0])) - 1) {
        d /= 1024.0;
        u++;
    }

    /* Choose decimal places based on magnitude for ~3 sig figs:
     * 100-999.99 -> 0 dp, 10-99.99 -> 1 dp, <10 -> 2 dp  */
    const char *fmt;
    if (d >= 100.0)      fmt = "%s%.0f %s";
    else if (d >= 10.0)  fmt = "%s%.1f %s";
    else                 fmt = "%s%.2f %s";

    return snprintf(buf, buflen, fmt, neg ? "-" : "", d, units[u]);
}

WINAPI_EXPORT HRESULT StrFormatByteSize64A(LONGLONG bytes, LPSTR buf, UINT buflen)
{
    SHLW_TRACE("[shlwapi] StrFormatByteSize64A(%lld, %u)\n",
            (long long)bytes, (unsigned)buflen);

    if (!buf || buflen == 0) return E_INVALIDARG;

    int n = format_byte_size(bytes, buf, buflen);
    if (n < 0 || (UINT)n >= buflen) {
        if (buflen > 0) buf[buflen - 1] = '\0';
        return E_POINTER;
    }
    return S_OK;
}

WINAPI_EXPORT LPSTR StrFormatByteSizeA(DWORD bytes, LPSTR buf, UINT buflen)
{
    SHLW_TRACE("[shlwapi] StrFormatByteSizeA(%u, %u)\n",
            (unsigned)bytes, (unsigned)buflen);

    if (!buf || buflen == 0) return NULL;
    (void)StrFormatByteSize64A((LONGLONG)bytes, buf, buflen);
    return buf;
}

WINAPI_EXPORT LPWSTR StrFormatByteSizeW(LONGLONG bytes, LPWSTR buf, UINT buflen)
{
    SHLW_TRACE("[shlwapi] StrFormatByteSizeW(%lld, %u)\n",
            (long long)bytes, (unsigned)buflen);

    if (!buf || buflen == 0) return NULL;

    char narrow[64];
    if (format_byte_size(bytes, narrow, sizeof(narrow)) < 0) {
        buf[0] = 0;
        return NULL;
    }
    narrow_to_w(narrow, buf, (size_t)buflen);
    return buf;
}

/* ------------------------------------------------------------------ */
/*  StrDup                                                             */
/* ------------------------------------------------------------------ */

/*
 * Note: Windows' StrDupA allocates via LocalAlloc and the caller must
 * LocalFree().  Our LocalAlloc is a pass-through to malloc (see
 * kernel32 stubs) and LocalFree maps to free, so malloc() here matches
 * the round-trip.  If an app expects HeapFree on the process heap this
 * could leak, but the expected pairing (StrDup+LocalFree) works.
 */
WINAPI_EXPORT LPSTR StrDupA(LPCSTR src)
{
    SHLW_TRACE("[shlwapi] StrDupA(\"%s\")\n",
            src ? src : "(null)");

    if (!src) {
        /* Windows allocates an empty string in this case */
        char *empty = (char *)malloc(1);
        if (!empty) return NULL;
        empty[0] = '\0';
        return empty;
    }
    size_t len = strlen(src);
    char *out = (char *)malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, src, len + 1);
    return out;
}

WINAPI_EXPORT LPWSTR StrDupW(LPCWSTR src)
{
    SHLW_TRACE("[shlwapi] StrDupW(...)\n");

    if (!src) {
        uint16_t *empty = (uint16_t *)malloc(sizeof(uint16_t));
        if (!empty) return NULL;
        empty[0] = 0;
        return empty;
    }
    size_t len = wcslen16(src);
    uint16_t *out = (uint16_t *)malloc((len + 1) * sizeof(uint16_t));
    if (!out) return NULL;
    memcpy(out, src, (len + 1) * sizeof(uint16_t));
    return out;
}

/* ------------------------------------------------------------------ */
/*  StrToIntEx / StrToInt64Ex — decimal / 0xHEX parsing                */
/* ------------------------------------------------------------------ */

/*
 * Parse a string into a signed 64-bit integer.
 * Decimal by default; if STIF_SUPPORT_HEX is set, a "0x" prefix
 * triggers hex parsing.  A single leading sign ('+' / '-') is
 * honored for decimal only.  Returns 1 on success, 0 on failure.
 */
static int parse_int64_ex(const char *s, DWORD flags, LONGLONG *out)
{
    if (!s || !out) return 0;
    while (*s == ' ' || *s == '\t') s++;
    int neg = 0;
    if (*s == '+') s++;
    else if (*s == '-') { neg = 1; s++; }

    /* Use unsigned accumulator: wrap is defined and negation is safe. */
    uint64_t uval = 0;
    int digits = 0;

    if ((flags & STIF_SUPPORT_HEX) && s[0] == '0' &&
        (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
        while (*s) {
            int c = (unsigned char)*s;
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else break;
            /* Cap at UINT64_MAX to avoid undefined wrap on extreme input. */
            if (uval > (0xFFFFFFFFFFFFFFFFull >> 4)) uval = 0xFFFFFFFFFFFFFFFFull;
            else uval = (uval << 4) | (uint64_t)d;
            digits++;
            s++;
        }
    } else {
        while (*s >= '0' && *s <= '9') {
            uint64_t d = (uint64_t)(*s - '0');
            /* Saturate at UINT64_MAX instead of wrapping. */
            if (uval > (0xFFFFFFFFFFFFFFFFull - d) / 10ull) {
                uval = 0xFFFFFFFFFFFFFFFFull;
            } else {
                uval = uval * 10ull + d;
            }
            digits++;
            s++;
        }
    }

    if (digits == 0) return 0;
    /* Apply sign via unsigned two's complement negate, then bit-copy back
     * to signed.  This correctly handles -9223372036854775808 (LLONG_MIN)
     * without invoking UB on signed negation. */
    if (neg) uval = (uint64_t)0 - uval;
    *out = (LONGLONG)uval;
    return 1;
}

WINAPI_EXPORT BOOL StrToIntExA(LPCSTR str, DWORD flags, int *out)
{
    SHLW_TRACE("[shlwapi] StrToIntExA(\"%s\", 0x%x)\n",
            str ? str : "(null)", (unsigned)flags);

    if (!str || !out) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    LONGLONG v = 0;
    if (!parse_int64_ex(str, flags, &v)) return FALSE;
    *out = (int)v;
    return TRUE;
}

WINAPI_EXPORT BOOL StrToIntExW(LPCWSTR str, DWORD flags, int *out)
{
    SHLW_TRACE("[shlwapi] StrToIntExW(0x%x)\n", (unsigned)flags);

    if (!str || !out) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    char narrow[256];
    w_to_narrow(str, narrow, sizeof(narrow));
    return StrToIntExA(narrow, flags, out);
}

WINAPI_EXPORT BOOL StrToInt64ExA(LPCSTR str, DWORD flags, LONGLONG *out)
{
    SHLW_TRACE("[shlwapi] StrToInt64ExA(\"%s\", 0x%x)\n",
            str ? str : "(null)", (unsigned)flags);

    if (!str || !out) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return parse_int64_ex(str, flags, out) ? TRUE : FALSE;
}

WINAPI_EXPORT BOOL StrToInt64ExW(LPCWSTR str, DWORD flags, LONGLONG *out)
{
    SHLW_TRACE("[shlwapi] StrToInt64ExW(0x%x)\n", (unsigned)flags);

    if (!str || !out) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    char narrow[256];
    w_to_narrow(str, narrow, sizeof(narrow));
    return StrToInt64ExA(narrow, flags, out);
}

/* ------------------------------------------------------------------ */
/*  UrlEscape / UrlUnescape                                            */
/* ------------------------------------------------------------------ */

/*
 * RFC 3986 "unreserved": ALPHA / DIGIT / "-" / "." / "_" / "~"
 * Windows' default UrlEscape additionally preserves reserved
 * characters that are structurally meaningful in URLs ( ":" "/" "?"
 * "#" "[" "]" "@" "!" "$" "&" "'" "(" ")" "*" "+" "," ";" "=" ) when
 * the URL_ESCAPE_PERCENT flag is NOT set.  For simplicity we keep
 * colon, slash, question mark and hash by default.
 */
static int is_unreserved(int c)
{
    if ((c >= 'A' && c <= 'Z') ||
        (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9'))
        return 1;
    switch (c) {
        case '-': case '.': case '_': case '~':
            return 1;
    }
    return 0;
}

static int is_url_structural(int c)
{
    switch (c) {
        case ':': case '/': case '?': case '#':
        case '[': case ']': case '@':
            return 1;
    }
    return 0;
}

WINAPI_EXPORT HRESULT UrlEscapeA(LPCSTR url, LPSTR esc, LPDWORD esc_len, DWORD flags)
{
    SHLW_TRACE("[shlwapi] UrlEscapeA(\"%s\", 0x%x)\n",
            url ? url : "(null)", (unsigned)flags);

    (void)flags;
    if (!url || !esc || !esc_len) return E_POINTER;

    DWORD cap = *esc_len;
    DWORD need = 0;
    static const char hex[] = "0123456789ABCDEF";

    for (const unsigned char *p = (const unsigned char *)url; *p; p++) {
        int c = *p;
        if (is_unreserved(c) || is_url_structural(c)) {
            if (need + 1 < cap) esc[need] = (char)c;
            need++;
        } else {
            if (need + 3 < cap) {
                esc[need]     = '%';
                esc[need + 1] = hex[(c >> 4) & 0xF];
                esc[need + 2] = hex[c & 0xF];
            }
            need += 3;
        }
    }

    if (need + 1 > cap) {
        *esc_len = need + 1;
        if (cap > 0) esc[cap - 1] = '\0';
        return E_POINTER;
    }
    esc[need] = '\0';
    *esc_len = need;
    return S_OK;
}

WINAPI_EXPORT HRESULT UrlEscapeW(LPCWSTR url, LPWSTR esc, LPDWORD esc_len, DWORD flags)
{
    SHLW_TRACE("[shlwapi] UrlEscapeW(0x%x)\n", (unsigned)flags);

    if (!url || !esc || !esc_len) return E_POINTER;

    /* Narrow, escape, widen.  Buffer is bounded for typical URL usage. */
    char in[4096], out[4096 * 3 + 1];
    w_to_narrow(url, in, sizeof(in));

    DWORD nlen = (DWORD)sizeof(out);
    HRESULT hr = UrlEscapeA(in, out, &nlen, flags);
    if (hr != S_OK) {
        /* Out-of-buffer or similar: still report required size */
        *esc_len = nlen;
        return hr;
    }

    DWORD cap = *esc_len;
    DWORD need = nlen; /* without NUL */
    if (need + 1 > cap) {
        *esc_len = need + 1;
        if (cap > 0) esc[cap - 1] = 0;
        return E_POINTER;
    }
    narrow_to_w(out, esc, (size_t)cap);
    *esc_len = need;
    return S_OK;
}

static inline int hex_val(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

WINAPI_EXPORT HRESULT UrlUnescapeA(LPSTR url, LPSTR unesc, LPDWORD unesc_len, DWORD flags)
{
    SHLW_TRACE("[shlwapi] UrlUnescapeA(\"%s\", 0x%x)\n",
            url ? url : "(null)", (unsigned)flags);

    (void)flags;
    if (!url) return E_POINTER;

    /*
     * If unesc is NULL, operate in-place on url.  Otherwise write to
     * unesc up to *unesc_len and report required size on overflow.
     */
    int in_place = (unesc == NULL);
    if (!in_place && !unesc_len) return E_POINTER;

    char *src = url;
    char *dst = in_place ? url : unesc;
    DWORD cap = in_place ? 0xFFFFFFFFu : *unesc_len;
    DWORD wrote = 0;

    while (*src) {
        int c;
        if (src[0] == '%' && src[1] && src[2]) {
            int h = hex_val((unsigned char)src[1]);
            int l = hex_val((unsigned char)src[2]);
            if (h >= 0 && l >= 0) {
                c = (h << 4) | l;
                src += 3;
            } else {
                c = *src++;
            }
        } else {
            c = *src++;
        }
        if (wrote + 1 < cap) dst[wrote] = (char)c;
        wrote++;
    }

    if (!in_place) {
        if (wrote + 1 > cap) {
            *unesc_len = wrote + 1;
            if (cap > 0) dst[cap - 1] = '\0';
            return E_POINTER;
        }
        dst[wrote] = '\0';
        *unesc_len = wrote;
    } else {
        dst[wrote] = '\0';
        if (unesc_len) *unesc_len = wrote;
    }
    return S_OK;
}

WINAPI_EXPORT HRESULT UrlUnescapeW(LPWSTR url, LPWSTR unesc, LPDWORD unesc_len, DWORD flags)
{
    SHLW_TRACE("[shlwapi] UrlUnescapeW(0x%x)\n", (unsigned)flags);

    if (!url) return E_POINTER;

    char narrow_in[4096], narrow_out[4096];
    w_to_narrow(url, narrow_in, sizeof(narrow_in));

    if (unesc == NULL) {
        /* In-place on the wide buffer: decode narrow then widen back. */
        DWORD n = (DWORD)sizeof(narrow_out);
        HRESULT hr = UrlUnescapeA(narrow_in, narrow_out, &n, flags);
        if (hr != S_OK) {
            if (unesc_len) *unesc_len = n;
            return hr;
        }
        /* Widen back into url (we own it). */
        size_t orig = wcslen16(url);
        narrow_to_w(narrow_out, url, orig + 1);
        if (unesc_len) *unesc_len = n;
        return S_OK;
    }

    if (!unesc_len) return E_POINTER;

    DWORD narrow_cap = (DWORD)sizeof(narrow_out);
    HRESULT hr = UrlUnescapeA(narrow_in, narrow_out, &narrow_cap, flags);
    if (hr != S_OK) {
        *unesc_len = narrow_cap;
        return hr;
    }

    DWORD cap = *unesc_len;
    DWORD need = narrow_cap;
    if (need + 1 > cap) {
        *unesc_len = need + 1;
        if (cap > 0) unesc[cap - 1] = 0;
        return E_POINTER;
    }
    narrow_to_w(narrow_out, unesc, (size_t)cap);
    *unesc_len = need;
    return S_OK;
}

/* ------------------------------------------------------------------ */
/*  HashData — shlwapi's simple buffer hash (FNV-1a here)              */
/* ------------------------------------------------------------------ */

/*
 * Windows' HashData is documented as an "intentionally weak" hash; we
 * implement it as FNV-1a over the input, then tile the output by
 * re-hashing the running state to fill hash[0..hlen-1].  This gives a
 * deterministic result for a given input/length regardless of hash
 * buffer size, which matches how callers use it as a salted marker.
 */
WINAPI_EXPORT DWORD HashData(const BYTE *data, DWORD dlen, BYTE *hash, DWORD hlen)
{
    SHLW_TRACE("[shlwapi] HashData(dlen=%u, hlen=%u)\n",
            (unsigned)dlen, (unsigned)hlen);

    /* data may be NULL iff dlen==0; hash may be NULL iff hlen==0. */
    if ((!data && dlen > 0) || (!hash && hlen > 0)) {
        set_last_error(ERROR_INVALID_PARAMETER);
        /* Per MS docs this returns non-zero on failure */
        return 0x80070057u; /* E_INVALIDARG */
    }
    if (hlen == 0) return ERROR_SUCCESS;

    uint32_t h = 0x811c9dc5u; /* FNV-1a offset basis */
    for (DWORD i = 0; i < dlen; i++) {
        h ^= (uint32_t)data[i];
        h *= 0x01000193u; /* FNV prime */
    }

    /* Tile the 32-bit hash into the output buffer, re-mixing after each
     * 4-byte window so the bytes aren't just a literal repeat. */
    for (DWORD i = 0; i < hlen; i++) {
        BYTE b = (BYTE)((h >> ((i & 3) * 8)) & 0xFF);
        hash[i] = b;
        if ((i & 3) == 3) {
            /* Re-mix the state before the next 4 bytes */
            h ^= (uint32_t)i;
            h *= 0x01000193u;
            h = (h << 13) | (h >> 19);
        }
    }

    return ERROR_SUCCESS;
}
