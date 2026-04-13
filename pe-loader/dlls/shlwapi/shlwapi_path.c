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

/* ------------------------------------------------------------------ */
/*  Path existence / type                                              */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT BOOL PathFileExistsA(LPCSTR pszPath)
{
    fprintf(stderr, "[shlwapi] PathFileExistsA(\"%s\")\n",
            pszPath ? pszPath : "(null)");

    if (!pszPath)
        return FALSE;

    char linux_path[4096];
    win_path_to_linux(pszPath, linux_path, sizeof(linux_path));

    return (access(linux_path, F_OK) == 0) ? TRUE : FALSE;
}

WINAPI_EXPORT BOOL PathFileExistsW(LPCWSTR pszPath)
{
    fprintf(stderr, "[shlwapi] PathFileExistsW(...)\n");

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
    fprintf(stderr, "[shlwapi] PathIsDirectoryA(\"%s\")\n",
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
    fprintf(stderr, "[shlwapi] PathIsRelativeA(\"%s\")\n",
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
    fprintf(stderr, "[shlwapi] PathCombineA(\"%s\", \"%s\")\n",
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
    fprintf(stderr, "[shlwapi] PathRemoveFileSpecA(\"%s\")\n",
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
    fprintf(stderr, "[shlwapi] PathFindFileNameA(\"%s\")\n",
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
    fprintf(stderr, "[shlwapi] PathFindExtensionA(\"%s\")\n",
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
    fprintf(stderr, "[shlwapi] PathAddExtensionA(\"%s\", \"%s\")\n",
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
    fprintf(stderr, "[shlwapi] PathRemoveExtensionA(\"%s\")\n",
            pszPath ? pszPath : "(null)");

    if (!pszPath)
        return;

    LPSTR ext = PathFindExtensionA(pszPath);
    if (ext && *ext == '.')
        *ext = '\0';
}

WINAPI_EXPORT BOOL PathAppendA(LPSTR pszPath, LPCSTR pszMore)
{
    fprintf(stderr, "[shlwapi] PathAppendA(\"%s\", \"%s\")\n",
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
    fprintf(stderr, "[shlwapi] PathStripPathA(\"%s\")\n",
            pszPath ? pszPath : "(null)");

    if (!pszPath)
        return;

    LPSTR filename = PathFindFileNameA(pszPath);
    if (filename != pszPath)
        memmove(pszPath, filename, strlen(filename) + 1);
}

WINAPI_EXPORT BOOL PathCanonicalizeA(LPSTR pszDest, LPCSTR pszSrc)
{
    fprintf(stderr, "[shlwapi] PathCanonicalizeA(\"%s\")\n",
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
    fprintf(stderr, "[shlwapi] StrStrIA(\"%s\", \"%s\")\n",
            pszFirst ? pszFirst : "(null)",
            pszSrch ? pszSrch : "(null)");

    if (!pszFirst || !pszSrch)
        return NULL;

    return (LPSTR)strcasestr(pszFirst, pszSrch);
}

WINAPI_EXPORT int StrCmpIA(LPCSTR psz1, LPCSTR psz2)
{
    fprintf(stderr, "[shlwapi] StrCmpIA(\"%s\", \"%s\")\n",
            psz1 ? psz1 : "(null)",
            psz2 ? psz2 : "(null)");

    if (!psz1 && !psz2) return 0;
    if (!psz1) return -1;
    if (!psz2) return 1;

    return strcasecmp(psz1, psz2);
}

WINAPI_EXPORT int StrCmpNIA(LPCSTR psz1, LPCSTR psz2, int nChar)
{
    fprintf(stderr, "[shlwapi] StrCmpNIA(\"%s\", \"%s\", %d)\n",
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
    fprintf(stderr, "[shlwapi] wvnsprintfA(...)\n");

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

    fprintf(stderr, "[shlwapi] SHDeleteKeyA(\"%s\")\n",
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
    narrow_to_w(out, pszDest, 4096);
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
    if (len > 0 && pszPath[len-1] != '\\' && pszPath[len-1] != '/')
        pszPath[len++] = '\\';
    const uint16_t *src = pszMore;
    while (*src == '\\' || *src == '/') src++;
    while (*src && len < 4095) pszPath[len++] = *src++;
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
        /* No extension, append */
        size_t len = wcslen16(pszPath);
        for (size_t i = 0; pszExt[i] && len < 4094; i++)
            pszPath[len++] = pszExt[i];
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
    narrow_to_w(dst, pszDest, 4096);
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
    fprintf(stderr, "[shlwapi] PathIsURLW(...)\n");

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
