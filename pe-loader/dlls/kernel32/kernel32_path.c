/*
 * kernel32_path.c - Path and module filename functions
 *
 * GetModuleFileNameA/W, GetTempPathA, GetCurrentDirectoryA/W,
 * SetCurrentDirectoryA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <limits.h>

#include "common/dll_common.h"
#include "compat/env_setup.h"

/*
 * Convert a Linux path to a Windows-style path with backslashes.
 * /home/user/Games/foo.exe -> C:\home\user\Games\foo.exe
 * Relative paths are returned as-is with backslashes.
 */
static void linux_path_to_win(const char *linux_path, char *win_path, size_t size)
{
    if (!linux_path || !win_path || size == 0) return;

    /* Prepend C: for absolute paths */
    if (linux_path[0] == '/') {
        snprintf(win_path, size, "C:%s", linux_path);
    } else {
        snprintf(win_path, size, "%s", linux_path);
    }

    /* Convert forward slashes to backslashes */
    for (char *p = win_path; *p; p++) {
        if (*p == '/') *p = '\\';
    }
}

/*
 * Look up a module's full path from the PEB LDR list by base address.
 * Returns a narrow string path or NULL.
 */
static const char *ldr_find_path_by_base(void *base)
{
    /* Walk LDR InLoadOrder list via env_find_module_by_base */
    void *entry = env_find_module_by_base(base);
    if (!entry) return NULL;

    /*
     * entry is a LDR_DATA_TABLE_ENTRY*.
     * FullDllName (UNICODE_STRING) is at offset 0x48.
     * UNICODE_STRING: { USHORT Length, USHORT MaxLen, pad, WCHAR *Buffer }
     */
    typedef struct { uint16_t Length; uint16_t MaxLen; uint32_t _pad; uint16_t *Buffer; } USTR;
    USTR *full_name = (USTR *)((char *)entry + 0x48);
    if (!full_name->Buffer || full_name->Length == 0)
        return NULL;

    /* Convert wide to narrow (static buffer) */
    static char narrow_buf[PATH_MAX];
    int wlen = full_name->Length / 2;
    if (wlen >= PATH_MAX) wlen = PATH_MAX - 1;
    for (int i = 0; i < wlen; i++)
        narrow_buf[i] = (char)(full_name->Buffer[i] & 0xFF);
    narrow_buf[wlen] = '\0';
    return narrow_buf;
}

WINAPI_EXPORT DWORD GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)
{
    if (!lpFilename || nSize == 0) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    char win_path[PATH_MAX];
    const char *path = NULL;

    /* NULL or fallback sentinel (main exe) → get exe path from PEB */
    if (hModule == NULL || (uintptr_t)hModule == 0x00400000) {
        /* Try PEB -> ProcessParameters -> ImagePathName first */
        void *peb = env_get_peb();
        if (peb) {
            /* ProcessParameters at PEB + 0x20 */
            void *params = *(void **)((char *)peb + 0x20);
            if (params) {
                /* ImagePathName (UNICODE_STRING) at offset 0x60 in RTL_USER_PROCESS_PARAMETERS */
                typedef struct { uint16_t Length; uint16_t MaxLen; uint32_t _pad; uint16_t *Buffer; } USTR;
                USTR *img = (USTR *)((char *)params + 0x60);
                if (img->Buffer && img->Length > 0) {
                    int wlen = img->Length / 2;
                    char linux_path[PATH_MAX];
                    if (wlen >= PATH_MAX) wlen = PATH_MAX - 1;
                    for (int i = 0; i < wlen; i++)
                        linux_path[i] = (char)(img->Buffer[i] & 0xFF);
                    linux_path[wlen] = '\0';
                    linux_path_to_win(linux_path, win_path, sizeof(win_path));
                    path = win_path;
                }
            }
        }

        /* Fallback: try LDR entry for main exe (first entry, DllBase == PEB->ImageBaseAddress) */
        if (!path && peb) {
            void *image_base = *(void **)((char *)peb + 0x10);
            if (image_base) {
                const char *ldr_path = ldr_find_path_by_base(image_base);
                if (ldr_path) {
                    linux_path_to_win(ldr_path, win_path, sizeof(win_path));
                    path = win_path;
                }
            }
        }

        /* Last resort: unknown */
        if (!path)
            path = "C:\\unknown.exe";
    } else {
        /* DLL module — look up in LDR list by base address */
        const char *ldr_path = ldr_find_path_by_base((void *)hModule);
        if (ldr_path) {
            linux_path_to_win(ldr_path, win_path, sizeof(win_path));
            path = win_path;
        }

        /* Fallback: check kernel32 module table for .so stub name */
        if (!path) {
            extern int kernel32_find_module_name(void *handle, char *buf, size_t bufsz);
            if (kernel32_find_module_name((void *)hModule, win_path, sizeof(win_path)) == 0)
                path = win_path;
        }

        if (!path)
            path = "C:\\Windows\\System32\\unknown.dll";
    }

    size_t len = strlen(path);
    if (len >= nSize) {
        memcpy(lpFilename, path, nSize - 1);
        lpFilename[nSize - 1] = '\0';
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return nSize;
    }

    strcpy(lpFilename, path);
    set_last_error(0);
    return (DWORD)len;
}

WINAPI_EXPORT DWORD GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
{
    if (!lpFilename || nSize == 0) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    char narrow[PATH_MAX];
    DWORD ret = GetModuleFileNameA(hModule, narrow, sizeof(narrow));
    if (ret == 0) return 0;

    size_t narrow_len = strlen(narrow);

    /* Convert to UTF-16LE with truncation handling */
    if (narrow_len >= nSize) {
        DWORD i;
        for (i = 0; i < nSize - 1; i++)
            lpFilename[i] = (WCHAR)(unsigned char)narrow[i];
        lpFilename[i] = 0;
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return nSize;
    }

    DWORD i;
    for (i = 0; i < (DWORD)narrow_len; i++)
        lpFilename[i] = (WCHAR)(unsigned char)narrow[i];
    lpFilename[i] = 0;
    return i;
}

WINAPI_EXPORT DWORD GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer)
{
    const char *tmp = getenv("TMPDIR");
    if (!tmp) tmp = "/tmp/";

    /* Ensure trailing slash */
    char buf[PATH_MAX];
    snprintf(buf, sizeof(buf), "%s/", tmp);
    /* Remove double slashes */
    size_t len = strlen(buf);
    while (len > 1 && buf[len - 1] == '/' && buf[len - 2] == '/')
        buf[--len] = '\0';

    if ((DWORD)(len + 1) > nBufferLength) {
        return (DWORD)(len + 1);
    }

    strcpy(lpBuffer, buf);
    return (DWORD)len;
}

WINAPI_EXPORT DWORD GetTempPathW(DWORD nBufferLength, LPWSTR lpBuffer)
{
    char narrow[PATH_MAX];
    DWORD ret = GetTempPathA(sizeof(narrow), narrow);
    if (ret == 0 || ret > nBufferLength) return ret;

    for (DWORD i = 0; i < ret; i++)
        lpBuffer[i] = (WCHAR)(unsigned char)narrow[i];
    lpBuffer[ret] = 0;
    return ret;
}

WINAPI_EXPORT DWORD GetCurrentDirectoryA(DWORD nBufferLength, LPSTR lpBuffer)
{
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }

    size_t len = strlen(cwd);
    if ((DWORD)(len + 1) > nBufferLength) {
        return (DWORD)(len + 1);
    }

    strcpy(lpBuffer, cwd);
    return (DWORD)len;
}

WINAPI_EXPORT DWORD GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer)
{
    char narrow[PATH_MAX];
    DWORD ret = GetCurrentDirectoryA(sizeof(narrow), narrow);
    if (ret == 0 || (DWORD)(ret + 1) > nBufferLength) return ret + 1;

    for (DWORD i = 0; i < ret; i++)
        lpBuffer[i] = (WCHAR)(unsigned char)narrow[i];
    lpBuffer[ret] = 0;
    return ret;
}

WINAPI_EXPORT BOOL SetCurrentDirectoryA(LPCSTR lpPathName)
{
    if (!lpPathName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Translate Windows path to Linux if needed */
    char linux_path[PATH_MAX];
    if (win_path_to_linux(lpPathName, linux_path, sizeof(linux_path)) == 0) {
        if (chdir(linux_path) == 0)
            return TRUE;
    } else {
        if (chdir(lpPathName) == 0)
            return TRUE;
    }

    set_last_error(ERROR_PATH_NOT_FOUND);
    return FALSE;
}

WINAPI_EXPORT BOOL SetCurrentDirectoryW(LPCWSTR lpPathName)
{
    if (!lpPathName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    char narrow[PATH_MAX];
    int i = 0;
    while (lpPathName[i] && i < PATH_MAX - 1) {
        narrow[i] = (char)(lpPathName[i] & 0xFF);
        i++;
    }
    narrow[i] = '\0';
    return SetCurrentDirectoryA(narrow);
}

WINAPI_EXPORT DWORD GetFullPathNameA(LPCSTR lpFileName, DWORD nBufferLength,
                                      LPSTR lpBuffer, LPSTR *lpFilePart)
{
    if (!lpFileName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    char resolved[PATH_MAX];
    if (lpFileName[0] == '/' || lpFileName[0] == '\\') {
        snprintf(resolved, sizeof(resolved), "%s", lpFileName);
    } else {
        char cwd[PATH_MAX / 2];
        if (!getcwd(cwd, sizeof(cwd))) {
            set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            return 0;
        }
        snprintf(resolved, sizeof(resolved), "%s/%s", cwd, lpFileName);
    }

    size_t len = strlen(resolved);
    if ((DWORD)(len + 1) > nBufferLength)
        return (DWORD)(len + 1);

    strcpy(lpBuffer, resolved);

    if (lpFilePart) {
        char *last_sep = strrchr(lpBuffer, '/');
        if (!last_sep) last_sep = strrchr(lpBuffer, '\\');
        *lpFilePart = last_sep ? last_sep + 1 : lpBuffer;
    }

    return (DWORD)len;
}

/* ---- Wide path functions ---- */

static void wcs_to_narrow(const uint16_t *wide, char *buf, size_t bufsz)
{
    size_t i = 0;
    while (wide && wide[i] && i < bufsz - 1) { buf[i] = (char)(wide[i] & 0xFF); i++; }
    buf[i] = '\0';
}

static void narrow_to_wcs(const char *narrow, uint16_t *buf, size_t bufsz)
{
    size_t i = 0;
    while (narrow[i] && i < bufsz - 1) { buf[i] = (uint16_t)(unsigned char)narrow[i]; i++; }
    buf[i] = 0;
}

WINAPI_EXPORT UINT GetWindowsDirectoryW(uint16_t *lpBuffer, UINT uSize)
{
    static const char *windir = "C:\\Windows";
    size_t len = strlen(windir);
    if (uSize < len + 1) return (UINT)(len + 1);
    narrow_to_wcs(windir, lpBuffer, uSize);
    return (UINT)len;
}

WINAPI_EXPORT UINT GetWindowsDirectoryA(char *lpBuffer, UINT uSize)
{
    static const char *windir = "C:\\Windows";
    size_t len = strlen(windir);
    if (uSize < len + 1) return (UINT)(len + 1);
    strcpy(lpBuffer, windir);
    return (UINT)len;
}

WINAPI_EXPORT UINT GetSystemDirectoryW(uint16_t *lpBuffer, UINT uSize)
{
    static const char *sysdir = "C:\\Windows\\System32";
    size_t len = strlen(sysdir);
    if (uSize < len + 1) return (UINT)(len + 1);
    narrow_to_wcs(sysdir, lpBuffer, uSize);
    return (UINT)len;
}

WINAPI_EXPORT UINT GetSystemDirectoryA(char *lpBuffer, UINT uSize)
{
    static const char *sysdir = "C:\\Windows\\System32";
    size_t len = strlen(sysdir);
    if (uSize < len + 1) return (UINT)(len + 1);
    strcpy(lpBuffer, sysdir);
    return (UINT)len;
}

WINAPI_EXPORT DWORD GetShortPathNameW(const uint16_t *lpszLongPath,
    uint16_t *lpszShortPath, DWORD cchBuffer)
{
    if (!lpszLongPath) return 0;
    int len = 0;
    while (lpszLongPath[len]) len++;
    if (lpszShortPath && cchBuffer > (DWORD)len) {
        for (int i = 0; i <= len; i++) lpszShortPath[i] = lpszLongPath[i];
    }
    return (DWORD)len;
}

WINAPI_EXPORT DWORD SearchPathW(const uint16_t *lpPath, const uint16_t *lpFileName,
    const uint16_t *lpExtension, DWORD nBufferLength,
    uint16_t *lpBuffer, uint16_t **lpFilePart)
{
    (void)lpPath; (void)lpFileName; (void)lpExtension;
    (void)nBufferLength; (void)lpBuffer; (void)lpFilePart;
    set_last_error(2); /* ERROR_FILE_NOT_FOUND */
    return 0;
}

WINAPI_EXPORT BOOL SetFileAttributesW(const uint16_t *lpFileName, DWORD dwFileAttributes)
{
    (void)lpFileName; (void)dwFileAttributes;
    return TRUE;
}

WINAPI_EXPORT BOOL RemoveDirectoryW(const uint16_t *lpPathName)
{
    char narrow[512];
    wcs_to_narrow(lpPathName, narrow, sizeof(narrow));
    if (rmdir(narrow) == 0) return TRUE;
    set_last_error(3); /* ERROR_PATH_NOT_FOUND */
    return FALSE;
}

WINAPI_EXPORT BOOL MoveFileExW(const uint16_t *lpExistingFileName,
    const uint16_t *lpNewFileName, DWORD dwFlags)
{
    (void)dwFlags;
    char src[512], dst[512];
    wcs_to_narrow(lpExistingFileName, src, sizeof(src));
    wcs_to_narrow(lpNewFileName, dst, sizeof(dst));
    if (rename(src, dst) == 0) return TRUE;
    set_last_error(5); /* ERROR_ACCESS_DENIED */
    return FALSE;
}

WINAPI_EXPORT BOOL CopyFileW(const uint16_t *lpExistingFileName,
    const uint16_t *lpNewFileName, BOOL bFailIfExists)
{
    char src[512], dst[512];
    wcs_to_narrow(lpExistingFileName, src, sizeof(src));
    wcs_to_narrow(lpNewFileName, dst, sizeof(dst));

    if (bFailIfExists) {
        FILE *test = fopen(dst, "r");
        if (test) { fclose(test); set_last_error(80); return FALSE; } /* ERROR_FILE_EXISTS */
    }

    FILE *in = fopen(src, "rb");
    if (!in) { set_last_error(2); return FALSE; }
    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); set_last_error(5); return FALSE; }

    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
        fwrite(buf, 1, n, out);
    fclose(out);
    fclose(in);
    return TRUE;
}

WINAPI_EXPORT UINT GetTempFileNameW(const uint16_t *lpPathName,
    const uint16_t *lpPrefixString, UINT uUnique, uint16_t *lpTempFileName)
{
    (void)lpPrefixString;
    if (uUnique != 0) {
        char path[512];
        wcs_to_narrow(lpPathName, path, sizeof(path));
        char tmp[600];
        snprintf(tmp, sizeof(tmp), "%s\\%u.tmp", path, uUnique);
        narrow_to_wcs(tmp, lpTempFileName, 260);
        return uUnique;
    }
    char path[512], prefix[64];
    wcs_to_narrow(lpPathName, path, sizeof(path));
    wcs_to_narrow(lpPrefixString, prefix, sizeof(prefix));
    char tmp[600];
    snprintf(tmp, sizeof(tmp), "%s/%sXXXXXX", path, prefix);
    int fd = mkstemp(tmp);
    if (fd >= 0) close(fd);
    narrow_to_wcs(tmp, lpTempFileName, 260);
    return 1;
}

WINAPI_EXPORT BOOL GetDiskFreeSpaceW(const uint16_t *lpRootPathName,
    DWORD *lpSectorsPerCluster, DWORD *lpBytesPerSector,
    DWORD *lpNumberOfFreeClusters, DWORD *lpTotalNumberOfClusters)
{
    (void)lpRootPathName;
    if (lpSectorsPerCluster) *lpSectorsPerCluster = 8;
    if (lpBytesPerSector) *lpBytesPerSector = 512;
    if (lpNumberOfFreeClusters) *lpNumberOfFreeClusters = 1000000;
    if (lpTotalNumberOfClusters) *lpTotalNumberOfClusters = 2000000;
    return TRUE;
}

/* --------------------------------------------------------------------------
 * Private Profile (INI file) implementation
 * -------------------------------------------------------------------------- */

/* Read the INI file into a malloc'd buffer. Returns NULL on error. */
static char *ini_read_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 4*1024*1024) { fclose(f); return NULL; }
    char *buf = malloc((size_t)sz + 2);
    if (!buf) { fclose(f); return NULL; }
    size_t r = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[r] = '\n'; buf[r+1] = '\0';
    return buf;
}

/* Find value for [section] key in INI buffer. Returns pointer to value start
 * (within buf) and sets *vlen. Returns NULL if not found. */
static const char *ini_find_value(const char *buf, const char *section,
                                   const char *key, size_t *vlen)
{
    size_t slen = strlen(section), klen = strlen(key);
    const char *p = buf;
    int in_section = 0;

    while (*p) {
        /* Skip whitespace */
        while (*p == ' ' || *p == '\t') p++;
        if (*p == ';' || *p == '#') { while (*p && *p != '\n') p++; if (*p) p++; continue; }

        if (*p == '[') {
            p++;
            in_section = 0;
            if (strncasecmp(p, section, slen) == 0 && p[slen] == ']')
                in_section = 1;
            while (*p && *p != '\n') p++;
            if (*p) p++;
            continue;
        }

        if (in_section && strncasecmp(p, key, klen) == 0) {
            const char *q = p + klen;
            while (*q == ' ' || *q == '\t') q++;
            if (*q == '=') {
                q++;
                while (*q == ' ' || *q == '\t') q++;
                const char *val_start = q;
                while (*q && *q != '\n' && *q != '\r') q++;
                /* Trim trailing whitespace */
                const char *val_end = q;
                while (val_end > val_start && (val_end[-1] == ' ' || val_end[-1] == '\t'))
                    val_end--;
                *vlen = (size_t)(val_end - val_start);
                return val_start;
            }
        }

        while (*p && *p != '\n') p++;
        if (*p) p++;
    }
    return NULL;
}

WINAPI_EXPORT DWORD GetPrivateProfileStringA(
    LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpDefault,
    LPSTR lpReturnedString, DWORD nSize, LPCSTR lpFileName)
{
    if (!lpReturnedString || nSize == 0) return 0;
    lpReturnedString[0] = '\0';

    const char *def = lpDefault ? lpDefault : "";

    if (!lpFileName || !lpAppName || !lpKeyName) {
        strncpy(lpReturnedString, def, nSize - 1);
        lpReturnedString[nSize - 1] = '\0';
        return (DWORD)strlen(lpReturnedString);
    }

    char linux_path[4096];
    win_path_to_linux(lpFileName, linux_path, sizeof(linux_path));

    char *buf = ini_read_file(linux_path);
    if (!buf) {
        strncpy(lpReturnedString, def, nSize - 1);
        lpReturnedString[nSize - 1] = '\0';
        return (DWORD)strlen(lpReturnedString);
    }

    size_t vlen = 0;
    const char *val = ini_find_value(buf, lpAppName, lpKeyName, &vlen);
    if (val && vlen > 0) {
        size_t copy = vlen < (size_t)(nSize - 1) ? vlen : (size_t)(nSize - 1);
        memcpy(lpReturnedString, val, copy);
        lpReturnedString[copy] = '\0';
    } else {
        strncpy(lpReturnedString, def, nSize - 1);
        lpReturnedString[nSize - 1] = '\0';
    }
    free(buf);
    return (DWORD)strlen(lpReturnedString);
}

WINAPI_EXPORT BOOL WritePrivateProfileStringA(
    LPCSTR lpAppName, LPCSTR lpKeyName, LPCSTR lpString, LPCSTR lpFileName)
{
    if (!lpFileName || !lpAppName || !lpKeyName) return FALSE;

    char linux_path[4096];
    win_path_to_linux(lpFileName, linux_path, sizeof(linux_path));

    /* Read existing file */
    char *buf = ini_read_file(linux_path);
    size_t buf_len = buf ? strlen(buf) : 0;

    /* Simple approach: rewrite the file with the new key/value */
    FILE *f = fopen(linux_path, "w");
    if (!f) { free(buf); return FALSE; }

    int wrote_section = 0, wrote_key = 0;
    size_t slen = strlen(lpAppName), klen = strlen(lpKeyName);

    if (buf) {
        char *line = buf;
        while (*line) {
            char *nl = strchr(line, '\n');
            size_t line_len = nl ? (size_t)(nl - line) : strlen(line);
            char line_buf[4096];
            size_t copy = line_len < sizeof(line_buf)-1 ? line_len : sizeof(line_buf)-1;
            memcpy(line_buf, line, copy); line_buf[copy] = '\0';

            /* Trim CR */
            if (copy > 0 && line_buf[copy-1] == '\r') line_buf[--copy] = '\0';

            /* Check if this is our section */
            const char *t = line_buf;
            while (*t == ' ' || *t == '\t') t++;
            if (*t == '[') {
                if (wrote_section && !wrote_key && lpString) {
                    /* Insert key before next section */
                    fprintf(f, "%s=%s\n", lpKeyName, lpString);
                    wrote_key = 1;
                }
                if (strncasecmp(t+1, lpAppName, slen) == 0 && t[1+slen] == ']')
                    wrote_section = 1;
                else wrote_section = 0;
            }

            if (wrote_section && !wrote_key) {
                /* Check if this is our key */
                if (strncasecmp(t, lpKeyName, klen) == 0) {
                    const char *q = t + klen;
                    while (*q == ' ' || *q == '\t') q++;
                    if (*q == '=') {
                        /* Replace or delete this line */
                        if (lpString)
                            fprintf(f, "%s=%s\n", lpKeyName, lpString);
                        /* else delete: skip */
                        wrote_key = 1;
                        line = nl ? nl + 1 : line + line_len;
                        continue;
                    }
                }
            }

            fprintf(f, "%s\n", line_buf);
            line = nl ? nl + 1 : line + line_len;
        }
        free(buf);
    }
    (void)buf_len;

    if (!wrote_section && lpString) {
        fprintf(f, "[%s]\n%s=%s\n", lpAppName, lpKeyName, lpString);
    } else if (wrote_section && !wrote_key && lpString) {
        fprintf(f, "%s=%s\n", lpKeyName, lpString);
    }

    fclose(f);
    return TRUE;
}

WINAPI_EXPORT UINT GetPrivateProfileIntA(LPCSTR lpAppName, LPCSTR lpKeyName,
    INT nDefault, LPCSTR lpFileName)
{
    char buf[64];
    GetPrivateProfileStringA(lpAppName, lpKeyName, NULL, buf, sizeof(buf), lpFileName);
    if (buf[0] == '\0') return (UINT)nDefault;
    return (UINT)atoi(buf);
}

WINAPI_EXPORT BOOL WritePrivateProfileSectionA(LPCSTR lpAppName,
    LPCSTR lpString, LPCSTR lpFileName)
{
    (void)lpAppName; (void)lpString; (void)lpFileName;
    return TRUE; /* Stub */
}

WINAPI_EXPORT DWORD GetPrivateProfileSectionA(LPCSTR lpAppName,
    LPSTR lpReturnedString, DWORD nSize, LPCSTR lpFileName)
{
    (void)lpAppName; (void)lpFileName;
    if (lpReturnedString && nSize >= 2) {
        lpReturnedString[0] = '\0';
        lpReturnedString[1] = '\0';
    }
    return 0;
}

WINAPI_EXPORT DWORD GetPrivateProfileStringW(const uint16_t *lpAppName,
    const uint16_t *lpKeyName, const uint16_t *lpDefault,
    uint16_t *lpReturnedString, DWORD nSize, const uint16_t *lpFileName)
{
    /* Convert to narrow and delegate */
    char sec[512]={0}, key[512]={0}, def[2048]={0}, file[4096]={0};
    for (int i=0; lpAppName && lpAppName[i] && i<511; i++) sec[i]=(char)lpAppName[i];
    for (int i=0; lpKeyName  && lpKeyName[i]  && i<511; i++) key[i]=(char)lpKeyName[i];
    for (int i=0; lpDefault  && lpDefault[i]  && i<2047; i++) def[i]=(char)lpDefault[i];
    for (int i=0; lpFileName && lpFileName[i] && i<4095; i++) file[i]=(char)lpFileName[i];
    char out[4096]={0};
    DWORD r = GetPrivateProfileStringA(sec, key, def, out, sizeof(out), file);
    if (lpReturnedString) {
        DWORD i=0;
        for (; out[i] && i < nSize-1; i++) lpReturnedString[i]=(uint16_t)(uint8_t)out[i];
        lpReturnedString[i]=0;
        r = i;
    }
    return r;
}

WINAPI_EXPORT BOOL WritePrivateProfileStringW(const uint16_t *lpAppName,
    const uint16_t *lpKeyName, const uint16_t *lpString,
    const uint16_t *lpFileName)
{
    char sec[512]={0}, key[512]={0}, val[2048]={0}, file[4096]={0};
    for (int i=0; lpAppName && lpAppName[i] && i<511; i++) sec[i]=(char)lpAppName[i];
    for (int i=0; lpKeyName  && lpKeyName[i]  && i<511; i++) key[i]=(char)lpKeyName[i];
    for (int i=0; lpString   && lpString[i]   && i<2047; i++) val[i]=(char)lpString[i];
    for (int i=0; lpFileName && lpFileName[i] && i<4095; i++) file[i]=(char)lpFileName[i];
    return WritePrivateProfileStringA(sec, key, lpString ? val : NULL, file);
}

/* FindFirstFileExW moved to kernel32_find.c */
