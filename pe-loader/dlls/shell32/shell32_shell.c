/*
 * shell32_shell.c - Windows Shell API stubs
 *
 * SHGetFolderPathA, ShellExecuteA, CommandLineToArgvW, SHGetSpecialFolderPath,
 * SHFileOperationA, ExtractIconA, etc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "common/dll_common.h"
#include "compat/trust_gate.h"

/* CSIDL folder IDs */
#define CSIDL_DESKTOP           0x0000
#define CSIDL_PROGRAMS          0x0002
#define CSIDL_PERSONAL          0x0005  /* My Documents */
#define CSIDL_FAVORITES         0x0006
#define CSIDL_STARTUP           0x0007
#define CSIDL_RECENT            0x0008
#define CSIDL_APPDATA           0x001A
#define CSIDL_LOCAL_APPDATA     0x001C
#define CSIDL_COMMON_APPDATA    0x0023
#define CSIDL_WINDOWS           0x0024
#define CSIDL_SYSTEM            0x0025
#define CSIDL_PROGRAM_FILES     0x0026
#define CSIDL_MYPICTURES        0x0027
#define CSIDL_PROFILE           0x0028
#define CSIDL_PROGRAM_FILESX86  0x002A
#define CSIDL_COMMON_FILES      0x002B
#define CSIDL_COMMON_DOCUMENTS  0x002E
#define CSIDL_FONTS             0x0014

/* KNOWNFOLDERID - same as CSIDL but for newer API */
#define FOLDERID_DESKTOP        CSIDL_DESKTOP
#define FOLDERID_DOCUMENTS      CSIDL_PERSONAL
#define FOLDERID_APPDATA        CSIDL_APPDATA
#define FOLDERID_LOCAL_APPDATA  CSIDL_LOCAL_APPDATA

/* HRESULT */
#define S_OK        ((HRESULT)0)
#define S_FALSE     ((HRESULT)1)
#define E_FAIL      ((HRESULT)0x80004005)
#define E_INVALIDARG ((HRESULT)0x80070057)

/* ShellExecute return codes (must be > 32 for success) */
#define SE_ERR_FNF             2
#define SE_ERR_NOASSOC        31
#define SE_ERR_OOM             8

static const char *get_home(void)
{
    const char *home = getenv("HOME");
    return home ? home : "/tmp";
}

/* Map CSIDL to a Linux path under ~/.pe-compat/ */
static int csidl_to_path(int csidl, char *path, size_t size)
{
    const char *home = get_home();
    const char *prefix = get_pe_compat_prefix();

    switch (csidl & 0xFF) {
    case CSIDL_DESKTOP:
        snprintf(path, size, "%s/Desktop", home);
        break;
    case CSIDL_PERSONAL:
        snprintf(path, size, "%s/Documents", home);
        break;
    case CSIDL_MYPICTURES:
        snprintf(path, size, "%s/Pictures", home);
        break;
    case CSIDL_APPDATA:
        snprintf(path, size, "%s/drives/c/Users/user/AppData/Roaming", prefix);
        break;
    case CSIDL_LOCAL_APPDATA:
        snprintf(path, size, "%s/drives/c/Users/user/AppData/Local", prefix);
        break;
    case CSIDL_COMMON_APPDATA:
        snprintf(path, size, "%s/drives/c/ProgramData", prefix);
        break;
    case CSIDL_PROGRAM_FILES:
    case CSIDL_PROGRAM_FILESX86:
        snprintf(path, size, "%s/drives/c/Program Files", prefix);
        break;
    case CSIDL_COMMON_FILES:
        snprintf(path, size, "%s/drives/c/Program Files/Common Files", prefix);
        break;
    case CSIDL_WINDOWS:
        snprintf(path, size, "%s/drives/c/Windows", prefix);
        break;
    case CSIDL_SYSTEM:
        snprintf(path, size, "%s/drives/c/Windows/System32", prefix);
        break;
    case CSIDL_FONTS:
        snprintf(path, size, "%s/drives/c/Windows/Fonts", prefix);
        break;
    case CSIDL_PROFILE:
        snprintf(path, size, "%s/drives/c/Users/user", prefix);
        break;
    case CSIDL_COMMON_DOCUMENTS:
        snprintf(path, size, "%s/drives/c/Users/Public/Documents", prefix);
        break;
    case CSIDL_RECENT:
        snprintf(path, size, "%s/drives/c/Users/user/Recent", prefix);
        break;
    case CSIDL_FAVORITES:
        snprintf(path, size, "%s/drives/c/Users/user/Favorites", prefix);
        break;
    default:
        snprintf(path, size, "%s/drives/c/Users/user", prefix);
        break;
    }

    /* Ensure the directory exists (create parents recursively) */
    {
        char tmp[4096];
        strncpy(tmp, path, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';
        for (char *p = tmp + 1; *p; p++) {
            if (*p == '/') {
                *p = '\0';
                mkdir(tmp, 0755);
                *p = '/';
            }
        }
        mkdir(tmp, 0755);
    }
    return 0;
}

WINAPI_EXPORT HRESULT SHGetFolderPathA(
    HWND hwnd, int csidl, HANDLE hToken,
    DWORD dwFlags, LPSTR pszPath)
{
    (void)hwnd;
    (void)hToken;
    (void)dwFlags;

    if (!pszPath)
        return E_INVALIDARG;

    char path[MAX_PATH];
    if (csidl_to_path(csidl, path, sizeof(path)) < 0)
        return E_FAIL;

    strncpy(pszPath, path, MAX_PATH - 1);
    pszPath[MAX_PATH - 1] = '\0';
    return S_OK;
}

WINAPI_EXPORT HRESULT SHGetFolderPathW(
    HWND hwnd, int csidl, HANDLE hToken,
    DWORD dwFlags, LPWSTR pszPath)
{
    if (!pszPath) return E_INVALIDARG;
    char narrow[MAX_PATH];
    HRESULT hr = SHGetFolderPathA(hwnd, csidl, hToken, dwFlags, narrow);
    if (hr != S_OK) return hr;

    /* Convert narrow to wide. Session 30: old code wrote the terminator at
     * strlen(narrow) even when the narrow string was longer than MAX_PATH-1
     * (impossible today, but defensive), potentially walking past the caller's
     * MAX_PATH-sized buffer. Cap at i and write NUL there. */
    int i;
    for (i = 0; i < MAX_PATH - 1 && narrow[i]; i++)
        pszPath[i] = (WCHAR)(unsigned char)narrow[i];
    pszPath[i] = 0;
    return S_OK;
}

WINAPI_EXPORT BOOL SHGetSpecialFolderPathA(
    HWND hwnd, LPSTR pszPath, int csidl, BOOL fCreate)
{
    (void)hwnd;
    (void)fCreate;

    if (!pszPath) return FALSE;

    char path[MAX_PATH];
    if (csidl_to_path(csidl, path, sizeof(path)) < 0)
        return FALSE;

    strncpy(pszPath, path, MAX_PATH - 1);
    pszPath[MAX_PATH - 1] = '\0';
    return TRUE;
}

WINAPI_EXPORT HRESULT SHGetKnownFolderPath(
    const GUID *rfid, DWORD dwFlags, HANDLE hToken, LPWSTR *ppszPath)
{
    (void)rfid;
    (void)dwFlags;
    (void)hToken;

    if (!ppszPath) return E_INVALIDARG;

    /* Default to user profile */
    const char *home = get_home();
    size_t len = strlen(home);

    WCHAR *path = malloc((len + 1) * sizeof(WCHAR));
    if (!path) { *ppszPath = NULL; return E_FAIL; }

    for (size_t i = 0; i < len; i++)
        path[i] = (WCHAR)(unsigned char)home[i];
    path[len] = 0;

    *ppszPath = path;
    return S_OK;
}

WINAPI_EXPORT HINSTANCE ShellExecuteA(
    HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile,
    LPCSTR lpParameters, LPCSTR lpDirectory, int nShowCmd)
{
    (void)hwnd;
    (void)nShowCmd;

    fprintf(stderr, "[shell32] ShellExecuteA('%s', '%s', '%s')\n",
            lpOperation ? lpOperation : "open",
            lpFile ? lpFile : "(null)",
            lpParameters ? lpParameters : "");

    if (!lpFile)
        return (HINSTANCE)(intptr_t)SE_ERR_FNF;

    /* Session 30: ShellExecute forks a child and execs arbitrary binaries —
     * this is a process-create gate on Windows (LUA elevation prompt, etc.).
     * Trust kernel must approve, otherwise an untrusted PE could escape
     * through ShellExecute("cmd.exe", ...) or rundll32 to spawn arbitrary
     * processes. SE_ERR_ACCESSDENIED is the canonical Windows error value
     * for blocked execution. */
    TRUST_CHECK_RET(TRUST_GATE_PROCESS_CREATE, "ShellExecuteA",
                    (HINSTANCE)(intptr_t)5 /* SE_ERR_ACCESSDENIED */);

    /* Try to open with xdg-open (files/URLs) or execute directly.
     * Use double-fork so the grandchild is reparented to init and
     * automatically reaped; avoids zombie leak since we never waitpid. */
    pid_t pid = fork();
    if (pid == 0) {
        pid_t pid2 = fork();
        if (pid2 == 0) {
            if (lpDirectory)
                if (chdir(lpDirectory) < 0) { /* ignore */ }

            if (lpParameters && lpParameters[0]) {
                /* Execute directly without shell to prevent command injection.
                 * lpParameters is passed as a single argument; callers that need
                 * word-splitting should tokenize before calling ShellExecuteA. */
                execlp(lpFile, lpFile, lpParameters, NULL);
            } else {
                execlp("xdg-open", "xdg-open", lpFile, NULL);
            }
            _exit(1);
        }
        _exit(0);
    }
    if (pid > 0) {
        int status;
        (void)waitpid(pid, &status, 0); /* Reap intermediate child */
        (void)status;
    }

    return (HINSTANCE)(intptr_t)42; /* > 32 = success */
}

WINAPI_EXPORT HINSTANCE ShellExecuteW(
    HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile,
    LPCWSTR lpParameters, LPCWSTR lpDirectory, int nShowCmd)
{
    /* Convert wide to narrow for the A version */
    char op[256] = {0}, file[4096] = {0}, params[4096] = {0}, dir[4096] = {0};

    if (lpOperation) {
        for (int i = 0; lpOperation[i] && i < 255; i++)
            op[i] = (char)(lpOperation[i] & 0xFF);
    }
    if (lpFile) {
        for (int i = 0; lpFile[i] && i < 4095; i++)
            file[i] = (char)(lpFile[i] & 0xFF);
    }
    if (lpParameters) {
        for (int i = 0; lpParameters[i] && i < 4095; i++)
            params[i] = (char)(lpParameters[i] & 0xFF);
    }
    if (lpDirectory) {
        for (int i = 0; lpDirectory[i] && i < 4095; i++)
            dir[i] = (char)(lpDirectory[i] & 0xFF);
    }

    return ShellExecuteA(hwnd,
                         lpOperation ? op : NULL,
                         lpFile ? file : NULL,
                         lpParameters ? params : NULL,
                         lpDirectory ? dir : NULL,
                         nShowCmd);
}

WINAPI_EXPORT LPWSTR *CommandLineToArgvW(LPCWSTR lpCmdLine, int *pNumArgs)
{
    if (!lpCmdLine || !pNumArgs) {
        if (pNumArgs) *pNumArgs = 0;
        return NULL;
    }

    /* Simple tokenizer: split by spaces, respect quotes */
    int wlen = 0;
    while (lpCmdLine[wlen]) wlen++;

    /* Worst case: every char is an arg. Guard against overflow. */
    if (wlen > 0x7FFFFF) { *pNumArgs = 0; return NULL; }
    size_t alloc_sz = (size_t)(wlen + 1) * sizeof(LPWSTR) + (size_t)(wlen + 1) * sizeof(WCHAR) * 2;
    LPWSTR *argv = (LPWSTR *)malloc(alloc_sz);
    if (!argv) {
        *pNumArgs = 0;
        return NULL;
    }

    WCHAR *buf = (WCHAR *)((char *)argv + (wlen + 1) * sizeof(LPWSTR));
    int argc = 0;
    int i = 0, j = 0;
    int in_quote = 0;

    while (lpCmdLine[i]) {
        /* Skip whitespace */
        while (lpCmdLine[i] == ' ' || lpCmdLine[i] == '\t')
            i++;
        if (!lpCmdLine[i]) break;

        argv[argc++] = &buf[j];
        in_quote = 0;

        while (lpCmdLine[i]) {
            if (lpCmdLine[i] == '"') {
                in_quote = !in_quote;
                i++;
            } else if (!in_quote && (lpCmdLine[i] == ' ' || lpCmdLine[i] == '\t')) {
                break;
            } else {
                buf[j++] = lpCmdLine[i++];
            }
        }
        buf[j++] = 0;
    }

    *pNumArgs = argc;
    return argv;
}

WINAPI_EXPORT HICON ExtractIconA(HINSTANCE hInst, LPCSTR lpszExeFileName, UINT nIconIndex)
{
    (void)hInst;
    (void)lpszExeFileName;
    (void)nIconIndex;
    return NULL; /* No icon support */
}

WINAPI_EXPORT UINT ExtractIconExA(LPCSTR lpszFile, int nIconIndex,
                                   HICON *phiconLarge, HICON *phiconSmall, UINT nIcons)
{
    (void)lpszFile;
    (void)nIconIndex;
    (void)nIcons;
    if (phiconLarge) *phiconLarge = NULL;
    if (phiconSmall) *phiconSmall = NULL;
    return 0;
}

WINAPI_EXPORT UINT DragQueryFileA(HANDLE hDrop, UINT iFile, LPSTR lpszFile, UINT cch)
{
    (void)hDrop;
    (void)iFile;
    (void)lpszFile;
    (void)cch;
    return 0;
}

WINAPI_EXPORT void DragAcceptFiles(HWND hWnd, BOOL fAccept)
{
    (void)hWnd;
    (void)fAccept;
}

WINAPI_EXPORT void DragFinish(HANDLE hDrop)
{
    (void)hDrop;
}

WINAPI_EXPORT HRESULT SHCreateDirectoryExA(HWND hwnd, LPCSTR pszPath, void *psa)
{
    (void)hwnd;
    (void)psa;

    if (!pszPath) return E_INVALIDARG;

    char linux_path[4096];
    win_path_to_linux(pszPath, linux_path, sizeof(linux_path));

    /* Create recursively */
    char tmp[4096];
    strncpy(tmp, linux_path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);

    return S_OK;
}

/* SHFileOperation stub */
typedef struct {
    HWND    hwnd;
    UINT    wFunc;
    LPCSTR  pFrom;
    LPCSTR  pTo;
    WORD    fFlags;
    BOOL    fAnyOperationsAborted;
    LPVOID  hNameMappings;
    LPCSTR  lpszProgressTitle;
} SHFILEOPSTRUCTA;

#define FO_MOVE     0x0001
#define FO_COPY     0x0002
#define FO_DELETE   0x0003
#define FO_RENAME   0x0004

WINAPI_EXPORT int SHFileOperationA(SHFILEOPSTRUCTA *lpFileOp)
{
    if (!lpFileOp) return 1;

    fprintf(stderr, "[shell32] SHFileOperationA(func=%u, from='%s')\n",
            lpFileOp->wFunc, lpFileOp->pFrom ? lpFileOp->pFrom : "(null)");

    /* Stub - report success without doing anything */
    lpFileOp->fAnyOperationsAborted = FALSE;
    return 0;
}

WINAPI_EXPORT void SHChangeNotify(long wEventId, UINT uFlags, LPCVOID dwItem1, LPCVOID dwItem2)
{
    (void)wEventId;
    (void)uFlags;
    (void)dwItem1;
    (void)dwItem2;
}

/* ---- Additional shell functions for SteamSetup/PuTTY ---- */

WINAPI_EXPORT HRESULT SHGetSpecialFolderLocation(HWND hwnd, int csidl, void **ppidl)
{
    (void)hwnd; (void)csidl;
    if (ppidl) *ppidl = NULL;
    return 0; /* S_OK — callers check ppidl for NULL */
}

WINAPI_EXPORT BOOL SHGetPathFromIDListW(const void *pidl, uint16_t *pszPath)
{
    (void)pidl;
    if (pszPath) pszPath[0] = 0;
    return TRUE;
}

WINAPI_EXPORT BOOL SHGetPathFromIDListA(const void *pidl, char *pszPath)
{
    (void)pidl;
    if (pszPath) pszPath[0] = 0;
    return TRUE;
}

WINAPI_EXPORT void *SHBrowseForFolderW(void *lpbi)
{
    (void)lpbi;
    return NULL; /* User cancelled */
}

WINAPI_EXPORT void *SHBrowseForFolderA(void *lpbi)
{
    (void)lpbi;
    return NULL;
}

WINAPI_EXPORT DWORD_PTR SHGetFileInfoW(const uint16_t *pszPath, DWORD dwFileAttributes,
    void *psfi, UINT cbFileInfo, UINT uFlags)
{
    (void)pszPath; (void)dwFileAttributes;
    (void)psfi; (void)cbFileInfo; (void)uFlags;
    return 0;
}

WINAPI_EXPORT DWORD_PTR SHGetFileInfoA(LPCSTR pszPath, DWORD dwFileAttributes,
    void *psfi, UINT cbFileInfo, UINT uFlags)
{
    (void)pszPath; (void)dwFileAttributes;
    (void)psfi; (void)cbFileInfo; (void)uFlags;
    return 0;
}

typedef struct {
    HWND hwnd;
    UINT wFunc;
    const uint16_t *pFrom;
    const uint16_t *pTo;
    uint16_t fFlags;
    BOOL fAnyOperationsAborted;
    void *hNameMappings;
    const uint16_t *lpszProgressTitle;
} SHFILEOPSTRUCTW;

WINAPI_EXPORT int SHFileOperationW(SHFILEOPSTRUCTW *lpFileOp)
{
    if (!lpFileOp) return 1;
    lpFileOp->fAnyOperationsAborted = FALSE;
    return 0;
}

/* ==========================================================================
 * IShellItem / SH* / IL* family — simple stubs
 *
 * Most of these return E_NOTIMPL; apps handle that by falling back to
 * legacy APIs (CSIDL, ShellExecute, plain paths). A few (SHGetStockIconInfo,
 * SHCreateDirectoryExW, SHAddToRecentDocs) give a "success with defaults"
 * answer since apps often ignore icons/recent-docs without ever branching.
 * ==========================================================================
 */

/* HRESULT constants local to shell32 */
#ifndef E_NOTIMPL
#define E_NOTIMPL   ((HRESULT)0x80004001)
#endif

/* Win32 error codes used by SHCreateDirectoryEx* */
#ifndef ERROR_SUCCESS
#define ERROR_SUCCESS                0
#endif
#ifndef ERROR_PATH_NOT_FOUND
#define ERROR_PATH_NOT_FOUND         3
#endif
#ifndef ERROR_ALREADY_EXISTS
#define ERROR_ALREADY_EXISTS         183
#endif
#ifndef ERROR_BAD_PATHNAME
#define ERROR_BAD_PATHNAME           161
#endif

/* Opaque types */
typedef void IBindCtx;
typedef void IShellFolder;
typedef void IShellItem;
typedef void IMalloc;
typedef void IUnknown;
typedef GUID *REFIID;
typedef struct _ITEMIDLIST ITEMIDLIST;
typedef ITEMIDLIST *PIDLIST_ABSOLUTE;
typedef ITEMIDLIST *PIDLIST_RELATIVE;
typedef const ITEMIDLIST *PCIDLIST_ABSOLUTE;
typedef const ITEMIDLIST *PCUIDLIST_RELATIVE;
typedef const ITEMIDLIST *PCUITEMID_CHILD;
typedef ULONG SFGAOF;

/* SHSTOCKICONINFO: exact 0x10C byte layout */
typedef int SHSTOCKICONID;
typedef struct _SHSTOCKICONINFO {
    DWORD  cbSize;
    HICON  hIcon;
    int    iSysImageIndex;
    int    iIcon;
    WCHAR  szPath[MAX_PATH];
} SHSTOCKICONINFO;

/* ---- SH* family ---- */

WINAPI_EXPORT HRESULT SHCreateItemFromParsingName(
    const uint16_t *path, IBindCtx *ctx, REFIID iid, void **item)
{
    (void)path; (void)ctx; (void)iid;
    if (item) *item = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT SHParseDisplayName(
    const uint16_t *name, IBindCtx *ctx,
    PIDLIST_ABSOLUTE *pidl, SFGAOF attrs, SFGAOF *out_attrs)
{
    (void)name; (void)ctx; (void)attrs;
    if (pidl) *pidl = NULL;
    if (out_attrs) *out_attrs = 0;
    return E_FAIL;
}

WINAPI_EXPORT HRESULT SHGetDesktopFolder(IShellFolder **ppshf)
{
    if (ppshf) *ppshf = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT SHGetStockIconInfo(
    SHSTOCKICONID id, UINT flags, SHSTOCKICONINFO *info)
{
    (void)id; (void)flags;
    /* Zero-fill so callers reading hIcon/szPath see a benign default.
     * Preserve cbSize so size-validating callers don't reject the struct. */
    if (!info) return E_INVALIDARG;
    DWORD saved_size = info->cbSize;
    memset(info, 0, sizeof(*info));
    info->cbSize = saved_size ? saved_size : (DWORD)sizeof(*info);
    return S_OK;
}

WINAPI_EXPORT HRESULT SHGetImageList(int id, REFIID iid, void **pp)
{
    (void)id; (void)iid;
    if (pp) *pp = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT void SHAddToRecentDocs(UINT flags, LPCVOID data)
{
    (void)flags; (void)data;
    /* No-op: we don't track a Recent Documents list. */
}

WINAPI_EXPORT HRESULT SHCreateShellItem(
    PCIDLIST_ABSOLUTE parent, IShellFolder *sf,
    PCUITEMID_CHILD child, IShellItem **ppsi)
{
    (void)parent; (void)sf; (void)child;
    if (ppsi) *ppsi = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT SHGetMalloc(IMalloc **ppm)
{
    if (ppm) *ppm = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT SHGetIDListFromObject(IUnknown *punk, PIDLIST_ABSOLUTE *ppidl)
{
    (void)punk;
    if (ppidl) *ppidl = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT SHGetInstanceExplorer(IUnknown **ppunk)
{
    if (ppunk) *ppunk = NULL;
    return E_NOTIMPL;
}

/* SHCreateDirectoryExW:
 *  mkdir -p on the wide path. Maps Linux errno to Win32 error codes
 *  returned as HRESULT-ish int values (matches native behavior —
 *  SHCreateDirectoryEx returns Win32 error codes, not HRESULTs).
 *  A narrow SHCreateDirectoryExA already exists above; leave it alone.
 */
WINAPI_EXPORT HRESULT SHCreateDirectoryExW(HWND hwnd, const uint16_t *pszPath, void *psa)
{
    (void)hwnd; (void)psa;

    if (!pszPath) return (HRESULT)ERROR_BAD_PATHNAME;

    char narrow[4096];
    wide_to_narrow_safe(pszPath, narrow, (int)sizeof(narrow));
    if (!narrow[0]) return (HRESULT)ERROR_BAD_PATHNAME;

    char linux_path[4096];
    win_path_to_linux(narrow, linux_path, sizeof(linux_path));

    /* Create recursively. Track whether any stage existed already. */
    char tmp[4096];
    strncpy(tmp, linux_path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    int any_existed = 0;
    int any_failed = 0;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) < 0) {
                if (errno == EEXIST) any_existed = 1;
                else if (errno == ENOENT) any_failed = 1;
            }
            *p = '/';
        }
    }
    int rc = mkdir(tmp, 0755);
    if (rc < 0 && errno == EEXIST)  return (HRESULT)ERROR_ALREADY_EXISTS;
    if (rc < 0 && errno == ENOENT)  return (HRESULT)ERROR_PATH_NOT_FOUND;
    if (rc < 0 && any_failed)       return (HRESULT)ERROR_PATH_NOT_FOUND;
    (void)any_existed;
    return (HRESULT)ERROR_SUCCESS;
}

/* ---- IL* PIDL family ----
 *
 * We don't actually synthesize PIDLs (they're opaque shell-side tokens with
 * no Linux analogue). Creators return NULL so callers fall back to path-based
 * APIs. ILFree frees what ILClone allocated; ILClone uses the ITEMIDLIST
 * self-describing length (first 2 bytes of each SHITEMID is cb; list ends
 * with a 2-byte zero cb) to memdup a caller-provided PIDL safely.
 */

WINAPI_EXPORT PIDLIST_ABSOLUTE ILCreateFromPathA(LPCSTR path)
{
    (void)path;
    return NULL;
}

WINAPI_EXPORT PIDLIST_ABSOLUTE ILCreateFromPathW(const uint16_t *path)
{
    (void)path;
    return NULL;
}

WINAPI_EXPORT void ILFree(PIDLIST_RELATIVE pidl)
{
    if (pidl) free(pidl);
}

WINAPI_EXPORT PIDLIST_RELATIVE ILClone(PCUIDLIST_RELATIVE pidl)
{
    if (!pidl) return NULL;

    /* Walk the ITEMIDLIST: each SHITEMID starts with a 2-byte cb (total
     * size of that element including the cb field). A terminator has cb=0.
     * Total length = sum(cb) + 2 for the terminator. Cap at 64KB to bound
     * pathological inputs. */
    const unsigned char *p = (const unsigned char *)pidl;
    size_t total = 0;
    while (total < 65534) {
        unsigned short cb = (unsigned short)(p[total] | (p[total + 1] << 8));
        if (cb == 0) { total += 2; break; }
        if (cb < 2) return NULL; /* malformed */
        total += cb;
    }
    if (total == 0 || total > 65536) return NULL;

    void *copy = malloc(total);
    if (!copy) return NULL;
    memcpy(copy, pidl, total);
    return (PIDLIST_RELATIVE)copy;
}
