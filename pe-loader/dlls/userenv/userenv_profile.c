/*
 * userenv_profile.c - User Environment (userenv.dll) stubs
 *
 * Provides GetUserProfileDirectory, CreateEnvironmentBlock, etc.
 * Backed by Linux HOME/passwd.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "common/dll_common.h"

extern char **environ;

static const char *get_home_dir(void)
{
    const char *home = getenv("HOME");
    if (home) return home;
    struct passwd *pw = getpwuid(getuid());
    if (pw) return pw->pw_dir;
    return "/tmp";
}

/* Return the Windows-compatible user profile directory under pe-compat */
static const char *get_profile_dir(void)
{
    static char profile_dir[4096];
    if (profile_dir[0] == '\0') {
        const char *home = get_home_dir();
        const char *user = "user";
        struct passwd *pw = getpwuid(getuid());
        if (pw) user = pw->pw_name;
        snprintf(profile_dir, sizeof(profile_dir),
                 "%s/.pe-compat/drives/c/Users/%s", home, user);
    }
    return profile_dir;
}

/* ========== Profile Directory Functions ========== */

WINAPI_EXPORT BOOL GetUserProfileDirectoryA(void *hToken, char *lpProfileDir,
                                              uint32_t *lpcchSize)
{
    (void)hToken;
    const char *dir = get_profile_dir();
    uint32_t len = (uint32_t)strlen(dir) + 1;

    if (!lpcchSize) return FALSE;
    if (!lpProfileDir || *lpcchSize < len) {
        *lpcchSize = len;
        return FALSE;
    }
    strncpy(lpProfileDir, dir, *lpcchSize);
    lpProfileDir[*lpcchSize - 1] = '\0';
    *lpcchSize = len;
    return TRUE;
}

WINAPI_EXPORT BOOL GetUserProfileDirectoryW(void *hToken, uint16_t *lpProfileDir,
                                              uint32_t *lpcchSize)
{
    (void)hToken;
    const char *dir = get_profile_dir();
    uint32_t len = (uint32_t)strlen(dir) + 1;

    if (!lpcchSize) return FALSE;
    if (!lpProfileDir || *lpcchSize < len) {
        *lpcchSize = len;
        return FALSE;
    }
    for (uint32_t i = 0; i < len; i++)
        lpProfileDir[i] = (uint16_t)(uint8_t)dir[i];
    *lpcchSize = len;
    return TRUE;
}

WINAPI_EXPORT BOOL GetProfilesDirectoryA(char *lpProfileDir, uint32_t *lpcchSize)
{
    const char *dir = "/home";
    uint32_t len = (uint32_t)strlen(dir) + 1;

    if (!lpcchSize) return FALSE;
    if (!lpProfileDir || *lpcchSize < len) {
        *lpcchSize = len;
        return FALSE;
    }
    strncpy(lpProfileDir, dir, *lpcchSize);
    lpProfileDir[*lpcchSize - 1] = '\0';
    *lpcchSize = len;
    return TRUE;
}

WINAPI_EXPORT BOOL GetProfilesDirectoryW(uint16_t *lpProfileDir, uint32_t *lpcchSize)
{
    const char *dir = "/home";
    uint32_t len = (uint32_t)strlen(dir) + 1;

    if (!lpcchSize) return FALSE;
    if (!lpProfileDir || *lpcchSize < len) {
        *lpcchSize = len;
        return FALSE;
    }
    for (uint32_t i = 0; i < len; i++)
        lpProfileDir[i] = (uint16_t)(uint8_t)dir[i];
    *lpcchSize = len;
    return TRUE;
}

WINAPI_EXPORT BOOL GetAllUsersProfileDirectoryA(char *lpProfileDir, uint32_t *lpcchSize)
{
    const char *dir = "/var/lib/pe-loader/allusers";
    uint32_t len = (uint32_t)strlen(dir) + 1;
    if (!lpcchSize) return FALSE;
    if (!lpProfileDir || *lpcchSize < len) {
        *lpcchSize = len;
        return FALSE;
    }
    strncpy(lpProfileDir, dir, *lpcchSize);
    lpProfileDir[*lpcchSize - 1] = '\0';
    *lpcchSize = len;
    return TRUE;
}

WINAPI_EXPORT BOOL GetAllUsersProfileDirectoryW(uint16_t *lpProfileDir, uint32_t *lpcchSize)
{
    const char *dir = "/var/lib/pe-loader/allusers";
    uint32_t len = (uint32_t)strlen(dir) + 1;
    if (!lpcchSize) return FALSE;
    if (!lpProfileDir || *lpcchSize < len) {
        *lpcchSize = len;
        return FALSE;
    }
    for (uint32_t i = 0; i < len; i++)
        lpProfileDir[i] = (uint16_t)(uint8_t)dir[i];
    *lpcchSize = len;
    return TRUE;
}

WINAPI_EXPORT BOOL GetDefaultUserProfileDirectoryA(char *lpProfileDir, uint32_t *lpcchSize)
{
    const char *dir = "/etc/skel";
    uint32_t len = (uint32_t)strlen(dir) + 1;
    if (!lpcchSize) return FALSE;
    if (!lpProfileDir || *lpcchSize < len) {
        *lpcchSize = len;
        return FALSE;
    }
    strncpy(lpProfileDir, dir, *lpcchSize);
    lpProfileDir[*lpcchSize - 1] = '\0';
    *lpcchSize = len;
    return TRUE;
}

WINAPI_EXPORT BOOL GetDefaultUserProfileDirectoryW(uint16_t *lpProfileDir, uint32_t *lpcchSize)
{
    const char *dir = "/etc/skel";
    uint32_t len = (uint32_t)strlen(dir) + 1;
    if (!lpcchSize) return FALSE;
    if (!lpProfileDir || *lpcchSize < len) {
        *lpcchSize = len;
        return FALSE;
    }
    for (uint32_t i = 0; i < len; i++)
        lpProfileDir[i] = (uint16_t)(uint8_t)dir[i];
    *lpcchSize = len;
    return TRUE;
}

/* ========== Environment Block ========== */

WINAPI_EXPORT BOOL CreateEnvironmentBlock(void **lpEnvironment, void *hToken, BOOL bInherit)
{
    (void)hToken; (void)bInherit;
    if (!lpEnvironment) return FALSE;

    /* Build a Unicode environment block: VAR=VALUE\0VAR=VALUE\0\0 */
    size_t total_size = 2; /* Final double-NUL in wchars */
    for (char **env = environ; *env; env++)
        total_size += strlen(*env) + 1;

    uint16_t *block = calloc(total_size, sizeof(uint16_t));
    if (!block) return FALSE;

    uint16_t *p = block;
    for (char **env = environ; *env; env++) {
        const char *s = *env;
        while (*s) *p++ = (uint16_t)(uint8_t)*s++;
        *p++ = 0;
    }
    *p = 0; /* Double-NUL terminator */

    *lpEnvironment = block;
    return TRUE;
}

WINAPI_EXPORT BOOL DestroyEnvironmentBlock(void *lpEnvironment)
{
    free(lpEnvironment);
    return TRUE;
}

/* ========== User Profile Load/Unload ========== */

WINAPI_EXPORT BOOL LoadUserProfileA(void *hToken, void *lpProfileInfo)
{
    (void)hToken; (void)lpProfileInfo;
    return TRUE;
}

WINAPI_EXPORT BOOL LoadUserProfileW(void *hToken, void *lpProfileInfo)
{
    (void)hToken; (void)lpProfileInfo;
    return TRUE;
}

WINAPI_EXPORT BOOL UnloadUserProfile(void *hToken, void *hProfile)
{
    (void)hToken; (void)hProfile;
    return TRUE;
}

/* ========== App Container ========== */

WINAPI_EXPORT HRESULT GetAppContainerFolderPath(const void *pszAppContainerSid,
                                                  void **ppszPath)
{
    (void)pszAppContainerSid;
    if (ppszPath) *ppszPath = NULL;
    return 0x80004001; /* E_NOTIMPL */
}

/* ========== Misc ========== */

WINAPI_EXPORT BOOL ExpandEnvironmentStringsForUserA(void *hToken, const char *lpSrc,
                                                      char *lpDest, uint32_t dwSize)
{
    (void)hToken;
    if (!lpSrc || !lpDest || dwSize == 0) return FALSE;
    /* Simple: just copy, expanding %USERPROFILE% etc. */
    const char *home = get_home_dir();

    /* Basic %USERPROFILE% expansion */
    const char *found = strstr(lpSrc, "%USERPROFILE%");
    if (found) {
        size_t prefix_len = found - lpSrc;
        size_t home_len = strlen(home);
        size_t suffix_len = strlen(found + 13);
        if (prefix_len + home_len + suffix_len + 1 > dwSize) return FALSE;
        memcpy(lpDest, lpSrc, prefix_len);
        memcpy(lpDest + prefix_len, home, home_len);
        memcpy(lpDest + prefix_len + home_len, found + 13, suffix_len + 1);
        return TRUE;
    }

    strncpy(lpDest, lpSrc, dwSize - 1);
    lpDest[dwSize - 1] = '\0';
    return TRUE;
}

WINAPI_EXPORT BOOL ExpandEnvironmentStringsForUserW(void *hToken, const void *lpSrc,
                                                      void *lpDest, uint32_t dwSize)
{
    (void)hToken;
    const uint16_t *src = (const uint16_t *)lpSrc;
    uint16_t *dst = (uint16_t *)lpDest;
    if (!src || !dst || dwSize == 0) return FALSE;

    /* Convert wide source to narrow for expansion */
    size_t wlen = 0;
    while (src[wlen]) wlen++;
    char *narrow_src = (char *)malloc(wlen + 1);
    if (!narrow_src) return FALSE;
    for (size_t i = 0; i < wlen; i++)
        narrow_src[i] = (char)(src[i] & 0xFF);
    narrow_src[wlen] = '\0';

    /* Expand using narrow logic */
    char *narrow_dst = (char *)malloc(dwSize);
    if (!narrow_dst) { free(narrow_src); return FALSE; }

    const char *home = get_home_dir();
    const char *found = strstr(narrow_src, "%USERPROFILE%");
    if (found) {
        size_t prefix_len = found - narrow_src;
        size_t home_len = strlen(home);
        size_t suffix_len = strlen(found + 13);
        if (prefix_len + home_len + suffix_len + 1 > dwSize) {
            free(narrow_src); free(narrow_dst); return FALSE;
        }
        memcpy(narrow_dst, narrow_src, prefix_len);
        memcpy(narrow_dst + prefix_len, home, home_len);
        memcpy(narrow_dst + prefix_len + home_len, found + 13, suffix_len + 1);
    } else {
        strncpy(narrow_dst, narrow_src, dwSize - 1);
        narrow_dst[dwSize - 1] = '\0';
    }

    /* Convert result back to wide */
    size_t rlen = strlen(narrow_dst);
    if (rlen + 1 > dwSize) { free(narrow_src); free(narrow_dst); return FALSE; }
    for (size_t i = 0; i <= rlen; i++)
        dst[i] = (uint16_t)(unsigned char)narrow_dst[i];

    free(narrow_src);
    free(narrow_dst);
    return TRUE;
}
