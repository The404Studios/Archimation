/*
 * kernel32_resource.c - PE resource loading functions
 *
 * Parses the .rsrc section of loaded PE images to implement:
 *   FindResourceA/W, LoadResource, SizeofResource, LockResource,
 *   LoadStringA/W, FreeResource
 *
 * The PE resource directory is a three-level tree:
 *   Level 1: Resource type (RT_STRING, RT_ICON, RT_DIALOG, etc.)
 *   Level 2: Resource name/ID
 *   Level 3: Language ID
 *   Leaf:    Resource data entry (RVA + size)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <dlfcn.h>
#include <pthread.h>

#include "common/dll_common.h"

/* Resource types */
#define RT_CURSOR        1
#define RT_BITMAP        2
#define RT_ICON          3
#define RT_MENU          4
#define RT_DIALOG        5
#define RT_STRING        6
#define RT_FONTDIR       7
#define RT_FONT          8
#define RT_ACCELERATOR   9
#define RT_RCDATA        10
#define RT_MESSAGETABLE  11
#define RT_GROUP_CURSOR  12
#define RT_GROUP_ICON    14
#define RT_VERSION       16
#define RT_MANIFEST      24

/* HRSRC is an opaque handle to a found resource */
typedef HANDLE HRSRC;
typedef HANDLE HGLOBAL;

/* ----------------------------------------------------------------
 * PE resource directory structures (on-disk / in-memory layout)
 * ---------------------------------------------------------------- */

#pragma pack(push, 1)

typedef struct {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    WORD  NumberOfNamedEntries;
    WORD  NumberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY;

typedef struct {
    union {
        struct {
            DWORD NameOffset   : 31;
            DWORD NameIsString : 1;
        };
        DWORD Name;
        WORD  Id;
    };
    union {
        DWORD OffsetToData;
        struct {
            DWORD OffsetToDirectory : 31;
            DWORD DataIsDirectory   : 1;
        };
    };
} IMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef struct {
    DWORD OffsetToData;  /* RVA of the resource data */
    DWORD Size;
    DWORD CodePage;
    DWORD Reserved;
} IMAGE_RESOURCE_DATA_ENTRY;

#pragma pack(pop)

/* ----------------------------------------------------------------
 * Resource context - cached per-module resource directory info
 * ---------------------------------------------------------------- */

typedef struct {
    void  *rsrc_base;     /* Pointer to start of .rsrc section in memory */
    DWORD  rsrc_rva;      /* RVA of .rsrc section */
    void  *image_base;    /* Module base address */
    DWORD  rsrc_size;     /* Size of resource section */
} rsrc_context_t;

/* Internal resource handle structure */
typedef struct {
    const IMAGE_RESOURCE_DATA_ENTRY *data_entry;
    void *image_base;
} rsrc_handle_t;

#define MAX_RSRC_HANDLES 256
static rsrc_handle_t g_rsrc_handles[MAX_RSRC_HANDLES];
static int g_rsrc_handle_count = 0;
static pthread_mutex_t g_rsrc_lock = PTHREAD_MUTEX_INITIALIZER;

/* ----------------------------------------------------------------
 * Get resource directory from module
 * ---------------------------------------------------------------- */

/* Forward declare - implemented in kernel32_module.c or loader */
extern void *get_module_base(HMODULE hModule);

static int get_rsrc_context(HMODULE hModule, rsrc_context_t *ctx)
{
    /* Get the actual base address */
    void *base = hModule;
    if (!base || base == INVALID_HANDLE_VALUE) {
        /* NULL hModule = main executable - use a sentinel approach */
        /* Try reading from the PEB */
        extern void *env_get_peb(void);
        void *peb = env_get_peb();
        if (peb) {
            /* ImageBaseAddress is at offset 0x10 in FULL_PEB */
            base = *(void **)((char *)peb + 0x10);
        }
    }

    if (!base)
        return -1;

    ctx->image_base = base;

    /* Parse PE headers to find resource directory */
    unsigned char *p = (unsigned char *)base;

    /* Check MZ magic */
    if (p[0] != 'M' || p[1] != 'Z')
        return -1;

    /* Get e_lfanew (offset to PE signature) */
    int32_t e_lfanew = *(int32_t *)(p + 0x3C);
    if (e_lfanew < 0 || e_lfanew > 0x10000)
        return -1;

    unsigned char *pe_sig = p + e_lfanew;
    if (pe_sig[0] != 'P' || pe_sig[1] != 'E' || pe_sig[2] != 0 || pe_sig[3] != 0)
        return -1;

    /* COFF header follows PE signature */
    unsigned char *coff = pe_sig + 4;
    uint16_t opt_hdr_size = *(uint16_t *)(coff + 16);

    /* Optional header */
    unsigned char *opt = coff + 20;
    uint16_t magic = *(uint16_t *)opt;

    /* Get resource data directory entry */
    DWORD rsrc_rva = 0, rsrc_size = 0;

    if (magic == 0x020B) {
        /* PE32+ */
        /* Data directory starts at offset 112 in the optional header */
        /* Resource directory is index 2 */
        if (opt_hdr_size >= 112 + (3 * 8)) {
            uint32_t *dd = (uint32_t *)(opt + 112 + 2 * 8);
            rsrc_rva = dd[0];
            rsrc_size = dd[1];
        }
    } else if (magic == 0x010B) {
        /* PE32 */
        if (opt_hdr_size >= 96 + (3 * 8)) {
            uint32_t *dd = (uint32_t *)(opt + 96 + 2 * 8);
            rsrc_rva = dd[0];
            rsrc_size = dd[1];
        }
    } else {
        return -1;
    }

    if (rsrc_rva == 0 || rsrc_size == 0)
        return -1; /* No resource section */

    ctx->rsrc_base = p + rsrc_rva;
    ctx->rsrc_rva = rsrc_rva;
    ctx->rsrc_size = rsrc_size;

    return 0;
}

/* ----------------------------------------------------------------
 * Resource directory traversal helpers
 * ---------------------------------------------------------------- */

/*
 * Find a directory entry by ID or name at a given directory level.
 * Returns pointer to the entry, or NULL.
 */
static const IMAGE_RESOURCE_DIRECTORY_ENTRY *find_entry_by_id(
    const IMAGE_RESOURCE_DIRECTORY *dir,
    const void *rsrc_base,
    WORD id)
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *entries =
        (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);

    int total = dir->NumberOfNamedEntries + dir->NumberOfIdEntries;

    /* ID entries come after named entries */
    for (int i = dir->NumberOfNamedEntries; i < total; i++) {
        if (!entries[i].NameIsString && entries[i].Id == id)
            return &entries[i];
    }

    (void)rsrc_base;
    return NULL;
}

/*
 * Find a directory entry by name string at a given directory level.
 */
static const IMAGE_RESOURCE_DIRECTORY_ENTRY *find_entry_by_name(
    const IMAGE_RESOURCE_DIRECTORY *dir,
    const void *rsrc_base,
    LPCWSTR name)
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *entries =
        (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);

    for (int i = 0; i < dir->NumberOfNamedEntries; i++) {
        if (!entries[i].NameIsString)
            continue;

        /* Get the name string (length-prefixed UTF-16) */
        const unsigned char *name_ptr =
            (const unsigned char *)rsrc_base + entries[i].NameOffset;
        uint16_t name_len = *(const uint16_t *)name_ptr;
        const WCHAR *name_str = (const WCHAR *)(name_ptr + 2);

        /* Compare */
        int match = 1;
        int j;
        for (j = 0; j < name_len && name[j]; j++) {
            if (name_str[j] != name[j]) {
                match = 0;
                break;
            }
        }
        if (match && j == name_len && name[j] == 0)
            return &entries[i];
    }

    return NULL;
}

/*
 * Get the first entry at a directory level (for language fallback).
 */
static const IMAGE_RESOURCE_DIRECTORY_ENTRY *get_first_entry(
    const IMAGE_RESOURCE_DIRECTORY *dir)
{
    int total = dir->NumberOfNamedEntries + dir->NumberOfIdEntries;
    if (total == 0)
        return NULL;

    return (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);
}

/* ----------------------------------------------------------------
 * FindResourceA / FindResourceW
 * ---------------------------------------------------------------- */

/*
 * IS_INTRESOURCE: check if a pointer is actually an integer resource ID
 */
#define IS_INTRESOURCE(p) (((ULONG_PTR)(p) >> 16) == 0)
#define MAKEINTRESOURCE(i) ((LPSTR)(ULONG_PTR)(WORD)(i))

WINAPI_EXPORT HRSRC FindResourceA(HMODULE hModule, LPCSTR lpName, LPCSTR lpType)
{
    rsrc_context_t ctx;
    if (get_rsrc_context(hModule, &ctx) < 0) {
        set_last_error(ERROR_INVALID_HANDLE);
        return NULL;
    }

    const IMAGE_RESOURCE_DIRECTORY *root =
        (const IMAGE_RESOURCE_DIRECTORY *)ctx.rsrc_base;

    /* Level 1: Find type */
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *type_entry;
    if (IS_INTRESOURCE(lpType)) {
        type_entry = find_entry_by_id(root, ctx.rsrc_base, (WORD)(ULONG_PTR)lpType);
    } else {
        /* Convert ANSI name to wide for comparison */
        WCHAR wtype[256];
        int i;
        for (i = 0; lpType[i] && i < 255; i++)
            wtype[i] = (WCHAR)(unsigned char)lpType[i];
        wtype[i] = 0;
        type_entry = find_entry_by_name(root, ctx.rsrc_base, wtype);
    }

    if (!type_entry || !type_entry->DataIsDirectory) {
        set_last_error(ERROR_INVALID_DATA);
        return NULL;
    }

    /* Level 2: Find name/ID */
    const IMAGE_RESOURCE_DIRECTORY *name_dir =
        (const IMAGE_RESOURCE_DIRECTORY *)
        ((const char *)ctx.rsrc_base + type_entry->OffsetToDirectory);

    const IMAGE_RESOURCE_DIRECTORY_ENTRY *name_entry;
    if (IS_INTRESOURCE(lpName)) {
        name_entry = find_entry_by_id(name_dir, ctx.rsrc_base, (WORD)(ULONG_PTR)lpName);
    } else {
        WCHAR wname[256];
        int i;
        for (i = 0; lpName[i] && i < 255; i++)
            wname[i] = (WCHAR)(unsigned char)lpName[i];
        wname[i] = 0;
        name_entry = find_entry_by_name(name_dir, ctx.rsrc_base, wname);
    }

    if (!name_entry || !name_entry->DataIsDirectory) {
        set_last_error(ERROR_INVALID_DATA);
        return NULL;
    }

    /* Level 3: Language - pick first available (language-neutral fallback) */
    const IMAGE_RESOURCE_DIRECTORY *lang_dir =
        (const IMAGE_RESOURCE_DIRECTORY *)
        ((const char *)ctx.rsrc_base + name_entry->OffsetToDirectory);

    const IMAGE_RESOURCE_DIRECTORY_ENTRY *lang_entry = get_first_entry(lang_dir);
    if (!lang_entry || lang_entry->DataIsDirectory) {
        set_last_error(ERROR_INVALID_DATA);
        return NULL;
    }

    /* Get the data entry leaf */
    const IMAGE_RESOURCE_DATA_ENTRY *data_entry =
        (const IMAGE_RESOURCE_DATA_ENTRY *)
        ((const char *)ctx.rsrc_base + lang_entry->OffsetToData);

    /* Allocate a handle (with recycling of freed slots) */
    pthread_mutex_lock(&g_rsrc_lock);
    int slot = -1;
    for (int i = 0; i < g_rsrc_handle_count; i++) {
        if (g_rsrc_handles[i].data_entry == NULL) { slot = i; break; }
    }
    if (slot < 0) {
        if (g_rsrc_handle_count >= MAX_RSRC_HANDLES) {
            /* Table exhausted — refuse rather than recycling an in-use slot
             * (the existing handle owner would see a stale/UAF pointer). */
            pthread_mutex_unlock(&g_rsrc_lock);
            set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }
        slot = g_rsrc_handle_count++;
    }

    rsrc_handle_t *rh = &g_rsrc_handles[slot];
    rh->data_entry = data_entry;
    rh->image_base = ctx.image_base;
    pthread_mutex_unlock(&g_rsrc_lock);

    return (HRSRC)rh;
}

WINAPI_EXPORT HRSRC FindResourceW(HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType)
{
    /* Convert wide strings to ANSI and delegate */
    char name_a[256] = {0};
    char type_a[256] = {0};
    LPCSTR pName;
    LPCSTR pType;

    if (IS_INTRESOURCE(lpName)) {
        pName = (LPCSTR)lpName;
    } else {
        for (int i = 0; i < 255 && lpName[i]; i++)
            name_a[i] = (char)(lpName[i] & 0x7F);
        pName = name_a;
    }

    if (IS_INTRESOURCE(lpType)) {
        pType = (LPCSTR)lpType;
    } else {
        for (int i = 0; i < 255 && lpType[i]; i++)
            type_a[i] = (char)(lpType[i] & 0x7F);
        pType = type_a;
    }

    return FindResourceA(hModule, pName, pType);
}

WINAPI_EXPORT HRSRC FindResourceExA(HMODULE hModule, LPCSTR lpType, LPCSTR lpName, WORD wLanguage)
{
    (void)wLanguage;
    return FindResourceA(hModule, lpName, lpType);
}

WINAPI_EXPORT HRSRC FindResourceExW(HMODULE hModule, LPCWSTR lpType, LPCWSTR lpName, WORD wLanguage)
{
    (void)wLanguage;
    return FindResourceW(hModule, lpName, lpType);
}

/* ----------------------------------------------------------------
 * LoadResource / LockResource / SizeofResource / FreeResource
 * ---------------------------------------------------------------- */

WINAPI_EXPORT HGLOBAL LoadResource(HMODULE hModule, HRSRC hResInfo)
{
    (void)hModule;
    if (!hResInfo) {
        set_last_error(ERROR_INVALID_HANDLE);
        return NULL;
    }
    /* The "resource handle" is the same as the HRSRC for us */
    return (HGLOBAL)hResInfo;
}

WINAPI_EXPORT LPVOID LockResource(HGLOBAL hResData)
{
    if (!hResData) return NULL;

    rsrc_handle_t *rh = (rsrc_handle_t *)hResData;
    if (!rh->data_entry || !rh->image_base)
        return NULL;

    /* OffsetToData is an RVA from the image base */
    return (LPVOID)((unsigned char *)rh->image_base + rh->data_entry->OffsetToData);
}

WINAPI_EXPORT DWORD SizeofResource(HMODULE hModule, HRSRC hResInfo)
{
    (void)hModule;
    if (!hResInfo) return 0;

    rsrc_handle_t *rh = (rsrc_handle_t *)hResInfo;
    if (!rh->data_entry)
        return 0;

    return rh->data_entry->Size;
}

WINAPI_EXPORT BOOL FreeResource(HGLOBAL hResData)
{
    if (!hResData)
        return FALSE;

    /* Mark the slot as free for recycling */
    rsrc_handle_t *rh = (rsrc_handle_t *)hResData;
    pthread_mutex_lock(&g_rsrc_lock);
    rh->data_entry = NULL;
    rh->image_base = NULL;
    pthread_mutex_unlock(&g_rsrc_lock);

    /* Resources are part of the mapped image - nothing else to free */
    return TRUE;
}

/* ----------------------------------------------------------------
 * LoadStringA / LoadStringW - forwarded to canonical user32
 *
 * Many Windows executables import these from kernel32.dll even though
 * the canonical implementation lives in user32.dll.  We forward at
 * runtime via dlsym so that the real user32 code is used.
 * ---------------------------------------------------------------- */

WINAPI_EXPORT int WINAPI LoadStringA(HINSTANCE hInstance, UINT uID,
                                      LPSTR lpBuffer, int cchBufferMax)
{
    typedef int (WINAPI *fn_t)(HINSTANCE, UINT, LPSTR, int);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        void *h = dlopen("libpe_user32.so", RTLD_LAZY);
        if (h) real_fn = (fn_t)dlsym(h, "LoadStringA");
    }
    return real_fn ? real_fn(hInstance, uID, lpBuffer, cchBufferMax) : 0;
}

WINAPI_EXPORT int WINAPI LoadStringW(HINSTANCE hInstance, UINT uID,
                                      LPWSTR lpBuffer, int cchBufferMax)
{
    typedef int (WINAPI *fn_t)(HINSTANCE, UINT, LPWSTR, int);
    static fn_t real_fn = NULL;
    if (!real_fn) {
        void *h = dlopen("libpe_user32.so", RTLD_LAZY);
        if (h) real_fn = (fn_t)dlsym(h, "LoadStringW");
    }
    return real_fn ? real_fn(hInstance, uID, lpBuffer, cchBufferMax) : 0;
}

/* ----------------------------------------------------------------
 * EnumResourceTypes / EnumResourceNames stubs
 * ---------------------------------------------------------------- */

typedef BOOL (*ENUMRESTYPEPROCA)(HMODULE, LPSTR, LONG_PTR);
typedef BOOL (*ENUMRESNAMEPROCW)(HMODULE, LPCWSTR, LPWSTR, LONG_PTR);

WINAPI_EXPORT BOOL EnumResourceTypesA(HMODULE hModule, ENUMRESTYPEPROCA lpEnumFunc, LONG_PTR lParam)
{
    (void)hModule;
    (void)lpEnumFunc;
    (void)lParam;
    set_last_error(ERROR_INVALID_FUNCTION);
    return FALSE;
}

WINAPI_EXPORT BOOL EnumResourceNamesW(HMODULE hModule, LPCWSTR lpType,
                                       ENUMRESNAMEPROCW lpEnumFunc, LONG_PTR lParam)
{
    (void)hModule;
    (void)lpType;
    (void)lpEnumFunc;
    (void)lParam;
    set_last_error(ERROR_INVALID_FUNCTION);
    return FALSE;
}
