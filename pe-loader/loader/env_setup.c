/*
 * env_setup.c - PEB/TEB emulation for Windows PE executables
 *
 * Sets up the Process Environment Block (PEB) and Thread Environment
 * Block (TEB) that Windows executables expect to find. Many CRT
 * initialization routines read fields from PEB/TEB.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <asm/prctl.h>

#include "pe/pe_header.h"
#include "win32/windef.h"
#include "win32/winnt.h"

/* RTL_USER_PROCESS_PARAMETERS (simplified) */
typedef struct {
    ULONG  MaximumLength;
    ULONG  Length;
    ULONG  Flags;
    ULONG  DebugFlags;
    PVOID  ConsoleHandle;
    ULONG  ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    /* CurrentDirectory */
    struct {
        UNICODE_STRING DosPath;
        HANDLE         Handle;
    } CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID  Environment;
    ULONG  StartingX;
    ULONG  StartingY;
    ULONG  CountX;
    ULONG  CountY;
    ULONG  CountCharsX;
    ULONG  CountCharsY;
    ULONG  FillAttribute;
    ULONG  WindowFlags;
    ULONG  ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
} RTL_USER_PROCESS_PARAMETERS;

/* LIST_ENTRY - doubly linked list node (Windows-compatible layout) */
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

/* PEB_LDR_DATA using proper LIST_ENTRY */
typedef struct {
    ULONG      Length;
    BOOL       Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA;

/*
 * LDR_DATA_TABLE_ENTRY - per-module entry in the PEB LDR lists.
 *
 * Windows apps (and many CRT init routines) iterate these lists
 * to enumerate loaded modules, find base addresses, etc.
 *
 * The list pointers at different offsets point into different
 * positions within this structure:
 *   InLoadOrderLinks           - offset 0x00
 *   InMemoryOrderLinks         - offset 0x10
 *   InInitializationOrderLinks - offset 0x20
 */
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY      InLoadOrderLinks;               /* 0x00 */
    LIST_ENTRY      InMemoryOrderLinks;              /* 0x10 */
    LIST_ENTRY      InInitializationOrderLinks;      /* 0x20 */
    PVOID           DllBase;                         /* 0x30 */
    PVOID           EntryPoint;                      /* 0x38 */
    ULONG           SizeOfImage;                     /* 0x40 */
    BYTE            _pad0[4];                        /* 0x44 */
    UNICODE_STRING  FullDllName;                     /* 0x48 */
    UNICODE_STRING  BaseDllName;                     /* 0x58 */
    ULONG           Flags;                           /* 0x68 */
    WORD            LoadCount;                       /* 0x6C */
    WORD            TlsIndex;                        /* 0x6E */
    LIST_ENTRY      HashLinks;                       /* 0x70 */
    ULONG           TimeDateStamp;                   /* 0x80 */
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

/* LDR flags */
#define LDR_ENTRY_PROCESSED     0x00004000
#define LDR_ENTRY_IMAGE_DLL     0x00000004
#define LDR_ENTRY_LOAD_IN_PROGRESS 0x00001000

/* Maximum tracked modules */
#define MAX_LDR_MODULES 256
static LDR_DATA_TABLE_ENTRY g_ldr_entries[MAX_LDR_MODULES];
static int g_ldr_entry_count = 0;

/* Full PEB structure */
typedef struct {
    BYTE                InheritedAddressSpace;      /* 0x000 */
    BYTE                ReadImageFileExecOptions;    /* 0x001 */
    BYTE                BeingDebugged;               /* 0x002 */
    BYTE                BitField;                    /* 0x003 */
    BYTE                Padding0[4];                 /* 0x004 */
    PVOID               Mutant;                      /* 0x008 */
    PVOID               ImageBaseAddress;            /* 0x010 */
    PEB_LDR_DATA       *Ldr;                        /* 0x018 */
    RTL_USER_PROCESS_PARAMETERS *ProcessParameters; /* 0x020 */
    PVOID               SubSystemData;               /* 0x028 */
    PVOID               ProcessHeap;                 /* 0x030 */
    PVOID               FastPebLock;                 /* 0x038 */
    PVOID               AtlThunkSListPtr;            /* 0x040 */
    PVOID               IFEOKey;                     /* 0x048 */
    ULONG               CrossProcessFlags;           /* 0x050 */
    BYTE                Padding1[4];                 /* 0x054 */
    PVOID               KernelCallbackTable;         /* 0x058 */
    ULONG               SystemReserved;              /* 0x060 */
    ULONG               AtlThunkSListPtr32;          /* 0x064 */
    PVOID               ApiSetMap;                    /* 0x068 */
    ULONG               TlsExpansionCounter;         /* 0x070 */
    BYTE                Padding2[4];                 /* 0x074 */
    PVOID               TlsBitmap;                   /* 0x078 */
    ULONG               TlsBitmapBits[2];            /* 0x080 */
    PVOID               ReadOnlySharedMemoryBase;    /* 0x088 */
    PVOID               SharedData;                  /* 0x090 */
    PVOID               ReadOnlyStaticServerData;    /* 0x098 */
    PVOID               AnsiCodePageData;            /* 0x0A0 */
    PVOID               OemCodePageData;             /* 0x0A8 */
    PVOID               UnicodeCaseTableData;        /* 0x0B0 */
    ULONG               NumberOfProcessors;          /* 0x0B8 */
    ULONG               NtGlobalFlag;                /* 0x0BC */
    LARGE_INTEGER        CriticalSectionTimeout;     /* 0x0C0 */
    SIZE_T              HeapSegmentReserve;           /* 0x0C8 */
    SIZE_T              HeapSegmentCommit;            /* 0x0D0 */
    SIZE_T              HeapDeCommitTotalFreeThreshold; /* 0x0D8 */
    SIZE_T              HeapDeCommitFreeBlockThreshold; /* 0x0E0 */
    ULONG               NumberOfHeaps;               /* 0x0E8 */
    ULONG               MaximumNumberOfHeaps;        /* 0x0EC */
    PVOID               ProcessHeaps;                /* 0x0F0 */
    /* ... many more fields ... */
    BYTE                _padding[0x400];             /* Pad to safe size */
} FULL_PEB;

/* Full TEB structure */
typedef struct {
    /* NT_TIB */
    PVOID ExceptionList;          /* 0x000 */
    PVOID StackBase;              /* 0x008 */
    PVOID StackLimit;             /* 0x010 */
    PVOID SubSystemTib;           /* 0x018 */
    PVOID FiberData;              /* 0x020 */
    PVOID ArbitraryUserPointer;   /* 0x028 */
    PVOID Self;                   /* 0x030 - Points to this TEB */
    /* End of NT_TIB */
    PVOID EnvironmentPointer;     /* 0x038 */
    struct {
        PVOID UniqueProcess;      /* 0x040 */
        PVOID UniqueThread;       /* 0x048 */
    } ClientId;
    PVOID ActiveRpcHandle;        /* 0x050 */
    PVOID ThreadLocalStoragePointer; /* 0x058 */
    FULL_PEB *ProcessEnvironmentBlock; /* 0x060 */
    ULONG LastErrorValue;         /* 0x068 */
    BYTE  _padding[0x1800];       /* Pad to safe size */
} FULL_TEB;

/* Thread-local TEB storage */
static __thread FULL_TEB *tls_teb = NULL;

/*
 * TLS slot array — the Windows-compatible TLS directory.
 * TEB->ThreadLocalStoragePointer points to this array.
 * Each slot holds a pointer to the TLS data block for that TLS index.
 * TLS_MINIMUM_AVAILABLE = 64 on Windows.
 */
#define TLS_MINIMUM_AVAILABLE 64
#define TLS_MAX_SLOTS 256
static __thread void *g_tls_slots[TLS_MAX_SLOTS];

/* Global PEB (shared across all threads) */
static FULL_PEB *g_peb = NULL;
static PEB_LDR_DATA *g_ldr = NULL;
static RTL_USER_PROCESS_PARAMETERS *g_params = NULL;

/* Wide string helper: convert ASCII to UTF-16LE */
static WCHAR *ascii_to_wide(const char *str)
{
    if (!str) return NULL;
    size_t len = strlen(str);
    WCHAR *wide = calloc(len + 1, sizeof(WCHAR));
    if (!wide) return NULL;
    for (size_t i = 0; i < len; i++)
        wide[i] = (WCHAR)(unsigned char)str[i];
    return wide;
}

static void init_unicode_string(UNICODE_STRING *us, const char *ascii)
{
    WCHAR *wide = ascii_to_wide(ascii);
    if (wide) {
        size_t len = 0;
        while (wide[len]) len++;
        us->Length = (USHORT)(len * sizeof(WCHAR));
        us->MaximumLength = us->Length + sizeof(WCHAR);
        us->Buffer = wide;
    } else {
        us->Length = 0;
        us->MaximumLength = 0;
        us->Buffer = NULL;
    }
}

/*
 * Set the GS register base to point at the TEB so that
 * mov rax, gs:[0x30] resolves to TEB->Self (i.e. the TEB pointer).
 * This is critical for Windows binaries that access TEB via GS segment.
 */
static int set_gs_base(FULL_TEB *teb)
{
    return syscall(SYS_arch_prctl, ARCH_SET_GS, (unsigned long)teb);
}

/* Forward declaration */
int env_setup_thread(void);

int env_setup_init(void *image_base, const char *image_path, const char *command_line)
{
    /* Allocate PEB */
    g_peb = mmap(NULL, sizeof(FULL_PEB),
                 PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_peb == MAP_FAILED) return -1;
    memset(g_peb, 0, sizeof(FULL_PEB));

    /* Allocate LDR data */
    g_ldr = calloc(1, sizeof(PEB_LDR_DATA));
    if (!g_ldr) return -1;
    g_ldr->Length = sizeof(PEB_LDR_DATA);
    g_ldr->Initialized = TRUE;
    /* Initialize empty circular lists */
    g_ldr->InLoadOrderModuleList.Flink = &g_ldr->InLoadOrderModuleList;
    g_ldr->InLoadOrderModuleList.Blink = &g_ldr->InLoadOrderModuleList;
    g_ldr->InMemoryOrderModuleList.Flink = &g_ldr->InMemoryOrderModuleList;
    g_ldr->InMemoryOrderModuleList.Blink = &g_ldr->InMemoryOrderModuleList;
    g_ldr->InInitializationOrderModuleList.Flink = &g_ldr->InInitializationOrderModuleList;
    g_ldr->InInitializationOrderModuleList.Blink = &g_ldr->InInitializationOrderModuleList;

    /* Reset module tracking */
    g_ldr_entry_count = 0;

    /* Allocate process parameters */
    g_params = calloc(1, sizeof(RTL_USER_PROCESS_PARAMETERS));
    if (!g_params) return -1;

    g_params->MaximumLength = sizeof(RTL_USER_PROCESS_PARAMETERS);
    g_params->Length = sizeof(RTL_USER_PROCESS_PARAMETERS);

    /* Set up paths and command line */
    if (image_path)
        init_unicode_string(&g_params->ImagePathName, image_path);
    if (command_line)
        init_unicode_string(&g_params->CommandLine, command_line);

    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd)))
        init_unicode_string(&g_params->CurrentDirectory.DosPath, cwd);

    /* Fill PEB fields */
    g_peb->ImageBaseAddress = image_base;
    g_peb->Ldr = g_ldr;
    g_peb->ProcessParameters = g_params;
    g_peb->BeingDebugged = 0;
    g_peb->NtGlobalFlag = 0; /* No debug flags */

    /* ProcessHeap is wired at runtime by GetProcessHeap() in kernel32.
     * Set a marker that kernel32 will replace with the real heap handle.
     * Many CRT init routines read PEB->ProcessHeap, so we need it early. */
    g_peb->ProcessHeap = NULL; /* Will be set by env_wire_process_heap() */

    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    g_peb->NumberOfProcessors = (ULONG)(nproc > 0 ? nproc : 1);

    /*
     * Populate standard Windows environment variables.
     * GetEnvironmentVariableA/W uses getenv(), so we must seed the
     * process environment with the vars that Windows apps expect.
     * Uses setenv(..., 0) to not overwrite if already set (e.g. by
     * pe-run-game or the user's shell).
     */
    {
        const char *home = getenv("HOME");
        const char *user = getenv("USER");
        if (!home) home = "/tmp";
        if (!user) user = "user";

        char buf[4096];

        /* Core system paths */
        setenv("SystemRoot",    "C:\\Windows", 0);
        setenv("windir",        "C:\\Windows", 0);
        setenv("SystemDrive",   "C:", 0);
        setenv("ComSpec",       "C:\\Windows\\system32\\cmd.exe", 0);
        setenv("OS",            "Windows_NT", 0);

        /* Temp */
        snprintf(buf, sizeof(buf), "C:\\Users\\%s\\AppData\\Local\\Temp", user);
        setenv("TEMP", buf, 0);
        setenv("TMP",  buf, 0);

        /* User profile paths */
        snprintf(buf, sizeof(buf), "C:\\Users\\%s", user);
        setenv("USERPROFILE", buf, 0);
        setenv("HOMEPATH",    buf + 2, 0); /* strip "C:" */
        setenv("HOMEDRIVE",   "C:", 0);

        snprintf(buf, sizeof(buf), "C:\\Users\\%s\\AppData\\Roaming", user);
        setenv("APPDATA", buf, 0);

        snprintf(buf, sizeof(buf), "C:\\Users\\%s\\AppData\\Local", user);
        setenv("LOCALAPPDATA", buf, 0);

        /* Program Files */
        setenv("ProgramFiles",       "C:\\Program Files", 0);
        setenv("ProgramFiles(x86)",  "C:\\Program Files (x86)", 0);
        setenv("ProgramW6432",       "C:\\Program Files", 0);
        setenv("CommonProgramFiles", "C:\\Program Files\\Common Files", 0);
        setenv("CommonProgramW6432", "C:\\Program Files\\Common Files", 0);

        /* Machine identity */
        char hostname[256] = "ARCHLINUX";
        gethostname(hostname, sizeof(hostname));
        setenv("COMPUTERNAME", hostname, 0);
        setenv("USERNAME",     user, 0);
        setenv("USERDOMAIN",   hostname, 0);

        /* System path */
        setenv("Path",
               "C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;"
               "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\", 0);

        /* Processor info */
        char nproc_str[16];
        snprintf(nproc_str, sizeof(nproc_str), "%ld", nproc > 0 ? nproc : 1);
        setenv("NUMBER_OF_PROCESSORS",  nproc_str, 0);
        setenv("PROCESSOR_ARCHITECTURE","AMD64", 0);
    }

    /* Create TEB for main thread */
    return env_setup_thread();
}

int env_setup_thread(void)
{
    if (tls_teb)
        return 0; /* Already set up */

    FULL_TEB *teb = mmap(NULL, sizeof(FULL_TEB),
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (teb == MAP_FAILED) return -1;
    memset(teb, 0, sizeof(FULL_TEB));

    teb->Self = teb;
    teb->ProcessEnvironmentBlock = g_peb;
    teb->ClientId.UniqueProcess = (PVOID)(uintptr_t)getpid();
    teb->ClientId.UniqueThread = (PVOID)(uintptr_t)pthread_self();

    /* Wire the TLS slot array — this is what gs:0x58 returns */
    memset(g_tls_slots, 0, sizeof(g_tls_slots));
    teb->ThreadLocalStoragePointer = g_tls_slots;

    /* Stack bounds (approximate) */
    pthread_attr_t attr;
    void *stack_addr = NULL;
    size_t stack_size = 0;
    if (pthread_getattr_np(pthread_self(), &attr) == 0) {
        pthread_attr_getstack(&attr, &stack_addr, &stack_size);
        pthread_attr_destroy(&attr);
    }
    teb->StackBase = (PVOID)((uintptr_t)stack_addr + stack_size);
    teb->StackLimit = stack_addr;

    tls_teb = teb;

    /* Set the GS segment register so gs:[0x30] -> TEB->Self -> TEB */
    if (set_gs_base(teb) != 0) {
        fprintf(stderr, "pe-compat: warning: arch_prctl(ARCH_SET_GS) failed, "
                "gs-based TEB access will not work\n");
    }

    return 0;
}

FULL_TEB *env_get_teb(void)
{
    if (!tls_teb)
        env_setup_thread();
    return tls_teb;
}

FULL_PEB *env_get_peb(void)
{
    return g_peb;
}

/*
 * Store a TLS data pointer in the TEB TLS slot array.
 * Called by pe_tls.c when allocating TLS data for a thread.
 * This ensures gs:0x58 → slot_array[index] → data works correctly.
 */
void env_tls_set_slot(DWORD index, void *data)
{
    if (index < TLS_MAX_SLOTS)
        g_tls_slots[index] = data;
    /* Also update TEB in case it was set up before slots were populated */
    if (tls_teb && !tls_teb->ThreadLocalStoragePointer)
        tls_teb->ThreadLocalStoragePointer = g_tls_slots;
}

void *env_tls_get_slot(DWORD index)
{
    if (index < TLS_MAX_SLOTS)
        return g_tls_slots[index];
    return NULL;
}

void env_set_last_error(DWORD error)
{
    if (tls_teb)
        tls_teb->LastErrorValue = error;
}

DWORD env_get_last_error(void)
{
    if (tls_teb)
        return tls_teb->LastErrorValue;
    return 0;
}

/*
 * Register a loaded module in the PEB LDR module lists.
 * Called by the loader after mapping each PE/DLL.
 *
 * @param base       Module base address
 * @param size       Size of the mapped image
 * @param entry_point  Entry point address (or NULL)
 * @param full_path  Full path to the module
 * @param name       Short name (e.g. "kernel32.dll")
 * @param is_dll     Non-zero if this is a DLL (not the main EXE)
 */
int env_register_module(void *base, ULONG size, void *entry_point,
                        const char *full_path, const char *name, int is_dll)
{
    if (!g_ldr || g_ldr_entry_count >= MAX_LDR_MODULES)
        return -1;

    LDR_DATA_TABLE_ENTRY *entry = &g_ldr_entries[g_ldr_entry_count];
    memset(entry, 0, sizeof(*entry));

    entry->DllBase = base;
    entry->EntryPoint = entry_point;
    entry->SizeOfImage = size;
    entry->LoadCount = 1;
    entry->TlsIndex = 0;
    entry->Flags = LDR_ENTRY_PROCESSED;
    if (is_dll)
        entry->Flags |= LDR_ENTRY_IMAGE_DLL;

    /* Set up names */
    if (full_path)
        init_unicode_string(&entry->FullDllName, full_path);
    if (name)
        init_unicode_string(&entry->BaseDllName, name);

    /* Insert into InLoadOrderModuleList (at tail) */
    LIST_ENTRY *load_tail = g_ldr->InLoadOrderModuleList.Blink;
    entry->InLoadOrderLinks.Flink = &g_ldr->InLoadOrderModuleList;
    entry->InLoadOrderLinks.Blink = load_tail;
    load_tail->Flink = &entry->InLoadOrderLinks;
    g_ldr->InLoadOrderModuleList.Blink = &entry->InLoadOrderLinks;

    /* Insert into InMemoryOrderModuleList (at tail) */
    LIST_ENTRY *mem_tail = g_ldr->InMemoryOrderModuleList.Blink;
    entry->InMemoryOrderLinks.Flink = &g_ldr->InMemoryOrderModuleList;
    entry->InMemoryOrderLinks.Blink = mem_tail;
    mem_tail->Flink = &entry->InMemoryOrderLinks;
    g_ldr->InMemoryOrderModuleList.Blink = &entry->InMemoryOrderLinks;

    /* Insert into InInitializationOrderModuleList (at tail) */
    LIST_ENTRY *init_tail = g_ldr->InInitializationOrderModuleList.Blink;
    entry->InInitializationOrderLinks.Flink = &g_ldr->InInitializationOrderModuleList;
    entry->InInitializationOrderLinks.Blink = init_tail;
    init_tail->Flink = &entry->InInitializationOrderLinks;
    g_ldr->InInitializationOrderModuleList.Blink = &entry->InInitializationOrderLinks;

    g_ldr_entry_count++;
    return 0;
}

/*
 * Find a module in the LDR list by base address.
 * Returns the LDR_DATA_TABLE_ENTRY pointer, or NULL.
 */
void *env_find_module_by_base(void *base)
{
    for (int i = 0; i < g_ldr_entry_count; i++) {
        if (g_ldr_entries[i].DllBase == base)
            return &g_ldr_entries[i];
    }
    return NULL;
}

/*
 * Find a module in the LDR list by name (case-insensitive).
 * Returns the DllBase, or NULL.
 */
void *env_find_module_by_name(const char *name)
{
    if (!name) return NULL;

    for (int i = 0; i < g_ldr_entry_count; i++) {
        UNICODE_STRING *base_name = &g_ldr_entries[i].BaseDllName;
        if (!base_name->Buffer)
            continue;

        /* Compare ASCII name against wide string */
        int match = 1;
        int j;
        for (j = 0; name[j] && j < base_name->Length / (int)sizeof(WCHAR); j++) {
            WCHAR wc = base_name->Buffer[j];
            char c1 = (wc < 128) ? (char)wc : '?';
            char c2 = name[j];
            /* Case-insensitive compare */
            if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
            if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
            if (c1 != c2) { match = 0; break; }
        }
        if (match && name[j] == '\0' && j == base_name->Length / (int)sizeof(WCHAR))
            return g_ldr_entries[i].DllBase;
    }
    return NULL;
}

/*
 * Wire PEB->ProcessHeap to a real heap handle.
 * Called by kernel32 initialization after the heap subsystem is ready.
 */
void env_wire_process_heap(void *heap_handle)
{
    if (g_peb && heap_handle)
        g_peb->ProcessHeap = heap_handle;
}

void env_cleanup(void)
{
    if (tls_teb) {
        munmap(tls_teb, sizeof(FULL_TEB));
        tls_teb = NULL;
    }

    if (g_params) {
        free(g_params->ImagePathName.Buffer);
        free(g_params->CommandLine.Buffer);
        free(g_params->CurrentDirectory.DosPath.Buffer);
        free(g_params);
        g_params = NULL;
    }

    free(g_ldr);
    g_ldr = NULL;

    if (g_peb) {
        munmap(g_peb, sizeof(FULL_PEB));
        g_peb = NULL;
    }
}
