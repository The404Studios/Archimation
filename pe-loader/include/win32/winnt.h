#ifndef WINNT_H
#define WINNT_H

#include "windef.h"

/* Generic access rights */
#define GENERIC_READ        0x80000000
#define GENERIC_WRITE       0x40000000
#define GENERIC_EXECUTE     0x20000000
#define GENERIC_ALL         0x10000000

/* Standard access rights */
#define DELETE              0x00010000
#define READ_CONTROL        0x00020000
#define WRITE_DAC           0x00040000
#define WRITE_OWNER         0x00080000
#define SYNCHRONIZE         0x00100000

/* File creation disposition */
#define CREATE_NEW          1
#define CREATE_ALWAYS       2
#define OPEN_EXISTING       3
#define OPEN_ALWAYS         4
#define TRUNCATE_EXISTING   5

/* File attributes */
#define FILE_ATTRIBUTE_READONLY     0x00000001
#define FILE_ATTRIBUTE_HIDDEN       0x00000002
#define FILE_ATTRIBUTE_SYSTEM       0x00000004
#define FILE_ATTRIBUTE_DIRECTORY    0x00000010
#define FILE_ATTRIBUTE_ARCHIVE      0x00000020
#define FILE_ATTRIBUTE_NORMAL       0x00000080
#define FILE_ATTRIBUTE_TEMPORARY    0x00000100

/* File flags (combined with attributes in dwFlagsAndAttributes) */
#define FILE_FLAG_WRITE_THROUGH     0x80000000
#define FILE_FLAG_OVERLAPPED        0x40000000
#define FILE_FLAG_NO_BUFFERING      0x20000000
#define FILE_FLAG_RANDOM_ACCESS     0x10000000
#define FILE_FLAG_SEQUENTIAL_SCAN   0x08000000
#define FILE_FLAG_DELETE_ON_CLOSE   0x04000000
#define FILE_FLAG_BACKUP_SEMANTICS  0x02000000

/* File share mode */
#define FILE_SHARE_READ     0x00000001
#define FILE_SHARE_WRITE    0x00000002
#define FILE_SHARE_DELETE   0x00000004

/* Memory allocation types */
#define MEM_COMMIT          0x00001000
#define MEM_RESERVE         0x00002000
#define MEM_DECOMMIT        0x00004000
#define MEM_RELEASE         0x00008000
#define MEM_RESET           0x00080000

/* Memory protection constants */
#define PAGE_NOACCESS           0x01
#define PAGE_READONLY           0x02
#define PAGE_READWRITE          0x04
#define PAGE_WRITECOPY          0x08
#define PAGE_EXECUTE            0x10
#define PAGE_EXECUTE_READ       0x20
#define PAGE_EXECUTE_READWRITE  0x40
#define PAGE_EXECUTE_WRITECOPY  0x80
#define PAGE_GUARD              0x100

/* Heap flags */
#define HEAP_NO_SERIALIZE           0x00000001
#define HEAP_GENERATE_EXCEPTIONS    0x00000004
#define HEAP_ZERO_MEMORY            0x00000008
#define HEAP_REALLOC_IN_PLACE_ONLY  0x00000010

/* Thread creation flags */
#define CREATE_SUSPENDED    0x00000004

/* Wait return values */
#define WAIT_OBJECT_0       0x00000000
#define WAIT_ABANDONED_0    0x00000080
#define WAIT_IO_COMPLETION  0x000000C0
#define WAIT_TIMEOUT        0x00000102
#define WAIT_FAILED         0xFFFFFFFF
#define INFINITE            0xFFFFFFFF

/* Standard handles */
#define STD_INPUT_HANDLE    ((DWORD)-10)
#define STD_OUTPUT_HANDLE   ((DWORD)-11)
#define STD_ERROR_HANDLE    ((DWORD)-12)

/* Console modes */
#define ENABLE_PROCESSED_INPUT      0x0001
#define ENABLE_LINE_INPUT           0x0002
#define ENABLE_ECHO_INPUT           0x0004
#define ENABLE_PROCESSED_OUTPUT     0x0001
#define ENABLE_WRAP_AT_EOL_OUTPUT   0x0002

/* Error codes */
#define ERROR_SUCCESS                   0
#define ERROR_INVALID_FUNCTION          1
#define ERROR_FILE_NOT_FOUND            2
#define ERROR_PATH_NOT_FOUND            3
#define ERROR_ACCESS_DENIED             5
#define ERROR_INVALID_HANDLE            6
#define ERROR_NOT_ENOUGH_MEMORY         8
#define ERROR_INVALID_DATA              13
#define ERROR_OUTOFMEMORY               14
#define ERROR_INVALID_DRIVE             15
#define ERROR_NO_MORE_FILES             18
#define ERROR_WRITE_PROTECT             19
#define ERROR_SHARING_VIOLATION         32
#define ERROR_LOCK_VIOLATION            33
#define ERROR_HANDLE_EOF                38
#define ERROR_FILE_EXISTS               80
#define ERROR_INVALID_PARAMETER         87
#define ERROR_BROKEN_PIPE               109
#define ERROR_INSUFFICIENT_BUFFER       122
#define ERROR_INVALID_NAME              123
#define ERROR_MOD_NOT_FOUND             126
#define ERROR_PROC_NOT_FOUND            127
#define ERROR_ALREADY_EXISTS            183
#define ERROR_ENVVAR_NOT_FOUND          203
#define ERROR_MORE_DATA                 234
#define ERROR_NO_MORE_ITEMS             259
#define ERROR_TOO_MANY_POSTS            298
#define ERROR_PIPE_BUSY                 231
#define ERROR_PIPE_NOT_CONNECTED        233
#define ERROR_PIPE_CONNECTED            535
#define ERROR_NOT_READY                 21
#define ERROR_GEN_FAILURE               31
#define ERROR_NOT_SUPPORTED             50
#define ERROR_BUFFER_OVERFLOW           111
#define ERROR_NEGATIVE_SEEK             131
#define ERROR_SEM_TIMEOUT               121
#define ERROR_NOACCESS                  998
#define ERROR_OPERATION_ABORTED         995
#define ERROR_IO_INCOMPLETE             996
#define ERROR_IO_PENDING                997
#define ERROR_TIMEOUT                   1460

/* NTSTATUS codes */
#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000)
#define STATUS_BUFFER_OVERFLOW          ((NTSTATUS)0x80000005)
#define STATUS_NO_MORE_ENTRIES          ((NTSTATUS)0x8000001A)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001)
#define STATUS_NOT_IMPLEMENTED          ((NTSTATUS)0xC0000002)
#define STATUS_INVALID_HANDLE           ((NTSTATUS)0xC0000008)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000D)
#define STATUS_NO_SUCH_FILE             ((NTSTATUS)0xC000000F)
#define STATUS_NO_MEMORY                ((NTSTATUS)0xC0000017)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034)
#define STATUS_OBJECT_NAME_COLLISION    ((NTSTATUS)0xC0000035)
#define STATUS_TIMEOUT                  ((NTSTATUS)0x00000102)
#define STATUS_PENDING                  ((NTSTATUS)0x00000103)
#define STATUS_WAIT_0                   ((NTSTATUS)0x00000000)

/* UNICODE_STRING (NT native string type) */
typedef struct {
    USHORT Length;           /* Length in bytes, not including null */
    USHORT MaximumLength;   /* Total buffer size in bytes */
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PSTR   Buffer;
} ANSI_STRING, *PANSI_STRING;

/* Process Environment Block (simplified) */
typedef struct _PEB {
    BYTE                Reserved1[2];
    BYTE                BeingDebugged;
    BYTE                Reserved2[1];
    PVOID               Reserved3[2];
    PVOID               Ldr;                /* PEB_LDR_DATA* */
    PVOID               ProcessParameters;  /* RTL_USER_PROCESS_PARAMETERS* */
    BYTE                Reserved4[104];
    PVOID               Reserved5[52];
    PVOID               PostProcessInitRoutine;
    BYTE                Reserved6[128];
    PVOID               Reserved7[1];
    ULONG               SessionId;
} PEB, *PPEB;

/* Thread Environment Block (simplified) */
typedef struct _TEB {
    PVOID               Reserved1[12];
    PPEB                ProcessEnvironmentBlock;
    PVOID               Reserved2[399];
    BYTE                Reserved3[1952];
    PVOID               TlsSlots[64];
    BYTE                Reserved4[8];
    PVOID               Reserved5[26];
    PVOID               ReservedForOle;
    PVOID               Reserved6[4];
    PVOID               TlsExpansionSlots;
} TEB, *PTEB;

#endif /* WINNT_H */
