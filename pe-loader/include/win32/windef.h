#ifndef WINDEF_H
#define WINDEF_H

#include <stdint.h>
#include <stddef.h>

/*
 * Core Windows type definitions for the PE compatibility layer.
 * These map Windows types to standard C types on Linux.
 */

/* Basic integer types */
typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef uint16_t            WORD;
typedef uint32_t            DWORD;
typedef uint64_t            QWORD;
typedef int32_t             LONG;
typedef uint32_t            ULONG;
typedef int64_t             LONGLONG;
typedef uint64_t            ULONGLONG;
typedef int16_t             SHORT;
typedef uint16_t            USHORT;
typedef unsigned int        UINT;
typedef int                 INT;
typedef float               FLOAT;
typedef char                CHAR;
typedef unsigned char       UCHAR;
typedef uint16_t            WCHAR;  /* Windows wchar_t is 2 bytes (UTF-16LE), NOT Linux 4-byte wchar_t */

/* Pointer-sized types */
typedef intptr_t            INT_PTR;
typedef uintptr_t           UINT_PTR;
typedef intptr_t            LONG_PTR;
typedef uintptr_t           ULONG_PTR;
typedef uintptr_t           DWORD_PTR;
typedef uint64_t            DWORD64;
typedef uint64_t           *PDWORD64;
typedef uintptr_t           SIZE_T;
typedef intptr_t            SSIZE_T;

/* String types — use uint16_t for wide strings (Windows UTF-16LE, 2 bytes per char) */
typedef char               *LPSTR;
typedef const char         *LPCSTR;
typedef uint16_t           *LPWSTR;
typedef const uint16_t     *LPCWSTR;
typedef char               *PSTR;
typedef const char         *PCSTR;
typedef uint16_t           *PWSTR;
typedef const uint16_t     *PCWSTR;
typedef char               *LPCH;
typedef uint16_t           *LPWCH;

/* Void pointer types */
typedef void               *LPVOID;
typedef const void         *LPCVOID;
typedef void               *PVOID;

/* Function pointer type */
typedef void              (*FARPROC)(void);

/* HANDLE types */
typedef void               *HANDLE;
typedef HANDLE              HMODULE;
typedef HANDLE              HINSTANCE;
typedef HANDLE              HWND;
typedef HANDLE              HDC;
typedef HANDLE              HBRUSH;
typedef HANDLE              HPEN;
typedef HANDLE              HFONT;
typedef HANDLE              HBITMAP;
typedef HANDLE              HGDIOBJ;
typedef HANDLE              HICON;
typedef HANDLE              HCURSOR;
typedef HANDLE              HMENU;
typedef HANDLE              HKEY;
typedef HANDLE              HRGN;
typedef HANDLE              HPALETTE;
typedef HANDLE              HGLOBAL;
typedef HANDLE              HLOCAL;

/* Pointer to DWORD etc */
typedef DWORD              *LPDWORD;
typedef DWORD              *PDWORD;
typedef WORD               *LPWORD;
typedef BOOL               *LPBOOL;
typedef BYTE               *LPBYTE;
typedef LONG               *LPLONG;
typedef LONG               *PLONG;
typedef INT                *LPINT;
typedef ULONG              *PULONG;
typedef USHORT             *PUSHORT;
typedef SIZE_T             *PSIZE_T;

/* Boolean values */
#ifndef TRUE
#define TRUE    1
#endif
#ifndef FALSE
#define FALSE   0
#endif
#ifndef NULL
#define NULL    ((void *)0)
#endif

/* INVALID_HANDLE_VALUE */
#define INVALID_HANDLE_VALUE    ((HANDLE)(intptr_t)-1)

/* Calling conventions (no-ops on Linux, used for documentation) */
#define WINAPI
#define CALLBACK
#define APIENTRY
#define STDCALL
#define CDECL
#define PASCAL

/* Max path */
#define MAX_PATH    260

/* Common Windows result type */
typedef LONG    HRESULT;
typedef LONG    NTSTATUS;

/* LARGE_INTEGER */
typedef union {
    struct {
        DWORD LowPart;
        LONG  HighPart;
    };
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef union {
    struct {
        DWORD LowPart;
        DWORD HighPart;
    };
    ULONGLONG QuadPart;
} ULARGE_INTEGER, *PULARGE_INTEGER;

/* FILETIME */
typedef struct {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;

/* GUID */
typedef struct {
    DWORD Data1;
    WORD  Data2;
    WORD  Data3;
    BYTE  Data4[8];
} GUID, *LPGUID;

/* RECT */
typedef struct {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
} RECT, *PRECT, *LPRECT;

/* POINT */
typedef struct {
    LONG x;
    LONG y;
} POINT, *PPOINT, *LPPOINT;

/* SIZE */
typedef struct {
    LONG cx;
    LONG cy;
} SIZE, *PSIZE, *LPSIZE;

/* WPARAM / LPARAM / LRESULT */
typedef UINT_PTR    WPARAM;
typedef LONG_PTR    LPARAM;
typedef LONG_PTR    LRESULT;

/* Atom */
typedef WORD        ATOM;

/* Security attributes (simplified) */
typedef struct {
    DWORD  nLength;
    LPVOID lpSecurityDescriptor;
    BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

/* Overlapped I/O (simplified) */
typedef struct {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union {
        struct {
            DWORD Offset;
            DWORD OffsetHigh;
        };
        PVOID Pointer;
    };
    HANDLE hEvent;
} OVERLAPPED, *LPOVERLAPPED;

#endif /* WINDEF_H */
