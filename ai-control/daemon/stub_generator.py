"""
Auto-Stub Generator -- Generates C implementations for Windows API stubs.

Takes a WinApiSignature and produces compilable C code that bridges
the Windows API call to a Linux equivalent.

Generated code follows the exact patterns used by the existing DLL stubs
in pe-loader/dlls/:
  - WINAPI_EXPORT (__attribute__((ms_abi, visibility("default"))))
  - set_last_error() / errno_to_win32_error() for error propagation
  - handle_alloc() / handle_lookup() / handle_close() for HANDLE management
  - win_path_to_linux() for path translation
  - Trust gate macros (TRUST_CHECK / TRUST_CHECK_RET) for security
  - (void)param; for silencing -Wunused-parameter on passthrough args

The generator supports six API families:
  - File I/O      (CreateFile/ReadFile/WriteFile -> open/read/write)
  - Memory         (VirtualAlloc -> mmap, HeapAlloc -> malloc)
  - Threading      (CreateThread -> pthread_create, WaitFor* -> futex/sem)
  - Registry       (RegOpenKey -> filesystem-backed registry)
  - Network        (socket/connect/send/recv -> direct POSIX sockets)
  - Generic        (safe no-op stub with stderr logging)
"""

import json
import logging
import os
import re
import subprocess
import textwrap
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("ai-control.stub_generator")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class WinApiParam:
    """A single parameter in a Windows API signature."""
    type: str       # e.g. "DWORD", "LPCSTR", "HANDLE"
    name: str       # e.g. "dwDesiredAccess", "lpFileName"


@dataclass
class WinApiSignature:
    """Parsed Windows API function signature."""
    dll: str                        # e.g. "kernel32.dll"
    name: str                       # e.g. "CreateFileA"
    return_type: str                # e.g. "HANDLE", "BOOL", "DWORD"
    params: list[WinApiParam] = field(default_factory=list)
    category: str = ""              # e.g. "file", "memory", "thread"
    calling_convention: str = "WINAPI"  # WINAPI, CDECL, etc.

    def to_dict(self) -> dict:
        return {
            "dll": self.dll,
            "name": self.name,
            "return_type": self.return_type,
            "params": [{"type": p.type, "name": p.name} for p in self.params],
            "category": self.category,
            "calling_convention": self.calling_convention,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "WinApiSignature":
        params = [WinApiParam(type=p["type"], name=p["name"])
                  for p in d.get("params", [])]
        return cls(
            dll=d.get("dll", "unknown.dll"),
            name=d["name"],
            return_type=d.get("return_type", "void"),
            params=params,
            category=d.get("category", ""),
            calling_convention=d.get("calling_convention", "WINAPI"),
        )

    @classmethod
    def parse(cls, declaration: str, dll: str = "unknown.dll") -> "WinApiSignature":
        """Parse a C-style function declaration.

        Accepted forms:
          HANDLE CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, ...);
          BOOL WINAPI ReadFile(HANDLE hFile, LPVOID lpBuffer, ...);
          int __stdcall WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);
        """
        decl = declaration.strip().rstrip(";").strip()
        # Strip calling conventions
        for cc in ("WINAPI", "__stdcall", "CALLBACK", "APIENTRY", "PASCAL", "CDECL"):
            decl = decl.replace(cc, " ")
        decl = re.sub(r"\s+", " ", decl).strip()

        # Split into "return_type name(params)"
        m = re.match(r"^(.+?)\s+(\w+)\s*\(([^)]*)\)\s*$", decl)
        if not m:
            raise ValueError(f"Cannot parse declaration: {declaration!r}")

        return_type = m.group(1).strip()
        name = m.group(2).strip()
        params_str = m.group(3).strip()

        params: list[WinApiParam] = []
        if params_str and params_str.lower() != "void":
            for chunk in params_str.split(","):
                chunk = chunk.strip()
                if not chunk:
                    continue
                # Handle pointer types: "DWORD *lpBytesRead" or "const char *name"
                # Take the last token as the name, everything before as the type
                tokens = chunk.rsplit(None, 1)
                if len(tokens) == 2:
                    ptype, pname = tokens
                    # If pname starts with *, it's part of the type
                    while pname.startswith("*"):
                        ptype += " *"
                        pname = pname[1:]
                    if not pname:
                        pname = f"param{len(params)}"
                    params.append(WinApiParam(type=ptype.strip(), name=pname.strip()))
                else:
                    # Single token -- type only
                    params.append(WinApiParam(type=chunk, name=f"param{len(params)}"))

        category = _classify_api(name, dll)

        return cls(
            dll=dll,
            name=name,
            return_type=return_type,
            params=params,
            category=category,
        )


# ---------------------------------------------------------------------------
# API classification
# ---------------------------------------------------------------------------

_CATEGORY_PATTERNS = {
    "file": re.compile(
        r"^(CreateFile|ReadFile|WriteFile|CloseHandle|SetFilePointer|"
        r"GetFileSize|DeleteFile|CopyFile|MoveFile|CreateDirectory|"
        r"RemoveDirectory|FindFirstFile|FindNextFile|FindClose|"
        r"GetTempPath|GetTempFileName|SetEndOfFile|FlushFileBuffers|"
        r"GetFileAttributes|SetFileAttributes|LockFile|UnlockFile|"
        r"GetFullPathName|GetCurrentDirectory|SetCurrentDirectory|"
        r"GetFileType|GetFileSizeEx|SetFilePointerEx|"
        r"CreateFileMapping|MapViewOfFile|UnmapViewOfFile)", re.IGNORECASE),
    "memory": re.compile(
        r"^(VirtualAlloc|VirtualFree|VirtualProtect|VirtualQuery|"
        r"HeapAlloc|HeapFree|HeapReAlloc|HeapCreate|HeapDestroy|"
        r"HeapSize|GetProcessHeap|GlobalAlloc|GlobalFree|GlobalLock|"
        r"GlobalUnlock|LocalAlloc|LocalFree|LocalLock|LocalUnlock|"
        r"HeapCompact|HeapValidate|HeapWalk|HeapLock|HeapUnlock)", re.IGNORECASE),
    "thread": re.compile(
        r"^(CreateThread|ExitThread|TerminateThread|GetCurrentThread|"
        r"GetCurrentThreadId|ResumeThread|SuspendThread|"
        r"SwitchToThread|Sleep|SleepEx|TlsAlloc|TlsFree|TlsGetValue|"
        r"TlsSetValue|WaitForSingleObject|WaitForMultipleObjects|"
        r"CreateEvent|SetEvent|ResetEvent|CreateMutex|ReleaseMutex|"
        r"CreateSemaphore|ReleaseSemaphore|InitializeCriticalSection|"
        r"EnterCriticalSection|LeaveCriticalSection|DeleteCriticalSection|"
        r"QueueUserAPC|QueueUserWorkItem|CreateThreadpool)", re.IGNORECASE),
    "process": re.compile(
        r"^(CreateProcess|ExitProcess|TerminateProcess|GetCurrentProcess|"
        r"GetCurrentProcessId|GetExitCodeProcess|OpenProcess|"
        r"GetProcessId|GetStartupInfo|GetCommandLine|GetEnvironment|"
        r"SetEnvironmentVariable|GetEnvironmentVariable)", re.IGNORECASE),
    "registry": re.compile(
        r"^(RegOpenKey|RegCreateKey|RegCloseKey|RegQueryValue|"
        r"RegSetValue|RegDeleteKey|RegDeleteValue|RegEnumKey|"
        r"RegEnumValue|RegNotifyChangeKeyValue|RegFlush)", re.IGNORECASE),
    "network": re.compile(
        r"^(WSAStartup|WSACleanup|WSAGetLastError|WSASetLastError|"
        r"socket|closesocket|connect|bind|listen|accept|send|recv|"
        r"sendto|recvfrom|select|shutdown|gethostbyname|getaddrinfo|"
        r"freeaddrinfo|ioctlsocket|setsockopt|getsockopt|"
        r"WSARecv|WSASend|WSAIoctl|htons|htonl|ntohs|ntohl|"
        r"inet_addr|inet_ntoa|gethostname|getpeername|getsockname)", re.IGNORECASE),
    "sync": re.compile(
        r"^(Interlocked|InitOnce|ConditionVariable|SRWLock|"
        r"AcquireSRWLock|ReleaseSRWLock|TryAcquireSRWLock|"
        r"WakeConditionVariable|WakeAllConditionVariable|"
        r"SleepConditionVariableSRW)", re.IGNORECASE),
    "module": re.compile(
        r"^(LoadLibrary|FreeLibrary|GetProcAddress|GetModuleHandle|"
        r"GetModuleFileName|DisableThreadLibraryCalls)", re.IGNORECASE),
    "console": re.compile(
        r"^(GetStdHandle|SetStdHandle|WriteConsole|ReadConsole|"
        r"AllocConsole|FreeConsole|GetConsoleMode|SetConsoleMode|"
        r"SetConsoleTitleA|GetConsoleTitle|GetConsoleScreenBufferInfo|"
        r"SetConsoleTextAttribute|FillConsoleOutputCharacter|"
        r"SetConsoleCursorPosition|GetConsoleCP|GetConsoleOutputCP)", re.IGNORECASE),
    "gdi": re.compile(
        r"^(CreateDC|DeleteDC|CreateCompatibleDC|SelectObject|"
        r"DeleteObject|GetStockObject|BitBlt|StretchBlt|"
        r"CreateBitmap|CreateFont|CreatePen|CreateBrush|"
        r"SetTextColor|SetBkColor|TextOut|GetDeviceCaps)", re.IGNORECASE),
    "user": re.compile(
        r"^(CreateWindow|DestroyWindow|ShowWindow|UpdateWindow|"
        r"DefWindowProc|RegisterClass|UnregisterClass|"
        r"GetMessage|PeekMessage|TranslateMessage|DispatchMessage|"
        r"PostMessage|SendMessage|PostQuitMessage|"
        r"MessageBox|SetWindowText|GetWindowText|"
        r"SetWindowPos|GetClientRect|GetWindowRect|"
        r"LoadCursor|LoadIcon|SetCursor)", re.IGNORECASE),
}


def _classify_api(name: str, dll: str = "") -> str:
    """Classify a Windows API function into a category."""
    for category, pattern in _CATEGORY_PATTERNS.items():
        if pattern.match(name):
            return category

    # Fallback: infer from DLL name
    dll_lower = dll.lower().replace(".dll", "")
    dll_category_map = {
        "kernel32": "system",
        "ntdll": "system",
        "advapi32": "registry",
        "ws2_32": "network",
        "wsock32": "network",
        "user32": "user",
        "gdi32": "gdi",
        "shell32": "shell",
        "ole32": "com",
        "oleaut32": "com",
        "msvcrt": "crt",
        "comctl32": "ui",
        "comdlg32": "ui",
        "winmm": "multimedia",
        "winhttp": "network",
        "crypt32": "crypto",
        "bcrypt": "crypto",
        "secur32": "crypto",
        "setupapi": "device",
        "iphlpapi": "network",
    }
    if dll_lower in dll_category_map:
        return dll_category_map[dll_lower]

    return "unknown"


# ---------------------------------------------------------------------------
# Windows -> C type mapping
# ---------------------------------------------------------------------------

# Comprehensive type map matching pe-loader/include/win32/windef.h exactly
WIN_TYPES: dict[str, str] = {
    # Basic integer types
    "HANDLE": "void *",
    "DWORD": "uint32_t",
    "WORD": "uint16_t",
    "BOOL": "int",
    "LONG": "int32_t",
    "ULONG": "uint32_t",
    "INT": "int",
    "UINT": "unsigned int",
    "BYTE": "uint8_t",
    "CHAR": "char",
    "UCHAR": "unsigned char",
    "WCHAR": "uint16_t",
    "SHORT": "int16_t",
    "USHORT": "uint16_t",
    "FLOAT": "float",
    "LONGLONG": "int64_t",
    "ULONGLONG": "uint64_t",
    "QWORD": "uint64_t",
    "DWORD64": "uint64_t",
    # Pointer-sized types
    "INT_PTR": "intptr_t",
    "UINT_PTR": "uintptr_t",
    "LONG_PTR": "intptr_t",
    "ULONG_PTR": "uintptr_t",
    "DWORD_PTR": "uintptr_t",
    "SIZE_T": "size_t",
    "SSIZE_T": "intptr_t",
    # String types (Windows wchar_t = 2 bytes, NOT Linux 4-byte wchar_t)
    "LPCSTR": "const char *",
    "LPSTR": "char *",
    "LPCWSTR": "const uint16_t *",
    "LPWSTR": "uint16_t *",
    "PCSTR": "const char *",
    "PSTR": "char *",
    "PCWSTR": "const uint16_t *",
    "PWSTR": "uint16_t *",
    "LPCH": "char *",
    "LPWCH": "uint16_t *",
    # Void pointer types
    "LPVOID": "void *",
    "LPCVOID": "const void *",
    "PVOID": "void *",
    # Function pointer
    "FARPROC": "void (*)(void)",
    # Handle aliases (all void* in our implementation)
    "HMODULE": "void *",
    "HINSTANCE": "void *",
    "HWND": "void *",
    "HDC": "void *",
    "HBRUSH": "void *",
    "HPEN": "void *",
    "HFONT": "void *",
    "HBITMAP": "void *",
    "HGDIOBJ": "void *",
    "HICON": "void *",
    "HCURSOR": "void *",
    "HMENU": "void *",
    "HKEY": "void *",
    "HRGN": "void *",
    "HPALETTE": "void *",
    "HGLOBAL": "void *",
    "HLOCAL": "void *",
    "SOCKET": "int",
    # Pointer-to-basic types
    "LPDWORD": "uint32_t *",
    "PDWORD": "uint32_t *",
    "LPWORD": "uint16_t *",
    "LPBOOL": "int *",
    "LPBYTE": "uint8_t *",
    "LPLONG": "int32_t *",
    "PLONG": "int32_t *",
    "LPINT": "int *",
    "PULONG": "uint32_t *",
    "PUSHORT": "uint16_t *",
    "PSIZE_T": "size_t *",
    "PDWORD64": "uint64_t *",
    # Result types
    "HRESULT": "int32_t",
    "NTSTATUS": "int32_t",
    # Composite types simplified for stubs
    "LARGE_INTEGER": "int64_t",
    "PLARGE_INTEGER": "int64_t *",
    "ULARGE_INTEGER": "uint64_t",
    "PULARGE_INTEGER": "uint64_t *",
    # Opaque pointer types (simplified)
    "OVERLAPPED *": "void *",
    "LPOVERLAPPED": "void *",
    "SECURITY_ATTRIBUTES *": "void *",
    "LPSECURITY_ATTRIBUTES": "void *",
    "PSECURITY_ATTRIBUTES": "void *",
    "LPFILETIME": "void *",
    "PFILETIME": "void *",
    # Callback types
    "LPTHREAD_START_ROUTINE": "uint32_t (*)(void *)",
    "WPARAM": "uintptr_t",
    "LPARAM": "intptr_t",
    "LRESULT": "intptr_t",
    "ATOM": "uint16_t",
}

# Windows error codes -> errno mapping (used in generated stubs)
WIN_TO_ERRNO: dict[str, str] = {
    "ERROR_SUCCESS": "0",
    "ERROR_FILE_NOT_FOUND": "ENOENT",
    "ERROR_PATH_NOT_FOUND": "ENOENT",
    "ERROR_ACCESS_DENIED": "EACCES",
    "ERROR_INVALID_HANDLE": "EBADF",
    "ERROR_NOT_ENOUGH_MEMORY": "ENOMEM",
    "ERROR_OUTOFMEMORY": "ENOMEM",
    "ERROR_INVALID_PARAMETER": "EINVAL",
    "ERROR_ALREADY_EXISTS": "EEXIST",
    "ERROR_FILE_EXISTS": "EEXIST",
    "ERROR_BROKEN_PIPE": "EPIPE",
    "ERROR_SHARING_VIOLATION": "EBUSY",
}

# Trust gate category for each API category
_TRUST_GATE_MAP: dict[str, tuple[str, str]] = {
    "file": ("TRUST_GATE_FILE_READ", "TRUST_CHECK_RET"),
    "memory": ("TRUST_GATE_MEMORY_EXEC", "TRUST_CHECK_RET"),
    "thread": ("TRUST_GATE_THREAD_CREATE", "TRUST_CHECK_RET"),
    "process": ("TRUST_GATE_PROCESS_CREATE", "TRUST_CHECK_RET"),
    "registry": ("TRUST_GATE_REGISTRY_READ", "TRUST_CHECK_RET"),
    "network": ("TRUST_GATE_NET_CONNECT", "TRUST_CHECK_RET"),
    "module": ("TRUST_GATE_DLL_LOAD", "TRUST_CHECK_RET"),
    "crypto": ("TRUST_GATE_CRYPTO_OP", "TRUST_CHECK_RET"),
    "gdi": ("TRUST_GATE_SCREEN_CAPTURE", "TRUST_CHECK_RET"),
    "user": ("TRUST_GATE_KEYBOARD_HOOK", "TRUST_CHECK_RET"),
    "device": ("TRUST_GATE_DEVICE_IOCTL", "TRUST_CHECK_RET"),
}


# ---------------------------------------------------------------------------
# Linux equivalent mappings for templated stubs
# ---------------------------------------------------------------------------

# File I/O templates: Windows function -> (Linux syscall, template key)
_FILE_IO_TEMPLATES: dict[str, str] = {
    "CreateFileA": "create_file_a",
    "CreateFileW": "create_file_w",
    "ReadFile": "read_file",
    "WriteFile": "write_file",
    "CloseHandle": "close_handle",
    "SetFilePointer": "set_file_pointer",
    "SetFilePointerEx": "set_file_pointer_ex",
    "GetFileSize": "get_file_size",
    "GetFileSizeEx": "get_file_size_ex",
    "DeleteFileA": "delete_file_a",
    "DeleteFileW": "delete_file_w",
    "CreateDirectoryA": "create_directory_a",
    "RemoveDirectoryA": "remove_directory_a",
    "FlushFileBuffers": "flush_file_buffers",
    "SetEndOfFile": "set_end_of_file",
    "GetFileType": "get_file_type",
    "GetFileAttributesA": "get_file_attributes_a",
    "GetTempPathA": "get_temp_path_a",
    "CopyFileA": "copy_file_a",
    "MoveFileA": "move_file_a",
}

_MEMORY_TEMPLATES: dict[str, str] = {
    "VirtualAlloc": "virtual_alloc",
    "VirtualFree": "virtual_free",
    "VirtualProtect": "virtual_protect",
    "HeapAlloc": "heap_alloc",
    "HeapFree": "heap_free",
    "HeapReAlloc": "heap_realloc",
    "GetProcessHeap": "get_process_heap",
    "GlobalAlloc": "global_alloc",
    "GlobalFree": "global_free",
    "LocalAlloc": "local_alloc",
    "LocalFree": "local_free",
}

_THREAD_TEMPLATES: dict[str, str] = {
    "CreateThread": "create_thread",
    "ExitThread": "exit_thread",
    "Sleep": "sleep_func",
    "SleepEx": "sleep_ex",
    "GetCurrentThreadId": "get_current_thread_id",
    "GetCurrentThread": "get_current_thread",
    "SwitchToThread": "switch_to_thread",
    "TlsAlloc": "tls_alloc",
    "TlsFree": "tls_free",
    "TlsGetValue": "tls_get_value",
    "TlsSetValue": "tls_set_value",
    "WaitForSingleObject": "wait_single",
    "CreateEvent": "create_event",
    "CreateEventA": "create_event",
    "SetEvent": "set_event",
    "ResetEvent": "reset_event",
    "CreateMutexA": "create_mutex",
    "ReleaseMutex": "release_mutex",
}

_REGISTRY_TEMPLATES: dict[str, str] = {
    "RegOpenKeyExA": "reg_open_key",
    "RegCreateKeyExA": "reg_create_key",
    "RegCloseKey": "reg_close_key",
    "RegQueryValueExA": "reg_query_value",
    "RegSetValueExA": "reg_set_value",
    "RegDeleteKeyA": "reg_delete_key",
    "RegDeleteValueA": "reg_delete_value",
    "RegEnumKeyExA": "reg_enum_key",
    "RegEnumValueA": "reg_enum_value",
}

_NETWORK_TEMPLATES: dict[str, str] = {
    "WSAStartup": "wsa_startup",
    "WSACleanup": "wsa_cleanup",
    "WSAGetLastError": "wsa_get_last_error",
    "WSASetLastError": "wsa_set_last_error",
    "socket": "sock_socket",
    "closesocket": "sock_close",
    "connect": "sock_connect",
    "bind": "sock_bind",
    "listen": "sock_listen",
    "accept": "sock_accept",
    "send": "sock_send",
    "recv": "sock_recv",
    "select": "sock_select",
    "setsockopt": "sock_setsockopt",
    "getsockopt": "sock_getsockopt",
    "ioctlsocket": "sock_ioctlsocket",
    "getaddrinfo": "sock_getaddrinfo",
    "freeaddrinfo": "sock_freeaddrinfo",
    "gethostbyname": "sock_gethostbyname",
    "gethostname": "sock_gethostname",
    "shutdown": "sock_shutdown",
}


# ---------------------------------------------------------------------------
# Template code fragments
# ---------------------------------------------------------------------------

def _file_io_template(key: str) -> Optional[str]:
    """Return C implementation for a file I/O template."""
    templates = {
        "create_file_a": textwrap.dedent("""\
            WINAPI_EXPORT HANDLE CreateFileA(
                LPCSTR lpFileName, DWORD dwDesiredAccess,
                DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
                HANDLE hTemplateFile)
            {
                TRUST_CHECK_RET(TRUST_GATE_FILE_READ, "CreateFileA", INVALID_HANDLE_VALUE);
                (void)dwShareMode; (void)lpSecurityAttributes;
                (void)dwFlagsAndAttributes; (void)hTemplateFile;

                int flags = 0;
                if ((dwDesiredAccess & 0xC0000000) == 0xC0000000)
                    flags = O_RDWR;
                else if (dwDesiredAccess & 0x40000000)
                    flags = O_WRONLY;
                else
                    flags = O_RDONLY;

                switch (dwCreationDisposition) {
                    case 1: /* CREATE_NEW */       flags |= O_CREAT | O_EXCL; break;
                    case 2: /* CREATE_ALWAYS */    flags |= O_CREAT | O_TRUNC; break;
                    case 3: /* OPEN_EXISTING */    break;
                    case 4: /* OPEN_ALWAYS */      flags |= O_CREAT; break;
                    case 5: /* TRUNCATE_EXISTING */ flags |= O_TRUNC; break;
                }

                char linux_path[PATH_MAX];
                win_path_to_linux(lpFileName, linux_path, sizeof(linux_path));

                int fd = open(linux_path, flags, 0644);
                if (fd < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return INVALID_HANDLE_VALUE;
                }
                return handle_alloc(HANDLE_TYPE_FILE, fd, NULL);
            }"""),

        "create_file_w": textwrap.dedent("""\
            WINAPI_EXPORT HANDLE CreateFileW(
                LPCWSTR lpFileName, DWORD dwDesiredAccess,
                DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
                HANDLE hTemplateFile)
            {
                TRUST_CHECK_RET(TRUST_GATE_FILE_READ, "CreateFileW", INVALID_HANDLE_VALUE);
                char narrow[4096];
                wide_to_narrow_safe(lpFileName, narrow, sizeof(narrow));
                return CreateFileA(narrow, dwDesiredAccess, dwShareMode,
                                   lpSecurityAttributes, dwCreationDisposition,
                                   dwFlagsAndAttributes, hTemplateFile);
            }"""),

        "read_file": textwrap.dedent("""\
            WINAPI_EXPORT BOOL ReadFile(
                HANDLE hFile, LPVOID lpBuffer,
                DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead,
                LPOVERLAPPED lpOverlapped)
            {
                TRUST_CHECK(TRUST_GATE_FILE_READ, "ReadFile");
                (void)lpOverlapped;

                int fd = handle_get_fd(hFile);
                if (fd < 0) {
                    set_last_error(ERROR_INVALID_HANDLE);
                    return FALSE;
                }

                ssize_t n = read(fd, lpBuffer, nNumberOfBytesToRead);
                if (n < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    if (lpNumberOfBytesRead) *lpNumberOfBytesRead = 0;
                    return FALSE;
                }
                if (lpNumberOfBytesRead) *lpNumberOfBytesRead = (DWORD)n;
                return TRUE;
            }"""),

        "write_file": textwrap.dedent("""\
            WINAPI_EXPORT BOOL WriteFile(
                HANDLE hFile, LPCVOID lpBuffer,
                DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten,
                LPOVERLAPPED lpOverlapped)
            {
                TRUST_CHECK(TRUST_GATE_FILE_WRITE, "WriteFile");
                (void)lpOverlapped;

                int fd = handle_get_fd(hFile);
                if (fd < 0) {
                    set_last_error(ERROR_INVALID_HANDLE);
                    return FALSE;
                }

                ssize_t n = write(fd, lpBuffer, nNumberOfBytesToWrite);
                if (n < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = 0;
                    return FALSE;
                }
                if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = (DWORD)n;
                return TRUE;
            }"""),

        "close_handle": textwrap.dedent("""\
            WINAPI_EXPORT BOOL CloseHandle(HANDLE hObject)
            {
                if (hObject == NULL || hObject == INVALID_HANDLE_VALUE) {
                    set_last_error(ERROR_INVALID_HANDLE);
                    return FALSE;
                }
                if (handle_close(hObject) < 0) {
                    set_last_error(ERROR_INVALID_HANDLE);
                    return FALSE;
                }
                return TRUE;
            }"""),

        "set_file_pointer": textwrap.dedent("""\
            WINAPI_EXPORT DWORD SetFilePointer(
                HANDLE hFile, LONG lDistanceToMove,
                PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)
            {
                int fd = handle_get_fd(hFile);
                if (fd < 0) {
                    set_last_error(ERROR_INVALID_HANDLE);
                    return (DWORD)-1;
                }

                int whence;
                switch (dwMoveMethod) {
                    case 0: whence = SEEK_SET; break;
                    case 1: whence = SEEK_CUR; break;
                    case 2: whence = SEEK_END; break;
                    default:
                        set_last_error(ERROR_INVALID_PARAMETER);
                        return (DWORD)-1;
                }

                off_t offset = (off_t)lDistanceToMove;
                if (lpDistanceToMoveHigh)
                    offset |= ((off_t)*lpDistanceToMoveHigh) << 32;

                off_t result = lseek(fd, offset, whence);
                if (result < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return (DWORD)-1;
                }

                if (lpDistanceToMoveHigh)
                    *lpDistanceToMoveHigh = (LONG)(result >> 32);
                return (DWORD)(result & 0xFFFFFFFF);
            }"""),

        "set_file_pointer_ex": textwrap.dedent("""\
            WINAPI_EXPORT BOOL SetFilePointerEx(
                HANDLE hFile, LARGE_INTEGER liDistanceToMove,
                PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod)
            {
                int fd = handle_get_fd(hFile);
                if (fd < 0) {
                    set_last_error(ERROR_INVALID_HANDLE);
                    return FALSE;
                }

                int whence;
                switch (dwMoveMethod) {
                    case 0: whence = SEEK_SET; break;
                    case 1: whence = SEEK_CUR; break;
                    case 2: whence = SEEK_END; break;
                    default:
                        set_last_error(ERROR_INVALID_PARAMETER);
                        return FALSE;
                }

                off_t result = lseek(fd, (off_t)liDistanceToMove, whence);
                if (result < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return FALSE;
                }
                if (lpNewFilePointer)
                    *lpNewFilePointer = (int64_t)result;
                return TRUE;
            }"""),

        "get_file_size": textwrap.dedent("""\
            WINAPI_EXPORT DWORD GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh)
            {
                int fd = handle_get_fd(hFile);
                if (fd < 0) {
                    set_last_error(ERROR_INVALID_HANDLE);
                    return (DWORD)-1;
                }

                struct stat st;
                if (fstat(fd, &st) < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return (DWORD)-1;
                }

                if (lpFileSizeHigh)
                    *lpFileSizeHigh = (DWORD)(st.st_size >> 32);
                return (DWORD)(st.st_size & 0xFFFFFFFF);
            }"""),

        "get_file_size_ex": textwrap.dedent("""\
            WINAPI_EXPORT BOOL GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize)
            {
                int fd = handle_get_fd(hFile);
                if (fd < 0) {
                    set_last_error(ERROR_INVALID_HANDLE);
                    return FALSE;
                }

                struct stat st;
                if (fstat(fd, &st) < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return FALSE;
                }
                if (lpFileSize)
                    *lpFileSize = (int64_t)st.st_size;
                return TRUE;
            }"""),

        "delete_file_a": textwrap.dedent("""\
            WINAPI_EXPORT BOOL DeleteFileA(LPCSTR lpFileName)
            {
                TRUST_CHECK(TRUST_GATE_FILE_WRITE, "DeleteFileA");

                char linux_path[PATH_MAX];
                win_path_to_linux(lpFileName, linux_path, sizeof(linux_path));

                if (unlink(linux_path) < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return FALSE;
                }
                return TRUE;
            }"""),

        "delete_file_w": textwrap.dedent("""\
            WINAPI_EXPORT BOOL DeleteFileW(LPCWSTR lpFileName)
            {
                char narrow[4096];
                wide_to_narrow_safe(lpFileName, narrow, sizeof(narrow));
                return DeleteFileA(narrow);
            }"""),

        "create_directory_a": textwrap.dedent("""\
            WINAPI_EXPORT BOOL CreateDirectoryA(
                LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
            {
                TRUST_CHECK(TRUST_GATE_FILE_WRITE, "CreateDirectoryA");
                (void)lpSecurityAttributes;

                char linux_path[PATH_MAX];
                win_path_to_linux(lpPathName, linux_path, sizeof(linux_path));

                if (mkdir(linux_path, 0755) < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return FALSE;
                }
                return TRUE;
            }"""),

        "remove_directory_a": textwrap.dedent("""\
            WINAPI_EXPORT BOOL RemoveDirectoryA(LPCSTR lpPathName)
            {
                TRUST_CHECK(TRUST_GATE_FILE_WRITE, "RemoveDirectoryA");

                char linux_path[PATH_MAX];
                win_path_to_linux(lpPathName, linux_path, sizeof(linux_path));

                if (rmdir(linux_path) < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return FALSE;
                }
                return TRUE;
            }"""),

        "flush_file_buffers": textwrap.dedent("""\
            WINAPI_EXPORT BOOL FlushFileBuffers(HANDLE hFile)
            {
                int fd = handle_get_fd(hFile);
                if (fd < 0) {
                    set_last_error(ERROR_INVALID_HANDLE);
                    return FALSE;
                }
                if (fsync(fd) < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return FALSE;
                }
                return TRUE;
            }"""),

        "set_end_of_file": textwrap.dedent("""\
            WINAPI_EXPORT BOOL SetEndOfFile(HANDLE hFile)
            {
                int fd = handle_get_fd(hFile);
                if (fd < 0) {
                    set_last_error(ERROR_INVALID_HANDLE);
                    return FALSE;
                }
                off_t pos = lseek(fd, 0, SEEK_CUR);
                if (pos < 0 || ftruncate(fd, pos) < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return FALSE;
                }
                return TRUE;
            }"""),

        "get_file_type": textwrap.dedent("""\
            WINAPI_EXPORT DWORD GetFileType(HANDLE hFile)
            {
                int fd = handle_get_fd(hFile);
                if (fd < 0) return 0; /* FILE_TYPE_UNKNOWN */

                struct stat st;
                if (fstat(fd, &st) < 0) return 0;

                if (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode))
                    return 1; /* FILE_TYPE_DISK */
                if (S_ISCHR(st.st_mode))
                    return 2; /* FILE_TYPE_CHAR */
                if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode))
                    return 3; /* FILE_TYPE_PIPE */
                return 0;
            }"""),

        "get_file_attributes_a": textwrap.dedent("""\
            WINAPI_EXPORT DWORD GetFileAttributesA(LPCSTR lpFileName)
            {
                char linux_path[PATH_MAX];
                win_path_to_linux(lpFileName, linux_path, sizeof(linux_path));

                struct stat st;
                if (stat(linux_path, &st) < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return (DWORD)-1; /* INVALID_FILE_ATTRIBUTES */
                }

                DWORD attrs = 0;
                if (S_ISDIR(st.st_mode))
                    attrs |= 0x10; /* FILE_ATTRIBUTE_DIRECTORY */
                if (!(st.st_mode & S_IWUSR))
                    attrs |= 0x01; /* FILE_ATTRIBUTE_READONLY */
                if (attrs == 0)
                    attrs = 0x80; /* FILE_ATTRIBUTE_NORMAL */
                return attrs;
            }"""),

        "get_temp_path_a": textwrap.dedent("""\
            WINAPI_EXPORT DWORD GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer)
            {
                const char *tmp = "/tmp/";
                DWORD len = (DWORD)strlen(tmp);
                if (nBufferLength > len) {
                    memcpy(lpBuffer, tmp, len + 1);
                    return len;
                }
                return len + 1; /* Buffer too small: return required size */
            }"""),

        "copy_file_a": textwrap.dedent("""\
            WINAPI_EXPORT BOOL CopyFileA(
                LPCSTR lpExistingFileName, LPCSTR lpNewFileName,
                BOOL bFailIfExists)
            {
                TRUST_CHECK(TRUST_GATE_FILE_WRITE, "CopyFileA");

                char src[PATH_MAX], dst[PATH_MAX];
                win_path_to_linux(lpExistingFileName, src, sizeof(src));
                win_path_to_linux(lpNewFileName, dst, sizeof(dst));

                if (bFailIfExists) {
                    struct stat st;
                    if (stat(dst, &st) == 0) {
                        set_last_error(ERROR_FILE_EXISTS);
                        return FALSE;
                    }
                }

                int in_fd = open(src, O_RDONLY);
                if (in_fd < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return FALSE;
                }

                int out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (out_fd < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    close(in_fd);
                    return FALSE;
                }

                char buf[65536];
                ssize_t n;
                while ((n = read(in_fd, buf, sizeof(buf))) > 0) {
                    ssize_t written = 0;
                    while (written < n) {
                        ssize_t w = write(out_fd, buf + written, n - written);
                        if (w < 0) {
                            set_last_error(errno_to_win32_error(errno));
                            close(in_fd);
                            close(out_fd);
                            return FALSE;
                        }
                        written += w;
                    }
                }

                close(in_fd);
                close(out_fd);
                return TRUE;
            }"""),

        "move_file_a": textwrap.dedent("""\
            WINAPI_EXPORT BOOL MoveFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName)
            {
                TRUST_CHECK(TRUST_GATE_FILE_WRITE, "MoveFileA");

                char src[PATH_MAX], dst[PATH_MAX];
                win_path_to_linux(lpExistingFileName, src, sizeof(src));
                win_path_to_linux(lpNewFileName, dst, sizeof(dst));

                if (rename(src, dst) < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return FALSE;
                }
                return TRUE;
            }"""),
    }
    return templates.get(key)


def _memory_template(key: str) -> Optional[str]:
    """Return C implementation for a memory template."""
    templates = {
        "virtual_alloc": textwrap.dedent("""\
            WINAPI_EXPORT LPVOID VirtualAlloc(
                LPVOID lpAddress, SIZE_T dwSize,
                DWORD flAllocationType, DWORD flProtect)
            {
                int prot = PROT_READ | PROT_WRITE;
                if ((flProtect & 0xFF) >= 0x10) /* PAGE_EXECUTE+ */
                    prot |= PROT_EXEC;
                if ((flProtect & 0xFF) == 0x01) /* PAGE_NOACCESS */
                    prot = PROT_NONE;
                if ((flProtect & 0xFF) == 0x02) /* PAGE_READONLY */
                    prot = PROT_READ;

                int flags = MAP_PRIVATE | MAP_ANONYMOUS;
                if (lpAddress != NULL)
                    flags |= MAP_FIXED_NOREPLACE;

                void *result = mmap(lpAddress, dwSize, prot, flags, -1, 0);
                if (result == MAP_FAILED) {
                    set_last_error(errno_to_win32_error(errno));
                    return NULL;
                }
                return result;
            }"""),

        "virtual_free": textwrap.dedent("""\
            WINAPI_EXPORT BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
            {
                if (dwFreeType & 0x00008000) { /* MEM_RELEASE */
                    if (dwSize == 0) dwSize = 0x40000; /* 256KB fallback */
                    munmap(lpAddress, dwSize);
                    return TRUE;
                }
                if (dwFreeType & 0x00004000) { /* MEM_DECOMMIT */
                    mprotect(lpAddress, dwSize, PROT_NONE);
                    madvise(lpAddress, dwSize, MADV_DONTNEED);
                    return TRUE;
                }
                set_last_error(ERROR_INVALID_PARAMETER);
                return FALSE;
            }"""),

        "virtual_protect": textwrap.dedent("""\
            WINAPI_EXPORT BOOL VirtualProtect(
                LPVOID lpAddress, SIZE_T dwSize,
                DWORD flNewProtect, DWORD *lpflOldProtect)
            {
                if (lpflOldProtect)
                    *lpflOldProtect = 0x04; /* PAGE_READWRITE */

                int prot = PROT_READ | PROT_WRITE;
                if ((flNewProtect & 0xFF) >= 0x10)
                    prot |= PROT_EXEC;
                if ((flNewProtect & 0xFF) == 0x01)
                    prot = PROT_NONE;
                if ((flNewProtect & 0xFF) == 0x02)
                    prot = PROT_READ;

                if (mprotect(lpAddress, dwSize, prot) < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return FALSE;
                }
                return TRUE;
            }"""),

        "heap_alloc": textwrap.dedent("""\
            WINAPI_EXPORT LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
            {
                (void)hHeap;
                void *ptr;
                if (dwBytes == 0) dwBytes = 1;
                if (dwFlags & 0x00000008) /* HEAP_ZERO_MEMORY */
                    ptr = calloc(1, dwBytes);
                else
                    ptr = malloc(dwBytes);
                if (!ptr)
                    set_last_error(ERROR_NOT_ENOUGH_MEMORY);
                return ptr;
            }"""),

        "heap_free": textwrap.dedent("""\
            WINAPI_EXPORT BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
            {
                (void)hHeap; (void)dwFlags;
                if (!lpMem) return TRUE;
                free(lpMem);
                return TRUE;
            }"""),

        "heap_realloc": textwrap.dedent("""\
            WINAPI_EXPORT LPVOID HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)
            {
                (void)hHeap;
                if (!lpMem) return HeapAlloc(hHeap, dwFlags, dwBytes);
                if (dwBytes == 0) dwBytes = 1;
                void *ptr = realloc(lpMem, dwBytes);
                if (!ptr) set_last_error(ERROR_NOT_ENOUGH_MEMORY);
                return ptr;
            }"""),

        "get_process_heap": textwrap.dedent("""\
            WINAPI_EXPORT HANDLE GetProcessHeap(void)
            {
                /* Return a sentinel value; HeapAlloc ignores the heap handle anyway */
                return (HANDLE)(uintptr_t)0xDEADBEEF;
            }"""),

        "global_alloc": textwrap.dedent("""\
            WINAPI_EXPORT HGLOBAL GlobalAlloc(UINT uFlags, SIZE_T dwBytes)
            {
                SIZE_T size = dwBytes ? dwBytes : 1;
                if (uFlags & 0x0040) /* GMEM_ZEROINIT */
                    return calloc(1, size);
                return malloc(size);
            }"""),

        "global_free": textwrap.dedent("""\
            WINAPI_EXPORT HGLOBAL GlobalFree(HGLOBAL hMem)
            {
                free(hMem);
                return NULL;
            }"""),

        "local_alloc": textwrap.dedent("""\
            WINAPI_EXPORT HLOCAL LocalAlloc(UINT uFlags, SIZE_T uBytes)
            {
                SIZE_T size = uBytes ? uBytes : 1;
                if (uFlags & 0x0040) /* LMEM_ZEROINIT */
                    return calloc(1, size);
                return malloc(size);
            }"""),

        "local_free": textwrap.dedent("""\
            WINAPI_EXPORT HLOCAL LocalFree(HLOCAL hMem)
            {
                free(hMem);
                return NULL;
            }"""),
    }
    return templates.get(key)


def _thread_template(key: str) -> Optional[str]:
    """Return C implementation for a threading template."""
    templates = {
        "create_thread": textwrap.dedent("""\
            WINAPI_EXPORT HANDLE CreateThread(
                LPSECURITY_ATTRIBUTES lpThreadAttributes,
                SIZE_T dwStackSize,
                LPTHREAD_START_ROUTINE lpStartAddress,
                LPVOID lpParameter,
                DWORD dwCreationFlags,
                LPDWORD lpThreadId)
            {
                TRUST_CHECK_RET(TRUST_GATE_THREAD_CREATE, "CreateThread", NULL);
                (void)lpThreadAttributes; (void)dwStackSize; (void)dwCreationFlags;

                typedef struct {
                    LPTHREAD_START_ROUTINE func;
                    LPVOID param;
                } thread_trampoline_t;

                /* Note: in production code, use the thread_data_t structure from
                 * kernel32_internal.h with proper suspend/resume support.
                 * This is a simplified template for auto-generated stubs. */
                pthread_t tid;
                thread_trampoline_t *tt = malloc(sizeof(thread_trampoline_t));
                if (!tt) {
                    set_last_error(ERROR_NOT_ENOUGH_MEMORY);
                    return NULL;
                }
                tt->func = lpStartAddress;
                tt->param = lpParameter;

                /* Trampoline: call ms_abi function from sysv_abi pthread */
                static void *thread_entry(void *arg) {
                    thread_trampoline_t *t = (thread_trampoline_t *)arg;
                    LPTHREAD_START_ROUTINE fn = t->func;
                    LPVOID p = t->param;
                    free(t);
                    DWORD ret = fn(p);
                    return (void *)(uintptr_t)ret;
                }

                if (pthread_create(&tid, NULL, thread_entry, tt) != 0) {
                    free(tt);
                    set_last_error(errno_to_win32_error(errno));
                    return NULL;
                }

                if (lpThreadId)
                    *lpThreadId = (DWORD)(uintptr_t)tid;
                return handle_alloc(HANDLE_TYPE_THREAD, -1, (void *)(uintptr_t)tid);
            }"""),

        "exit_thread": textwrap.dedent("""\
            WINAPI_EXPORT void ExitThread(DWORD dwExitCode)
            {
                pthread_exit((void *)(uintptr_t)dwExitCode);
            }"""),

        "sleep_func": textwrap.dedent("""\
            WINAPI_EXPORT void Sleep(DWORD dwMilliseconds)
            {
                if (dwMilliseconds == 0) {
                    sched_yield();
                    return;
                }
                struct timespec ts;
                ts.tv_sec = dwMilliseconds / 1000;
                ts.tv_nsec = (dwMilliseconds % 1000) * 1000000L;
                nanosleep(&ts, NULL);
            }"""),

        "sleep_ex": textwrap.dedent("""\
            WINAPI_EXPORT DWORD SleepEx(DWORD dwMilliseconds, BOOL bAlertable)
            {
                (void)bAlertable;
                if (dwMilliseconds == 0) {
                    sched_yield();
                    return 0;
                }
                struct timespec ts;
                ts.tv_sec = dwMilliseconds / 1000;
                ts.tv_nsec = (dwMilliseconds % 1000) * 1000000L;
                nanosleep(&ts, NULL);
                return 0;
            }"""),

        "get_current_thread_id": textwrap.dedent("""\
            WINAPI_EXPORT DWORD GetCurrentThreadId(void)
            {
                return (DWORD)syscall(SYS_gettid);
            }"""),

        "get_current_thread": textwrap.dedent("""\
            WINAPI_EXPORT HANDLE GetCurrentThread(void)
            {
                return (HANDLE)(intptr_t)-2; /* Windows pseudo-handle for current thread */
            }"""),

        "switch_to_thread": textwrap.dedent("""\
            WINAPI_EXPORT BOOL SwitchToThread(void)
            {
                return sched_yield() == 0 ? TRUE : FALSE;
            }"""),

        "tls_alloc": textwrap.dedent("""\
            WINAPI_EXPORT DWORD TlsAlloc(void)
            {
                pthread_key_t key;
                if (pthread_key_create(&key, NULL) != 0) {
                    set_last_error(ERROR_NOT_ENOUGH_MEMORY);
                    return (DWORD)-1; /* TLS_OUT_OF_INDEXES */
                }
                return (DWORD)key;
            }"""),

        "tls_free": textwrap.dedent("""\
            WINAPI_EXPORT BOOL TlsFree(DWORD dwTlsIndex)
            {
                if (pthread_key_delete((pthread_key_t)dwTlsIndex) != 0) {
                    set_last_error(ERROR_INVALID_PARAMETER);
                    return FALSE;
                }
                return TRUE;
            }"""),

        "tls_get_value": textwrap.dedent("""\
            WINAPI_EXPORT LPVOID TlsGetValue(DWORD dwTlsIndex)
            {
                set_last_error(ERROR_SUCCESS);
                return pthread_getspecific((pthread_key_t)dwTlsIndex);
            }"""),

        "tls_set_value": textwrap.dedent("""\
            WINAPI_EXPORT BOOL TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue)
            {
                if (pthread_setspecific((pthread_key_t)dwTlsIndex, lpTlsValue) != 0) {
                    set_last_error(ERROR_INVALID_PARAMETER);
                    return FALSE;
                }
                return TRUE;
            }"""),

        "wait_single": textwrap.dedent("""\
            WINAPI_EXPORT DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
            {
                handle_entry_t *entry = handle_lookup(hHandle);
                if (!entry) {
                    set_last_error(ERROR_INVALID_HANDLE);
                    return 0xFFFFFFFF; /* WAIT_FAILED */
                }

                /* For threads: join with timeout */
                if (entry->type == HANDLE_TYPE_THREAD) {
                    pthread_t tid = (pthread_t)(uintptr_t)entry->data;
                    if (dwMilliseconds == 0xFFFFFFFF) { /* INFINITE */
                        pthread_join(tid, NULL);
                        return 0; /* WAIT_OBJECT_0 */
                    }
                    /* Timed wait: use pthread_timedjoin_np if available */
                    struct timespec ts;
                    clock_gettime(CLOCK_REALTIME, &ts);
                    ts.tv_sec += dwMilliseconds / 1000;
                    ts.tv_nsec += (dwMilliseconds % 1000) * 1000000L;
                    if (ts.tv_nsec >= 1000000000L) {
                        ts.tv_sec++;
                        ts.tv_nsec -= 1000000000L;
                    }
                    if (pthread_timedjoin_np(tid, NULL, &ts) == 0)
                        return 0;
                    return 0x00000102; /* WAIT_TIMEOUT */
                }

                /* For file descriptors: use poll() */
                int fd = handle_get_fd(hHandle);
                if (fd >= 0) {
                    int timeout = (dwMilliseconds == 0xFFFFFFFF) ? -1 : (int)dwMilliseconds;
                    struct pollfd pfd = { .fd = fd, .events = POLLIN };
                    int ret = poll(&pfd, 1, timeout);
                    if (ret > 0) return 0;
                    if (ret == 0) return 0x00000102; /* WAIT_TIMEOUT */
                }

                set_last_error(ERROR_INVALID_HANDLE);
                return 0xFFFFFFFF;
            }"""),

        "create_event": textwrap.dedent("""\
            WINAPI_EXPORT HANDLE CreateEventA(
                LPSECURITY_ATTRIBUTES lpEventAttributes,
                BOOL bManualReset, BOOL bInitialState, LPCSTR lpName)
            {
                (void)lpEventAttributes; (void)lpName;

                typedef struct {
                    pthread_mutex_t mutex;
                    pthread_cond_t  cond;
                    int             signaled;
                    int             manual_reset;
                } event_data_t;

                event_data_t *ev = calloc(1, sizeof(event_data_t));
                if (!ev) {
                    set_last_error(ERROR_NOT_ENOUGH_MEMORY);
                    return NULL;
                }
                pthread_mutex_init(&ev->mutex, NULL);
                pthread_cond_init(&ev->cond, NULL);
                ev->signaled = bInitialState ? 1 : 0;
                ev->manual_reset = bManualReset ? 1 : 0;

                return handle_alloc(HANDLE_TYPE_EVENT, -1, ev);
            }"""),

        "set_event": textwrap.dedent("""\
            WINAPI_EXPORT BOOL SetEvent(HANDLE hEvent)
            {
                handle_entry_t *entry = handle_lookup(hEvent);
                if (!entry || entry->type != HANDLE_TYPE_EVENT) {
                    set_last_error(ERROR_INVALID_HANDLE);
                    return FALSE;
                }

                typedef struct {
                    pthread_mutex_t mutex;
                    pthread_cond_t  cond;
                    int             signaled;
                    int             manual_reset;
                } event_data_t;

                event_data_t *ev = (event_data_t *)entry->data;
                pthread_mutex_lock(&ev->mutex);
                ev->signaled = 1;
                if (ev->manual_reset)
                    pthread_cond_broadcast(&ev->cond);
                else
                    pthread_cond_signal(&ev->cond);
                pthread_mutex_unlock(&ev->mutex);
                return TRUE;
            }"""),

        "reset_event": textwrap.dedent("""\
            WINAPI_EXPORT BOOL ResetEvent(HANDLE hEvent)
            {
                handle_entry_t *entry = handle_lookup(hEvent);
                if (!entry || entry->type != HANDLE_TYPE_EVENT) {
                    set_last_error(ERROR_INVALID_HANDLE);
                    return FALSE;
                }

                typedef struct {
                    pthread_mutex_t mutex;
                    pthread_cond_t  cond;
                    int             signaled;
                    int             manual_reset;
                } event_data_t;

                event_data_t *ev = (event_data_t *)entry->data;
                pthread_mutex_lock(&ev->mutex);
                ev->signaled = 0;
                pthread_mutex_unlock(&ev->mutex);
                return TRUE;
            }"""),

        "create_mutex": textwrap.dedent("""\
            WINAPI_EXPORT HANDLE CreateMutexA(
                LPSECURITY_ATTRIBUTES lpMutexAttributes,
                BOOL bInitialOwner, LPCSTR lpName)
            {
                (void)lpMutexAttributes; (void)lpName;

                typedef struct {
                    pthread_mutex_t mutex;
                    DWORD           owner;
                } mutex_data_t;

                mutex_data_t *md = calloc(1, sizeof(mutex_data_t));
                if (!md) {
                    set_last_error(ERROR_NOT_ENOUGH_MEMORY);
                    return NULL;
                }

                pthread_mutexattr_t attr;
                pthread_mutexattr_init(&attr);
                pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
                pthread_mutex_init(&md->mutex, &attr);
                pthread_mutexattr_destroy(&attr);
                md->owner = 0;

                if (bInitialOwner) {
                    pthread_mutex_lock(&md->mutex);
                    md->owner = (DWORD)syscall(SYS_gettid);
                }

                return handle_alloc(HANDLE_TYPE_MUTEX, -1, md);
            }"""),

        "release_mutex": textwrap.dedent("""\
            WINAPI_EXPORT BOOL ReleaseMutex(HANDLE hMutex)
            {
                handle_entry_t *entry = handle_lookup(hMutex);
                if (!entry || entry->type != HANDLE_TYPE_MUTEX) {
                    set_last_error(ERROR_INVALID_HANDLE);
                    return FALSE;
                }

                typedef struct {
                    pthread_mutex_t mutex;
                    DWORD           owner;
                } mutex_data_t;

                mutex_data_t *md = (mutex_data_t *)entry->data;
                md->owner = 0;
                pthread_mutex_unlock(&md->mutex);
                return TRUE;
            }"""),
    }
    return templates.get(key)


def _registry_template(key: str) -> Optional[str]:
    """Return C implementation for a registry template."""
    templates = {
        "reg_open_key": textwrap.dedent("""\
            WINAPI_EXPORT LONG RegOpenKeyExA(
                HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions,
                DWORD samDesired, HKEY *phkResult)
            {
                TRUST_CHECK_RET(TRUST_GATE_REGISTRY_READ, "RegOpenKeyExA", ERROR_ACCESS_DENIED);
                (void)ulOptions; (void)samDesired;
                return registry_open_key(hKey, lpSubKey, phkResult);
            }"""),

        "reg_create_key": textwrap.dedent("""\
            WINAPI_EXPORT LONG RegCreateKeyExA(
                HKEY hKey, LPCSTR lpSubKey, DWORD Reserved,
                LPSTR lpClass, DWORD dwOptions, DWORD samDesired,
                LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                HKEY *phkResult, LPDWORD lpdwDisposition)
            {
                TRUST_CHECK_RET(TRUST_GATE_REGISTRY_WRITE, "RegCreateKeyExA", ERROR_ACCESS_DENIED);
                (void)Reserved; (void)lpClass; (void)dwOptions;
                (void)samDesired; (void)lpSecurityAttributes;
                if (lpdwDisposition) *lpdwDisposition = 1; /* REG_CREATED_NEW_KEY */
                return registry_create_key(hKey, lpSubKey, phkResult);
            }"""),

        "reg_close_key": textwrap.dedent("""\
            WINAPI_EXPORT LONG RegCloseKey(HKEY hKey)
            {
                return registry_close_key(hKey);
            }"""),

        "reg_query_value": textwrap.dedent("""\
            WINAPI_EXPORT LONG RegQueryValueExA(
                HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved,
                LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
            {
                TRUST_CHECK_RET(TRUST_GATE_REGISTRY_READ, "RegQueryValueExA", ERROR_ACCESS_DENIED);
                (void)lpReserved;
                return registry_get_value(hKey, NULL, lpValueName,
                                          lpType, lpData, lpcbData);
            }"""),

        "reg_set_value": textwrap.dedent("""\
            WINAPI_EXPORT LONG RegSetValueExA(
                HKEY hKey, LPCSTR lpValueName, DWORD Reserved,
                DWORD dwType, const BYTE *lpData, DWORD cbData)
            {
                TRUST_CHECK_RET(TRUST_GATE_REGISTRY_WRITE, "RegSetValueExA", ERROR_ACCESS_DENIED);
                (void)Reserved;
                return registry_set_value(hKey, lpValueName, dwType, lpData, cbData);
            }"""),

        "reg_delete_key": textwrap.dedent("""\
            WINAPI_EXPORT LONG RegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey)
            {
                TRUST_CHECK_RET(TRUST_GATE_REGISTRY_WRITE, "RegDeleteKeyA", ERROR_ACCESS_DENIED);
                return registry_delete_key(hKey, lpSubKey);
            }"""),

        "reg_delete_value": textwrap.dedent("""\
            WINAPI_EXPORT LONG RegDeleteValueA(HKEY hKey, LPCSTR lpValueName)
            {
                TRUST_CHECK_RET(TRUST_GATE_REGISTRY_WRITE, "RegDeleteValueA", ERROR_ACCESS_DENIED);
                return registry_delete_value(hKey, lpValueName);
            }"""),

        "reg_enum_key": textwrap.dedent("""\
            WINAPI_EXPORT LONG RegEnumKeyExA(
                HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcchName,
                LPDWORD lpReserved, LPSTR lpClass, LPDWORD lpcchClass,
                PFILETIME lpftLastWriteTime)
            {
                (void)lpReserved; (void)lpClass; (void)lpcchClass;
                (void)lpftLastWriteTime;
                return registry_enum_key(hKey, dwIndex, lpName, lpcchName);
            }"""),

        "reg_enum_value": textwrap.dedent("""\
            WINAPI_EXPORT LONG RegEnumValueA(
                HKEY hKey, DWORD dwIndex, LPSTR lpValueName,
                LPDWORD lpcchValueName, LPDWORD lpReserved,
                LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
            {
                (void)lpReserved;
                return registry_enum_value(hKey, dwIndex, lpValueName,
                                           lpcchValueName, lpType, lpData, lpcbData);
            }"""),
    }
    return templates.get(key)


def _network_template(key: str) -> Optional[str]:
    """Return C implementation for a network template."""
    templates = {
        "wsa_startup": textwrap.dedent("""\
            WINAPI_EXPORT int WSAStartup(WORD wVersionRequested, void *lpWSAData)
            {
                (void)wVersionRequested;
                /* Fill in a minimal WSADATA structure */
                if (lpWSAData) {
                    memset(lpWSAData, 0, 400); /* sizeof(WSADATA) */
                    uint16_t *ver = (uint16_t *)lpWSAData;
                    ver[0] = 0x0202; /* wVersion = 2.2 */
                    ver[1] = 0x0202; /* wHighVersion = 2.2 */
                }
                return 0; /* Success */
            }"""),

        "wsa_cleanup": textwrap.dedent("""\
            WINAPI_EXPORT int WSACleanup(void)
            {
                return 0; /* No-op on Linux */
            }"""),

        "wsa_get_last_error": textwrap.dedent("""\
            WINAPI_EXPORT int WSAGetLastError(void)
            {
                return (int)get_last_error();
            }"""),

        "wsa_set_last_error": textwrap.dedent("""\
            WINAPI_EXPORT void WSASetLastError(int iError)
            {
                set_last_error((DWORD)iError);
            }"""),

        "sock_socket": textwrap.dedent("""\
            WINAPI_EXPORT int pe_socket(int af, int type, int protocol)
            {
                TRUST_CHECK_RET(TRUST_GATE_NET_CONNECT, "socket", -1);
                int fd = socket(af, type, protocol);
                if (fd < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return -1;
                }
                /* Store as a HANDLE internally, but return int (SOCKET) */
                handle_alloc(HANDLE_TYPE_SOCKET, fd, NULL);
                return fd;
            }"""),

        "sock_close": textwrap.dedent("""\
            WINAPI_EXPORT int closesocket(int s)
            {
                if (close(s) < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return -1;
                }
                return 0;
            }"""),

        "sock_connect": textwrap.dedent("""\
            WINAPI_EXPORT int pe_connect(int s, const void *name, int namelen)
            {
                TRUST_CHECK_RET(TRUST_GATE_NET_CONNECT, "connect", -1);
                if (connect(s, (const struct sockaddr *)name, (socklen_t)namelen) < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return -1;
                }
                return 0;
            }"""),

        "sock_bind": textwrap.dedent("""\
            WINAPI_EXPORT int pe_bind(int s, const void *name, int namelen)
            {
                TRUST_CHECK_RET(TRUST_GATE_NET_LISTEN, "bind", -1);
                if (bind(s, (const struct sockaddr *)name, (socklen_t)namelen) < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return -1;
                }
                return 0;
            }"""),

        "sock_listen": textwrap.dedent("""\
            WINAPI_EXPORT int pe_listen(int s, int backlog)
            {
                TRUST_CHECK_RET(TRUST_GATE_NET_LISTEN, "listen", -1);
                if (listen(s, backlog) < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return -1;
                }
                return 0;
            }"""),

        "sock_accept": textwrap.dedent("""\
            WINAPI_EXPORT int pe_accept(int s, void *addr, int *addrlen)
            {
                socklen_t len = addrlen ? (socklen_t)*addrlen : 0;
                int fd = accept(s, (struct sockaddr *)addr, addrlen ? &len : NULL);
                if (fd < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return -1;
                }
                if (addrlen) *addrlen = (int)len;
                handle_alloc(HANDLE_TYPE_SOCKET, fd, NULL);
                return fd;
            }"""),

        "sock_send": textwrap.dedent("""\
            WINAPI_EXPORT int pe_send(int s, const void *buf, int len, int flags)
            {
                ssize_t n = send(s, buf, (size_t)len, flags);
                if (n < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return -1;
                }
                return (int)n;
            }"""),

        "sock_recv": textwrap.dedent("""\
            WINAPI_EXPORT int pe_recv(int s, void *buf, int len, int flags)
            {
                ssize_t n = recv(s, buf, (size_t)len, flags);
                if (n < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return -1;
                }
                return (int)n;
            }"""),

        "sock_select": textwrap.dedent("""\
            WINAPI_EXPORT int pe_select(int nfds, void *readfds, void *writefds,
                                        void *exceptfds, void *timeout)
            {
                /* Windows fd_set and Linux fd_set are compatible for POSIX sockets */
                return select(nfds, (fd_set *)readfds, (fd_set *)writefds,
                              (fd_set *)exceptfds, (struct timeval *)timeout);
            }"""),

        "sock_setsockopt": textwrap.dedent("""\
            WINAPI_EXPORT int pe_setsockopt(int s, int level, int optname,
                                            const void *optval, int optlen)
            {
                if (setsockopt(s, level, optname, optval, (socklen_t)optlen) < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return -1;
                }
                return 0;
            }"""),

        "sock_getsockopt": textwrap.dedent("""\
            WINAPI_EXPORT int pe_getsockopt(int s, int level, int optname,
                                            void *optval, int *optlen)
            {
                socklen_t len = optlen ? (socklen_t)*optlen : 0;
                if (getsockopt(s, level, optname, optval, &len) < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return -1;
                }
                if (optlen) *optlen = (int)len;
                return 0;
            }"""),

        "sock_ioctlsocket": textwrap.dedent("""\
            WINAPI_EXPORT int ioctlsocket(int s, long cmd, unsigned long *argp)
            {
                /* FIONBIO (0x8004667E): set non-blocking mode */
                if (cmd == (long)0x8004667E) {
                    int flags = fcntl(s, F_GETFL, 0);
                    if (flags < 0) return -1;
                    if (argp && *argp)
                        flags |= O_NONBLOCK;
                    else
                        flags &= ~O_NONBLOCK;
                    return fcntl(s, F_SETFL, flags) < 0 ? -1 : 0;
                }
                set_last_error(ERROR_INVALID_PARAMETER);
                return -1;
            }"""),

        "sock_getaddrinfo": textwrap.dedent("""\
            WINAPI_EXPORT int pe_getaddrinfo(const char *node, const char *service,
                                             const void *hints, void **res)
            {
                /* Direct passthrough -- POSIX getaddrinfo is compatible */
                return getaddrinfo(node, service,
                                   (const struct addrinfo *)hints,
                                   (struct addrinfo **)res);
            }"""),

        "sock_freeaddrinfo": textwrap.dedent("""\
            WINAPI_EXPORT void pe_freeaddrinfo(void *ai)
            {
                freeaddrinfo((struct addrinfo *)ai);
            }"""),

        "sock_gethostbyname": textwrap.dedent("""\
            WINAPI_EXPORT void *pe_gethostbyname(const char *name)
            {
                return (void *)gethostbyname(name);
            }"""),

        "sock_gethostname": textwrap.dedent("""\
            WINAPI_EXPORT int pe_gethostname(char *name, int namelen)
            {
                if (gethostname(name, (size_t)namelen) < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return -1;
                }
                return 0;
            }"""),

        "sock_shutdown": textwrap.dedent("""\
            WINAPI_EXPORT int pe_shutdown(int s, int how)
            {
                if (shutdown(s, how) < 0) {
                    set_last_error(errno_to_win32_error(errno));
                    return -1;
                }
                return 0;
            }"""),
    }
    return templates.get(key)


# ---------------------------------------------------------------------------
# Include headers per category
# ---------------------------------------------------------------------------

_CATEGORY_HEADERS: dict[str, list[str]] = {
    "file": [
        "<stdio.h>", "<stdlib.h>", "<string.h>", "<fcntl.h>", "<unistd.h>",
        "<sys/stat.h>", "<sys/mman.h>", "<errno.h>", "<limits.h>",
        '"common/dll_common.h"', '"compat/trust_gate.h"',
    ],
    "memory": [
        "<stdio.h>", "<stdlib.h>", "<string.h>", "<sys/mman.h>",
        "<errno.h>", "<malloc.h>",
        '"common/dll_common.h"', '"compat/trust_gate.h"',
    ],
    "thread": [
        "<stdio.h>", "<stdlib.h>", "<string.h>", "<pthread.h>",
        "<semaphore.h>", "<unistd.h>", "<sched.h>", "<time.h>",
        "<errno.h>", "<sys/syscall.h>", "<poll.h>",
        '"common/dll_common.h"', '"compat/trust_gate.h"',
    ],
    "registry": [
        "<stdio.h>", "<stdlib.h>", "<string.h>",
        '"common/dll_common.h"', '"compat/trust_gate.h"',
    ],
    "network": [
        "<stdio.h>", "<stdlib.h>", "<string.h>", "<unistd.h>",
        "<sys/socket.h>", "<sys/select.h>", "<netinet/in.h>",
        "<netinet/tcp.h>", "<arpa/inet.h>", "<netdb.h>",
        "<fcntl.h>", "<errno.h>", "<poll.h>",
        '"common/dll_common.h"', '"compat/trust_gate.h"',
    ],
    "generic": [
        "<stdio.h>", "<stdlib.h>", "<string.h>",
        '"common/dll_common.h"',
    ],
}


# ---------------------------------------------------------------------------
# StubGenerator
# ---------------------------------------------------------------------------

class StubGenerator:
    """Generates C stub implementations from API signatures."""

    # Available template families
    TEMPLATE_FAMILIES = ["file", "memory", "thread", "registry", "network", "generic"]

    # Cap the in-memory generated-stub cache to prevent unbounded growth over
    # long uptimes (each entry retains the full generated C source).
    MAX_GENERATED_CACHE = 2048

    def __init__(self, output_dir: str = "/tmp/generated-stubs"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self._generated: dict[str, dict] = {}  # name -> result dict

    def _map_type(self, win_type: str) -> str:
        """Map a Windows API type to its C equivalent."""
        # Strip whitespace and try exact match
        clean = win_type.strip()
        if clean in WIN_TYPES:
            return WIN_TYPES[clean]
        # Handle pointer variants: "DWORD *" -> "uint32_t *"
        if clean.endswith("*"):
            base = clean[:-1].strip()
            if base in WIN_TYPES:
                mapped = WIN_TYPES[base]
                if mapped.endswith("*"):
                    return mapped  # Already a pointer
                return mapped + " *"
        # Handle const prefix: "const DWORD" -> "const uint32_t"
        if clean.startswith("const "):
            rest = clean[6:].strip()
            mapped = self._map_type(rest)
            if mapped.startswith("const "):
                return mapped
            return "const " + mapped
        return clean  # Pass through unknown types

    def _default_return(self, return_type: str) -> str:
        """Determine the default return value for a given return type."""
        rt = return_type.strip()
        mapped = self._map_type(rt)

        if rt == "void" or mapped == "void":
            return ""
        if rt == "HANDLE" or mapped == "void *":
            return "return NULL;"
        if rt in ("BOOL", "int") or mapped in ("int", "int32_t"):
            return "return 0;"  # FALSE for BOOL
        if rt in ("DWORD", "UINT", "ULONG") or mapped in ("uint32_t", "unsigned int"):
            return "return 0;"
        if rt in ("LONG", "HRESULT", "NTSTATUS") or mapped == "int32_t":
            return "return 0;"
        if rt == "SIZE_T" or mapped == "size_t":
            return "return 0;"
        if rt in ("LPVOID", "PVOID") or "void *" in mapped:
            return "return NULL;"
        if "*" in mapped:
            return "return NULL;"
        return "return 0;"

    def _failure_return(self, sig: WinApiSignature) -> str:
        """Determine the failure return value for a signature."""
        rt = sig.return_type.strip()
        if rt == "HANDLE":
            return "INVALID_HANDLE_VALUE"
        if rt == "BOOL":
            return "FALSE"
        if rt in ("LPVOID", "PVOID", "void *"):
            return "NULL"
        if rt in ("DWORD", "UINT", "LONG", "HRESULT"):
            return "(DWORD)-1"
        if rt == "NTSTATUS":
            return "((NTSTATUS)0xC0000001)"  # STATUS_UNSUCCESSFUL
        if rt == "int":
            return "-1"
        return "0"

    def generate_stub(self, sig: WinApiSignature, strategy: str = "auto") -> dict:
        """Generate a C stub implementation for a Windows API function.

        Args:
            sig: Parsed API signature.
            strategy: "auto" (pick best template), "template" (use known
                      template), or "generic" (always generate no-op stub).

        Returns:
            {"code": str, "filename": str, "confidence": float, "notes": str}
        """
        code = None
        confidence = 0.0
        notes = ""

        if strategy in ("auto", "template"):
            code, confidence, notes = self._try_template(sig)

        if code is None or strategy == "generic":
            code = self._generate_generic_stub(sig)
            confidence = 0.3
            notes = "Auto-generated no-op stub with stderr logging."

        # Determine output filename
        dll_base = sig.dll.lower().replace(".dll", "").replace(".", "_")
        filename = f"{dll_base}_{sig.name}.c"
        filepath = os.path.join(self.output_dir, filename)

        result = {
            "code": code,
            "filename": filename,
            "filepath": filepath,
            "confidence": confidence,
            "notes": notes,
            "signature": sig.to_dict(),
        }

        if (len(self._generated) >= self.MAX_GENERATED_CACHE
                and sig.name not in self._generated):
            # Evict oldest insertion to keep dict bounded (dict is insertion-ordered)
            oldest = next(iter(self._generated))
            del self._generated[oldest]
        self._generated[sig.name] = result
        return result

    def _try_template(self, sig: WinApiSignature) -> tuple[Optional[str], float, str]:
        """Try to find a matching template for the given signature."""
        name = sig.name

        # File I/O
        if name in _FILE_IO_TEMPLATES:
            code = _file_io_template(_FILE_IO_TEMPLATES[name])
            if code:
                return code, 0.9, f"Matched file I/O template: {name} -> POSIX"

        # Memory
        if name in _MEMORY_TEMPLATES:
            code = _memory_template(_MEMORY_TEMPLATES[name])
            if code:
                return code, 0.9, f"Matched memory template: {name} -> mmap/malloc"

        # Threading
        if name in _THREAD_TEMPLATES:
            code = _thread_template(_THREAD_TEMPLATES[name])
            if code:
                return code, 0.85, f"Matched threading template: {name} -> pthread"

        # Registry
        if name in _REGISTRY_TEMPLATES:
            code = _registry_template(_REGISTRY_TEMPLATES[name])
            if code:
                return code, 0.85, f"Matched registry template: {name} -> filesystem"

        # Network
        if name in _NETWORK_TEMPLATES:
            code = _network_template(_NETWORK_TEMPLATES[name])
            if code:
                return code, 0.9, f"Matched network template: {name} -> POSIX socket"

        return None, 0.0, ""

    def _generate_generic_stub(self, sig: WinApiSignature) -> str:
        """Generate a safe no-op stub when no mapping exists."""
        mapped_return = self._map_type(sig.return_type)
        params_parts = []
        for p in sig.params:
            params_parts.append(f"{self._map_type(p.type)} {p.name}")
        params_str = ", ".join(params_parts) if params_parts else "void"

        # (void) casts for unused parameters
        void_lines = []
        for p in sig.params:
            void_lines.append(f"    (void){p.name};")
        void_block = "\n".join(void_lines)

        # Return value
        ret = self._default_return(sig.return_type)

        # Build the function
        lines = []
        lines.append(f"WINAPI_EXPORT {mapped_return} {sig.name}({params_str})")
        lines.append("{")
        if void_block:
            lines.append(void_block)
        lines.append(f'    fprintf(stderr, "[stub_gen] {sig.dll}!{sig.name} called '
                     f'(auto-generated stub)\\n");')
        if ret:
            lines.append(f"    {ret}")
        lines.append("}")

        return "\n".join(lines)

    def generate_dll_stubs(self, dll_name: str, signatures: list[WinApiSignature]) -> str:
        """Generate a complete .c file with all stubs for a DLL.

        Returns the full C source code as a string.
        """
        # Determine which categories are present
        categories = set()
        for sig in signatures:
            cat = sig.category or _classify_api(sig.name, dll_name)
            categories.add(cat)

        # Collect all needed headers
        all_headers: list[str] = []
        seen: set[str] = set()
        for cat in categories:
            for h in _CATEGORY_HEADERS.get(cat, _CATEGORY_HEADERS["generic"]):
                if h not in seen:
                    all_headers.append(h)
                    seen.add(h)
        # Ensure at minimum the generic headers
        for h in _CATEGORY_HEADERS["generic"]:
            if h not in seen:
                all_headers.append(h)
                seen.add(h)

        # Build header block
        dll_base = dll_name.lower().replace(".dll", "").replace(".", "_")
        header_lines = []
        header_lines.append(f"/*")
        header_lines.append(f" * {dll_base}_stubs.c - Auto-generated stubs for {dll_name}")
        header_lines.append(f" *")
        header_lines.append(f" * Generated by ai-control stub_generator.")
        header_lines.append(f" * {len(signatures)} function(s) implemented.")
        header_lines.append(f" */")
        header_lines.append("")
        header_lines.append("#define _GNU_SOURCE")

        # Separate system vs project includes
        sys_headers = [h for h in all_headers if h.startswith("<")]
        proj_headers = [h for h in all_headers if h.startswith('"')]

        for h in sys_headers:
            header_lines.append(f"#include {h}")
        header_lines.append("")
        for h in proj_headers:
            header_lines.append(f"#include {h}")
        header_lines.append("")

        # Generate each stub
        stub_blocks = []
        for sig in signatures:
            result = self.generate_stub(sig)
            stub_blocks.append(f"/* {sig.name} -- confidence: {result['confidence']:.0%} */")
            stub_blocks.append(result["code"])
            stub_blocks.append("")

        return "\n".join(header_lines) + "\n" + "\n".join(stub_blocks)

    def compile_stub(self, c_file: str, so_file: str) -> dict:
        """Compile a generated .c file into a .so shared library.

        Uses the same compiler flags as the PE loader Makefile.
        """
        cmd = [
            "gcc", "-shared", "-fPIC", "-o", so_file, c_file,
            "-I", "/usr/include/pe-compat",  # installed PE compat headers
            "-I", "pe-loader/include",        # in-tree headers
            "-I", "pe-loader/dlls",           # for common/dll_common.h
            "-Wall", "-Wextra",
            "-Wno-unused-parameter",
            "-Wno-unused-variable",
            "-lpthread",
        ]
        logger.info("Compiling: %s -> %s", c_file, so_file)
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )
            success = result.returncode == 0
            output = (result.stdout + result.stderr).strip()
            if not success:
                logger.error("Compilation failed: %s", output)
            return {
                "success": success,
                "returncode": result.returncode,
                "output": output,
                "command": " ".join(cmd),
            }
        except FileNotFoundError:
            return {
                "success": False,
                "returncode": -1,
                "output": "gcc not found. Install build-essential or gcc.",
                "command": " ".join(cmd),
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "returncode": -1,
                "output": "Compilation timed out (30s limit).",
                "command": " ".join(cmd),
            }

    def list_templates(self) -> dict:
        """List all available API templates by family."""
        return {
            "file": sorted(_FILE_IO_TEMPLATES.keys()),
            "memory": sorted(_MEMORY_TEMPLATES.keys()),
            "thread": sorted(_THREAD_TEMPLATES.keys()),
            "registry": sorted(_REGISTRY_TEMPLATES.keys()),
            "network": sorted(_NETWORK_TEMPLATES.keys()),
            "total_templates": (
                len(_FILE_IO_TEMPLATES) + len(_MEMORY_TEMPLATES) +
                len(_THREAD_TEMPLATES) + len(_REGISTRY_TEMPLATES) +
                len(_NETWORK_TEMPLATES)
            ),
        }

    def get_generated(self) -> dict:
        """Return all generated stubs from this session."""
        return {
            name: {
                "filename": r["filename"],
                "confidence": r["confidence"],
                "notes": r["notes"],
            }
            for name, r in self._generated.items()
        }

    def save_stub(self, name: str) -> Optional[str]:
        """Write a generated stub to disk. Returns the filepath or None."""
        if name not in self._generated:
            return None
        result = self._generated[name]
        filepath = result["filepath"]
        # Ensure generated file stays within output directory
        real_output = os.path.realpath(self.output_dir)
        real_filepath = os.path.realpath(filepath)
        if not real_filepath.startswith(real_output + os.sep) and real_filepath != real_output:
            raise ValueError(f"Path traversal detected: {filepath} escapes {self.output_dir}")
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as f:
            f.write(result["code"])
        logger.info("Saved stub: %s -> %s", name, filepath)
        return filepath

    def save_dll(self, dll_name: str, signatures: list[WinApiSignature]) -> str:
        """Generate a complete .c file for a DLL and write it to disk."""
        code = self.generate_dll_stubs(dll_name, signatures)
        dll_base = dll_name.lower().replace(".dll", "").replace(".", "_")
        filename = f"{dll_base}_stubs.c"
        filepath = os.path.join(self.output_dir, filename)
        # Ensure generated file stays within output directory
        real_output = os.path.realpath(self.output_dir)
        real_filepath = os.path.realpath(filepath)
        if not real_filepath.startswith(real_output + os.sep) and real_filepath != real_output:
            raise ValueError(f"Path traversal detected: {filepath} escapes {self.output_dir}")
        with open(filepath, "w") as f:
            f.write(code)
        logger.info("Saved DLL stubs: %s -> %s (%d functions)",
                     dll_name, filepath, len(signatures))
        return filepath
