"""
Windows API Signature Database

Comprehensive database of 200+ Windows API function signatures organized by DLL.
Each entry maps the function to its Linux equivalent, implementation complexity,
and current stub status.  Used by the auto-stub generator to create C
implementations for the PE loader.

Usage:
    db = WinApiDatabase()
    sig = db.lookup("kernel32.dll", "CreateFileA")
    results = db.search("thread")
    unimpl = db.get_unimplemented("kernel32.dll")
    stats = db.get_stats()
"""

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from typing import Optional

logger = logging.getLogger("ai-control.win_api_db")

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class WinApiSignature:
    dll: str                     # "kernel32.dll"
    name: str                    # "CreateFileA"
    return_type: str             # "HANDLE"
    params: list[dict]           # [{"name": "lpFileName", "type": "LPCSTR", "direction": "in"}, ...]
    category: str                # "file_io", "memory", "thread", "sync", ...
    linux_equivalent: str        # "open" or "" if no direct mapping
    complexity: str              # "trivial", "moderate", "complex", "needs_research"
    notes: str                   # Implementation hints
    implemented: bool            # Whether we already have this in our stubs

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Built-in signature data  (200+ entries)
# ---------------------------------------------------------------------------

def _p(name: str, ptype: str, direction: str = "in") -> dict:
    """Shorthand for building a parameter dict."""
    return {"name": name, "type": ptype, "direction": direction}


def _build_default_signatures() -> list[dict]:
    """Return the built-in list of 200+ API signatures as raw dicts."""
    sigs: list[dict] = []

    def _add(dll, name, ret, params, cat, linux, cpx, notes, impl=False):
        sigs.append({
            "dll": dll,
            "name": name,
            "return_type": ret,
            "params": params,
            "category": cat,
            "linux_equivalent": linux,
            "complexity": cpx,
            "notes": notes,
            "implemented": impl,
        })

    # ===================================================================
    # FILE I/O  (kernel32.dll)  -- 30+ functions
    # ===================================================================
    _add("kernel32.dll", "CreateFileA", "HANDLE", [
        _p("lpFileName", "LPCSTR"), _p("dwDesiredAccess", "DWORD"),
        _p("dwShareMode", "DWORD"), _p("lpSecurityAttributes", "LPSECURITY_ATTRIBUTES"),
        _p("dwCreationDisposition", "DWORD"), _p("dwFlagsAndAttributes", "DWORD"),
        _p("hTemplateFile", "HANDLE"),
    ], "file_io", "open()", "complex",
        "Translate Win32 access/share/creation flags to POSIX open flags. "
        "Map GENERIC_READ/WRITE to O_RDONLY/O_WRONLY/O_RDWR, creation dispositions "
        "to O_CREAT/O_EXCL/O_TRUNC combos. Return fd wrapped in HANDLE.", True)

    _add("kernel32.dll", "CreateFileW", "HANDLE", [
        _p("lpFileName", "LPCWSTR"), _p("dwDesiredAccess", "DWORD"),
        _p("dwShareMode", "DWORD"), _p("lpSecurityAttributes", "LPSECURITY_ATTRIBUTES"),
        _p("dwCreationDisposition", "DWORD"), _p("dwFlagsAndAttributes", "DWORD"),
        _p("hTemplateFile", "HANDLE"),
    ], "file_io", "open()", "complex",
        "Wide-char variant. Convert UTF-16LE filename to UTF-8 then call CreateFileA logic.", True)

    _add("kernel32.dll", "ReadFile", "BOOL", [
        _p("hFile", "HANDLE"), _p("lpBuffer", "LPVOID", "out"),
        _p("nNumberOfBytesToRead", "DWORD"),
        _p("lpNumberOfBytesRead", "LPDWORD", "out"),
        _p("lpOverlapped", "LPOVERLAPPED"),
    ], "file_io", "read()", "moderate",
        "Extract fd from HANDLE, call read(). If lpOverlapped is non-NULL, "
        "queue to IOCP or use AIO.", True)

    _add("kernel32.dll", "WriteFile", "BOOL", [
        _p("hFile", "HANDLE"), _p("lpBuffer", "LPCVOID"),
        _p("nNumberOfBytesToWrite", "DWORD"),
        _p("lpNumberOfBytesWritten", "LPDWORD", "out"),
        _p("lpOverlapped", "LPOVERLAPPED"),
    ], "file_io", "write()", "moderate",
        "Extract fd from HANDLE, call write(). Handle overlapped path like ReadFile.", True)

    _add("kernel32.dll", "CloseHandle", "BOOL", [
        _p("hObject", "HANDLE"),
    ], "file_io", "close()", "moderate",
        "Multiplex: detect handle type (file, thread, event, mutex, etc.) "
        "and dispatch to appropriate close logic.", True)

    _add("kernel32.dll", "SetFilePointer", "DWORD", [
        _p("hFile", "HANDLE"), _p("lDistanceToMove", "LONG"),
        _p("lpDistanceToMoveHigh", "PLONG"), _p("dwMoveMethod", "DWORD"),
    ], "file_io", "lseek()", "moderate",
        "Map FILE_BEGIN/FILE_CURRENT/FILE_END to SEEK_SET/SEEK_CUR/SEEK_END.", True)

    _add("kernel32.dll", "SetFilePointerEx", "BOOL", [
        _p("hFile", "HANDLE"), _p("liDistanceToMove", "LARGE_INTEGER"),
        _p("lpNewFilePointer", "PLARGE_INTEGER", "out"), _p("dwMoveMethod", "DWORD"),
    ], "file_io", "lseek()", "moderate",
        "64-bit lseek wrapper.", True)

    _add("kernel32.dll", "GetFileSize", "DWORD", [
        _p("hFile", "HANDLE"), _p("lpFileSizeHigh", "LPDWORD", "out"),
    ], "file_io", "fstat()", "trivial",
        "fstat() and return st_size split into low/high DWORDs.", True)

    _add("kernel32.dll", "GetFileSizeEx", "BOOL", [
        _p("hFile", "HANDLE"), _p("lpFileSize", "PLARGE_INTEGER", "out"),
    ], "file_io", "fstat()", "trivial", "64-bit variant of GetFileSize.", True)

    _add("kernel32.dll", "GetFileAttributesA", "DWORD", [
        _p("lpFileName", "LPCSTR"),
    ], "file_io", "stat()", "moderate",
        "stat() the path and translate st_mode to FILE_ATTRIBUTE_* flags.", True)

    _add("kernel32.dll", "GetFileAttributesW", "DWORD", [
        _p("lpFileName", "LPCWSTR"),
    ], "file_io", "stat()", "moderate", "Wide-char variant.", True)

    _add("kernel32.dll", "GetFileAttributesExA", "BOOL", [
        _p("lpFileName", "LPCSTR"), _p("fInfoLevelId", "GET_FILEEX_INFO_LEVELS"),
        _p("lpFileInformation", "LPVOID", "out"),
    ], "file_io", "stat()", "moderate",
        "Fill WIN32_FILE_ATTRIBUTE_DATA from stat() results.", True)

    _add("kernel32.dll", "SetFileAttributesA", "BOOL", [
        _p("lpFileName", "LPCSTR"), _p("dwFileAttributes", "DWORD"),
    ], "file_io", "chmod()", "trivial",
        "Map FILE_ATTRIBUTE_READONLY to chmod mode. Most Win32 attrs are no-ops on Linux.", True)

    _add("kernel32.dll", "FindFirstFileA", "HANDLE", [
        _p("lpFileName", "LPCSTR"),
        _p("lpFindFileData", "LPWIN32_FIND_DATAA", "out"),
    ], "file_io", "opendir() + readdir()", "complex",
        "Parse glob pattern, opendir() parent, fnmatch() entries. Return find context as HANDLE.", True)

    _add("kernel32.dll", "FindFirstFileW", "HANDLE", [
        _p("lpFileName", "LPCWSTR"),
        _p("lpFindFileData", "LPWIN32_FIND_DATAW", "out"),
    ], "file_io", "opendir() + readdir()", "complex", "Wide-char variant.", True)

    _add("kernel32.dll", "FindNextFileA", "BOOL", [
        _p("hFindFile", "HANDLE"),
        _p("lpFindFileData", "LPWIN32_FIND_DATAA", "out"),
    ], "file_io", "readdir()", "moderate", "Continue directory enumeration.", True)

    _add("kernel32.dll", "FindNextFileW", "BOOL", [
        _p("hFindFile", "HANDLE"),
        _p("lpFindFileData", "LPWIN32_FIND_DATAW", "out"),
    ], "file_io", "readdir()", "moderate", "Wide-char variant.", True)

    _add("kernel32.dll", "FindClose", "BOOL", [
        _p("hFindFile", "HANDLE"),
    ], "file_io", "closedir()", "trivial", "Close the find context and free memory.", True)

    _add("kernel32.dll", "CreateDirectoryA", "BOOL", [
        _p("lpPathName", "LPCSTR"),
        _p("lpSecurityAttributes", "LPSECURITY_ATTRIBUTES"),
    ], "file_io", "mkdir()", "trivial", "mkdir() with 0755. Security attributes ignored.", True)

    _add("kernel32.dll", "CreateDirectoryW", "BOOL", [
        _p("lpPathName", "LPCWSTR"),
        _p("lpSecurityAttributes", "LPSECURITY_ATTRIBUTES"),
    ], "file_io", "mkdir()", "trivial", "Wide-char variant.", True)

    _add("kernel32.dll", "RemoveDirectoryA", "BOOL", [
        _p("lpPathName", "LPCSTR"),
    ], "file_io", "rmdir()", "trivial", "Direct rmdir() mapping.", True)

    _add("kernel32.dll", "DeleteFileA", "BOOL", [
        _p("lpFileName", "LPCSTR"),
    ], "file_io", "unlink()", "trivial", "Direct unlink() mapping.", True)

    _add("kernel32.dll", "DeleteFileW", "BOOL", [
        _p("lpFileName", "LPCWSTR"),
    ], "file_io", "unlink()", "trivial", "Wide-char variant.", True)

    _add("kernel32.dll", "MoveFileA", "BOOL", [
        _p("lpExistingFileName", "LPCSTR"), _p("lpNewFileName", "LPCSTR"),
    ], "file_io", "rename()", "trivial",
        "rename(). Falls back to copy+delete across filesystems.", True)

    _add("kernel32.dll", "MoveFileExA", "BOOL", [
        _p("lpExistingFileName", "LPCSTR"), _p("lpNewFileName", "LPCSTR"),
        _p("dwFlags", "DWORD"),
    ], "file_io", "rename()", "moderate",
        "Handle MOVEFILE_REPLACE_EXISTING, MOVEFILE_COPY_ALLOWED flags.", True)

    _add("kernel32.dll", "CopyFileA", "BOOL", [
        _p("lpExistingFileName", "LPCSTR"), _p("lpNewFileName", "LPCSTR"),
        _p("bFailIfExists", "BOOL"),
    ], "file_io", "sendfile() / copy_file_range()", "moderate",
        "Open source, create dest (O_EXCL if bFailIfExists), copy contents.", True)

    _add("kernel32.dll", "GetTempPathA", "DWORD", [
        _p("nBufferLength", "DWORD"), _p("lpBuffer", "LPSTR", "out"),
    ], "file_io", "getenv(\"TMPDIR\") or /tmp", "trivial",
        "Return /tmp/ or $TMPDIR.", True)

    _add("kernel32.dll", "GetTempPathW", "DWORD", [
        _p("nBufferLength", "DWORD"), _p("lpBuffer", "LPWSTR", "out"),
    ], "file_io", "getenv(\"TMPDIR\") or /tmp", "trivial", "Wide-char variant.", True)

    _add("kernel32.dll", "GetTempFileNameA", "UINT", [
        _p("lpPathName", "LPCSTR"), _p("lpPrefixString", "LPCSTR"),
        _p("uUnique", "UINT"), _p("lpTempFileName", "LPSTR", "out"),
    ], "file_io", "mkstemp()", "moderate",
        "Generate unique temp filename using mkstemp() semantics.", True)

    _add("kernel32.dll", "FlushFileBuffers", "BOOL", [
        _p("hFile", "HANDLE"),
    ], "file_io", "fsync()", "trivial", "Direct fsync() mapping.", True)

    _add("kernel32.dll", "LockFile", "BOOL", [
        _p("hFile", "HANDLE"), _p("dwFileOffsetLow", "DWORD"),
        _p("dwFileOffsetHigh", "DWORD"), _p("nNumberOfBytesToLockLow", "DWORD"),
        _p("nNumberOfBytesToLockHigh", "DWORD"),
    ], "file_io", "fcntl(F_SETLK)", "moderate",
        "Map to POSIX advisory locks via fcntl(F_SETLK).", True)

    _add("kernel32.dll", "LockFileEx", "BOOL", [
        _p("hFile", "HANDLE"), _p("dwFlags", "DWORD"),
        _p("dwReserved", "DWORD"), _p("nNumberOfBytesToLockLow", "DWORD"),
        _p("nNumberOfBytesToLockHigh", "DWORD"), _p("lpOverlapped", "LPOVERLAPPED"),
    ], "file_io", "fcntl(F_SETLK/F_SETLKW)", "moderate",
        "LOCKFILE_EXCLUSIVE_LOCK maps to F_WRLCK, blocking via F_SETLKW.", True)

    _add("kernel32.dll", "UnlockFile", "BOOL", [
        _p("hFile", "HANDLE"), _p("dwFileOffsetLow", "DWORD"),
        _p("dwFileOffsetHigh", "DWORD"), _p("nNumberOfBytesToUnlockLow", "DWORD"),
        _p("nNumberOfBytesToUnlockHigh", "DWORD"),
    ], "file_io", "fcntl(F_SETLK, F_UNLCK)", "moderate", "Unlock via fcntl.", True)

    _add("kernel32.dll", "UnlockFileEx", "BOOL", [
        _p("hFile", "HANDLE"), _p("dwReserved", "DWORD"),
        _p("nNumberOfBytesToUnlockLow", "DWORD"),
        _p("nNumberOfBytesToUnlockHigh", "DWORD"),
        _p("lpOverlapped", "LPOVERLAPPED"),
    ], "file_io", "fcntl(F_SETLK, F_UNLCK)", "moderate", "Extended unlock.", True)

    _add("kernel32.dll", "GetFullPathNameA", "DWORD", [
        _p("lpFileName", "LPCSTR"), _p("nBufferLength", "DWORD"),
        _p("lpBuffer", "LPSTR", "out"), _p("lpFilePart", "LPSTR*", "out"),
    ], "file_io", "realpath()", "moderate",
        "Use realpath() for existing paths. For non-existent, build from cwd + relative.", True)

    _add("kernel32.dll", "SetEndOfFile", "BOOL", [
        _p("hFile", "HANDLE"),
    ], "file_io", "ftruncate()", "trivial",
        "ftruncate() at current file position.", True)

    _add("kernel32.dll", "GetFileType", "DWORD", [
        _p("hFile", "HANDLE"),
    ], "file_io", "fstat() + S_ISREG/S_ISCHR/S_ISFIFO", "trivial",
        "Map stat mode to FILE_TYPE_DISK/FILE_TYPE_CHAR/FILE_TYPE_PIPE.", True)

    _add("kernel32.dll", "DeviceIoControl", "BOOL", [
        _p("hDevice", "HANDLE"), _p("dwIoControlCode", "DWORD"),
        _p("lpInBuffer", "LPVOID"), _p("nInBufferSize", "DWORD"),
        _p("lpOutBuffer", "LPVOID", "out"), _p("nOutBufferSize", "DWORD"),
        _p("lpBytesReturned", "LPDWORD", "out"),
        _p("lpOverlapped", "LPOVERLAPPED"),
    ], "file_io", "ioctl()", "complex",
        "Map known Windows IOCTLs to Linux ioctl codes or emulate. "
        "Most game-relevant IOCTLs can be stubbed to return success.", True)

    _add("kernel32.dll", "CreatePipe", "BOOL", [
        _p("hReadPipe", "PHANDLE", "out"), _p("hWritePipe", "PHANDLE", "out"),
        _p("lpPipeAttributes", "LPSECURITY_ATTRIBUTES"),
        _p("nSize", "DWORD"),
    ], "file_io", "pipe()", "moderate",
        "pipe() returns two fds; wrap in HANDLEs.", True)

    _add("kernel32.dll", "ReadFileEx", "BOOL", [
        _p("hFile", "HANDLE"), _p("lpBuffer", "LPVOID", "out"),
        _p("nNumberOfBytesToRead", "DWORD"),
        _p("lpOverlapped", "LPOVERLAPPED"),
        _p("lpCompletionRoutine", "LPOVERLAPPED_COMPLETION_ROUTINE"),
    ], "file_io", "aio_read()", "complex",
        "Async read with completion callback. Queue to thread pool or use AIO.", True)

    _add("kernel32.dll", "WriteFileEx", "BOOL", [
        _p("hFile", "HANDLE"), _p("lpBuffer", "LPCVOID"),
        _p("nNumberOfBytesToWrite", "DWORD"),
        _p("lpOverlapped", "LPOVERLAPPED"),
        _p("lpCompletionRoutine", "LPOVERLAPPED_COMPLETION_ROUTINE"),
    ], "file_io", "aio_write()", "complex",
        "Async write with completion callback.", True)

    _add("kernel32.dll", "GetOverlappedResult", "BOOL", [
        _p("hFile", "HANDLE"), _p("lpOverlapped", "LPOVERLAPPED"),
        _p("lpNumberOfBytesTransferred", "LPDWORD", "out"),
        _p("bWait", "BOOL"),
    ], "file_io", "", "complex",
        "Check/wait for async I/O completion. Pairs with our IOCP implementation.", True)

    _add("kernel32.dll", "CreateIoCompletionPort", "HANDLE", [
        _p("FileHandle", "HANDLE"), _p("ExistingCompletionPort", "HANDLE"),
        _p("CompletionKey", "ULONG_PTR"), _p("NumberOfConcurrentThreads", "DWORD"),
    ], "file_io", "epoll_create() + thread pool", "complex",
        "Create IOCP backed by epoll or io_uring. Central async I/O dispatch.", True)

    _add("kernel32.dll", "GetQueuedCompletionStatus", "BOOL", [
        _p("CompletionPort", "HANDLE"),
        _p("lpNumberOfBytesTransferred", "LPDWORD", "out"),
        _p("lpCompletionKey", "PULONG_PTR", "out"),
        _p("lpOverlapped", "LPOVERLAPPED*", "out"),
        _p("dwMilliseconds", "DWORD"),
    ], "file_io", "epoll_wait()", "complex",
        "Dequeue a completion packet from IOCP. Backed by epoll_wait.", True)

    _add("kernel32.dll", "PostQueuedCompletionStatus", "BOOL", [
        _p("CompletionPort", "HANDLE"),
        _p("dwNumberOfBytesTransferred", "DWORD"),
        _p("dwCompletionKey", "ULONG_PTR"),
        _p("lpOverlapped", "LPOVERLAPPED"),
    ], "file_io", "", "moderate",
        "Post a user-defined completion packet to IOCP.", True)

    _add("kernel32.dll", "GetFileInformationByHandle", "BOOL", [
        _p("hFile", "HANDLE"),
        _p("lpFileInformation", "LPBY_HANDLE_FILE_INFORMATION", "out"),
    ], "file_io", "fstat()", "moderate",
        "Fill BY_HANDLE_FILE_INFORMATION from fstat. Map dev/ino to volume serial/index.", True)

    # ===================================================================
    # MEMORY  (kernel32.dll)  -- 15+ functions
    # ===================================================================
    _add("kernel32.dll", "VirtualAlloc", "LPVOID", [
        _p("lpAddress", "LPVOID"), _p("dwSize", "SIZE_T"),
        _p("flAllocationType", "DWORD"), _p("flProtect", "DWORD"),
    ], "memory", "mmap()", "complex",
        "Map MEM_COMMIT/MEM_RESERVE to mmap flags. "
        "PAGE_READWRITE -> PROT_READ|PROT_WRITE, etc. "
        "MEM_RESERVE uses MAP_NORESERVE.", True)

    _add("kernel32.dll", "VirtualFree", "BOOL", [
        _p("lpAddress", "LPVOID"), _p("dwSize", "SIZE_T"),
        _p("dwFreeType", "DWORD"),
    ], "memory", "munmap() / madvise(DONTNEED)", "moderate",
        "MEM_RELEASE -> munmap(). MEM_DECOMMIT -> madvise(MADV_DONTNEED).", True)

    _add("kernel32.dll", "VirtualProtect", "BOOL", [
        _p("lpAddress", "LPVOID"), _p("dwSize", "SIZE_T"),
        _p("flNewProtect", "DWORD"), _p("lpflOldProtect", "PDWORD", "out"),
    ], "memory", "mprotect()", "moderate",
        "Translate PAGE_* constants to PROT_* and call mprotect().", True)

    _add("kernel32.dll", "VirtualQuery", "SIZE_T", [
        _p("lpAddress", "LPCVOID"),
        _p("lpBuffer", "PMEMORY_BASIC_INFORMATION", "out"),
        _p("dwLength", "SIZE_T"),
    ], "memory", "/proc/self/maps", "complex",
        "Parse /proc/self/maps to find the region containing lpAddress "
        "and fill MEMORY_BASIC_INFORMATION.", True)

    _add("kernel32.dll", "HeapCreate", "HANDLE", [
        _p("flOptions", "DWORD"), _p("dwInitialSize", "SIZE_T"),
        _p("dwMaximumSize", "SIZE_T"),
    ], "memory", "mmap() arena", "moderate",
        "Create a private heap. Backed by a custom arena or just use malloc zones.", True)

    _add("kernel32.dll", "HeapDestroy", "BOOL", [
        _p("hHeap", "HANDLE"),
    ], "memory", "munmap()", "moderate", "Free the entire heap arena.", True)

    _add("kernel32.dll", "HeapAlloc", "LPVOID", [
        _p("hHeap", "HANDLE"), _p("dwFlags", "DWORD"), _p("dwBytes", "SIZE_T"),
    ], "memory", "malloc()", "trivial",
        "HEAP_ZERO_MEMORY -> calloc(). Default -> malloc().", True)

    _add("kernel32.dll", "HeapFree", "BOOL", [
        _p("hHeap", "HANDLE"), _p("dwFlags", "DWORD"), _p("lpMem", "LPVOID"),
    ], "memory", "free()", "trivial", "Direct free().", True)

    _add("kernel32.dll", "HeapReAlloc", "LPVOID", [
        _p("hHeap", "HANDLE"), _p("dwFlags", "DWORD"),
        _p("lpMem", "LPVOID"), _p("dwBytes", "SIZE_T"),
    ], "memory", "realloc()", "trivial",
        "realloc(). Handle HEAP_ZERO_MEMORY by zeroing new region.", True)

    _add("kernel32.dll", "HeapSize", "SIZE_T", [
        _p("hHeap", "HANDLE"), _p("dwFlags", "DWORD"), _p("lpMem", "LPCVOID"),
    ], "memory", "malloc_usable_size()", "trivial",
        "glibc malloc_usable_size() or track sizes in wrapper.", True)

    _add("kernel32.dll", "GetProcessHeap", "HANDLE", [], "memory", "",
         "trivial", "Return singleton handle for the default process heap.", True)

    _add("kernel32.dll", "GlobalAlloc", "HGLOBAL", [
        _p("uFlags", "UINT"), _p("dwBytes", "SIZE_T"),
    ], "memory", "malloc()", "trivial",
        "GMEM_FIXED -> malloc(). GMEM_MOVEABLE -> allocate with indirection header.", True)

    _add("kernel32.dll", "GlobalFree", "HGLOBAL", [
        _p("hMem", "HGLOBAL"),
    ], "memory", "free()", "trivial", "Direct free().", True)

    _add("kernel32.dll", "GlobalLock", "LPVOID", [
        _p("hMem", "HGLOBAL"),
    ], "memory", "", "trivial", "For GMEM_FIXED, return pointer as-is. For moveable, dereference.", True)

    _add("kernel32.dll", "GlobalUnlock", "BOOL", [
        _p("hMem", "HGLOBAL"),
    ], "memory", "", "trivial", "Decrement lock count. Always succeeds for GMEM_FIXED.", True)

    _add("kernel32.dll", "LocalAlloc", "HLOCAL", [
        _p("uFlags", "UINT"), _p("uBytes", "SIZE_T"),
    ], "memory", "malloc()", "trivial", "Same as GlobalAlloc; LMEM_FIXED -> malloc().", True)

    _add("kernel32.dll", "LocalFree", "HLOCAL", [
        _p("hMem", "HLOCAL"),
    ], "memory", "free()", "trivial", "Direct free().", True)

    _add("kernel32.dll", "CreateFileMappingA", "HANDLE", [
        _p("hFile", "HANDLE"), _p("lpFileMappingAttributes", "LPSECURITY_ATTRIBUTES"),
        _p("flProtect", "DWORD"), _p("dwMaximumSizeHigh", "DWORD"),
        _p("dwMaximumSizeLow", "DWORD"), _p("lpName", "LPCSTR"),
    ], "memory", "shm_open() / mmap()", "complex",
        "Named: shm_open(). File-backed: pass fd. Anonymous: MAP_ANONYMOUS. "
        "Track mapping objects for MapViewOfFile.", True)

    _add("kernel32.dll", "MapViewOfFile", "LPVOID", [
        _p("hFileMappingObject", "HANDLE"), _p("dwDesiredAccess", "DWORD"),
        _p("dwFileOffsetHigh", "DWORD"), _p("dwFileOffsetLow", "DWORD"),
        _p("dwNumberOfBytesToMap", "SIZE_T"),
    ], "memory", "mmap()", "moderate",
        "mmap() the underlying fd from the mapping object.", True)

    _add("kernel32.dll", "UnmapViewOfFile", "BOOL", [
        _p("lpBaseAddress", "LPCVOID"),
    ], "memory", "munmap()", "trivial", "Direct munmap().", True)

    # ===================================================================
    # THREADING  (kernel32.dll)  -- 25+ functions
    # ===================================================================
    _add("kernel32.dll", "CreateThread", "HANDLE", [
        _p("lpThreadAttributes", "LPSECURITY_ATTRIBUTES"),
        _p("dwStackSize", "SIZE_T"),
        _p("lpStartAddress", "LPTHREAD_START_ROUTINE"),
        _p("lpParameter", "LPVOID"), _p("dwCreationFlags", "DWORD"),
        _p("lpThreadId", "LPDWORD", "out"),
    ], "thread", "pthread_create()", "complex",
        "Wrap ms_abi start routine in sysv_abi trampoline. "
        "Handle CREATE_SUSPENDED. Return HANDLE wrapping pthread_t.", True)

    _add("kernel32.dll", "ExitThread", "void", [
        _p("dwExitCode", "DWORD"),
    ], "thread", "pthread_exit()", "trivial",
        "Store exit code, call pthread_exit().", True)

    _add("kernel32.dll", "GetCurrentThread", "HANDLE", [], "thread",
         "pthread_self()", "trivial", "Return pseudo-handle (-2).", True)

    _add("kernel32.dll", "GetCurrentThreadId", "DWORD", [], "thread",
         "gettid()", "trivial", "Return gettid() or pthread-based thread ID.", True)

    _add("kernel32.dll", "SuspendThread", "DWORD", [
        _p("hThread", "HANDLE"),
    ], "thread", "pthread_kill(SIGSTOP)", "complex",
        "No direct POSIX equivalent. Use signals or futex-based suspend.", True)

    _add("kernel32.dll", "ResumeThread", "DWORD", [
        _p("hThread", "HANDLE"),
    ], "thread", "pthread_kill(SIGCONT)", "complex",
        "Paired with SuspendThread. Signal-based resume.", True)

    _add("kernel32.dll", "WaitForSingleObject", "DWORD", [
        _p("hHandle", "HANDLE"), _p("dwMilliseconds", "DWORD"),
    ], "sync", "pthread_join() / sem_wait() / futex", "complex",
        "Multiplex on handle type: thread -> pthread_join, "
        "mutex -> pthread_mutex_timedlock, event -> cond_timedwait, "
        "semaphore -> sem_timedwait. INFINITE -> no timeout.", True)

    _add("kernel32.dll", "WaitForMultipleObjects", "DWORD", [
        _p("nCount", "DWORD"), _p("lpHandles", "const HANDLE*"),
        _p("bWaitAll", "BOOL"), _p("dwMilliseconds", "DWORD"),
    ], "sync", "poll() / futex", "complex",
        "Wait for any/all objects. No direct POSIX equiv for bWaitAll=TRUE across types. "
        "Use polling thread or eventfd.", True)

    _add("kernel32.dll", "CreateMutexA", "HANDLE", [
        _p("lpMutexAttributes", "LPSECURITY_ATTRIBUTES"),
        _p("bInitialOwner", "BOOL"), _p("lpName", "LPCSTR"),
    ], "sync", "pthread_mutex_init()", "moderate",
        "Named mutexes use shared memory + robust mutexes. "
        "If bInitialOwner, lock immediately.", True)

    _add("kernel32.dll", "CreateMutexW", "HANDLE", [
        _p("lpMutexAttributes", "LPSECURITY_ATTRIBUTES"),
        _p("bInitialOwner", "BOOL"), _p("lpName", "LPCWSTR"),
    ], "sync", "pthread_mutex_init()", "moderate", "Wide-char variant.", True)

    _add("kernel32.dll", "ReleaseMutex", "BOOL", [
        _p("hMutex", "HANDLE"),
    ], "sync", "pthread_mutex_unlock()", "trivial",
        "Verify caller owns mutex, then unlock.", True)

    _add("kernel32.dll", "CreateEventA", "HANDLE", [
        _p("lpEventAttributes", "LPSECURITY_ATTRIBUTES"),
        _p("bManualReset", "BOOL"), _p("bInitialState", "BOOL"),
        _p("lpName", "LPCSTR"),
    ], "sync", "pthread_cond + eventfd", "moderate",
        "Manual-reset: stays signaled until ResetEvent. "
        "Auto-reset: releases one waiter then resets.", True)

    _add("kernel32.dll", "CreateEventW", "HANDLE", [
        _p("lpEventAttributes", "LPSECURITY_ATTRIBUTES"),
        _p("bManualReset", "BOOL"), _p("bInitialState", "BOOL"),
        _p("lpName", "LPCWSTR"),
    ], "sync", "pthread_cond + eventfd", "moderate", "Wide-char variant.", True)

    _add("kernel32.dll", "SetEvent", "BOOL", [
        _p("hEvent", "HANDLE"),
    ], "sync", "pthread_cond_signal/broadcast", "trivial",
        "Auto-reset: cond_signal. Manual-reset: cond_broadcast + set flag.", True)

    _add("kernel32.dll", "ResetEvent", "BOOL", [
        _p("hEvent", "HANDLE"),
    ], "sync", "", "trivial", "Clear the signaled flag.", True)

    _add("kernel32.dll", "CreateSemaphoreA", "HANDLE", [
        _p("lpSemaphoreAttributes", "LPSECURITY_ATTRIBUTES"),
        _p("lInitialCount", "LONG"), _p("lMaximumCount", "LONG"),
        _p("lpName", "LPCSTR"),
    ], "sync", "sem_init()", "moderate",
        "sem_init() with initial count. Max count enforced in ReleaseSemaphore.", True)

    _add("kernel32.dll", "CreateSemaphoreW", "HANDLE", [
        _p("lpSemaphoreAttributes", "LPSECURITY_ATTRIBUTES"),
        _p("lInitialCount", "LONG"), _p("lMaximumCount", "LONG"),
        _p("lpName", "LPCWSTR"),
    ], "sync", "sem_init()", "moderate", "Wide-char variant.", True)

    _add("kernel32.dll", "ReleaseSemaphore", "BOOL", [
        _p("hSemaphore", "HANDLE"), _p("lReleaseCount", "LONG"),
        _p("lpPreviousCount", "LPLONG", "out"),
    ], "sync", "sem_post()", "trivial",
        "sem_post() lReleaseCount times. Check max count.", True)

    _add("kernel32.dll", "InitializeCriticalSection", "void", [
        _p("lpCriticalSection", "LPCRITICAL_SECTION"),
    ], "sync", "pthread_mutex_init(RECURSIVE)", "trivial",
        "Init a recursive pthread_mutex in the CS memory.", True)

    _add("kernel32.dll", "EnterCriticalSection", "void", [
        _p("lpCriticalSection", "LPCRITICAL_SECTION"),
    ], "sync", "pthread_mutex_lock()", "trivial",
        "pthread_mutex_lock() on the embedded recursive mutex.", True)

    _add("kernel32.dll", "LeaveCriticalSection", "void", [
        _p("lpCriticalSection", "LPCRITICAL_SECTION"),
    ], "sync", "pthread_mutex_unlock()", "trivial",
        "pthread_mutex_unlock().", True)

    _add("kernel32.dll", "DeleteCriticalSection", "void", [
        _p("lpCriticalSection", "LPCRITICAL_SECTION"),
    ], "sync", "pthread_mutex_destroy()", "trivial",
        "pthread_mutex_destroy().", True)

    _add("kernel32.dll", "TryEnterCriticalSection", "BOOL", [
        _p("lpCriticalSection", "LPCRITICAL_SECTION"),
    ], "sync", "pthread_mutex_trylock()", "trivial",
        "pthread_mutex_trylock(). Return TRUE on success.", True)

    _add("kernel32.dll", "TlsAlloc", "DWORD", [], "thread",
         "pthread_key_create()", "trivial",
         "pthread_key_create(). Return slot index.", True)

    _add("kernel32.dll", "TlsFree", "BOOL", [
        _p("dwTlsIndex", "DWORD"),
    ], "thread", "pthread_key_delete()", "trivial",
        "pthread_key_delete().", True)

    _add("kernel32.dll", "TlsGetValue", "LPVOID", [
        _p("dwTlsIndex", "DWORD"),
    ], "thread", "pthread_getspecific()", "trivial",
        "pthread_getspecific().", True)

    _add("kernel32.dll", "TlsSetValue", "BOOL", [
        _p("dwTlsIndex", "DWORD"), _p("lpTlsValue", "LPVOID"),
    ], "thread", "pthread_setspecific()", "trivial",
        "pthread_setspecific().", True)

    _add("kernel32.dll", "Sleep", "void", [
        _p("dwMilliseconds", "DWORD"),
    ], "thread", "usleep() / nanosleep()", "trivial",
        "nanosleep() with millisecond conversion. Sleep(0) -> sched_yield().", True)

    _add("kernel32.dll", "SleepEx", "DWORD", [
        _p("dwMilliseconds", "DWORD"), _p("bAlertable", "BOOL"),
    ], "thread", "nanosleep()", "moderate",
        "If bAlertable, check APC queue before/after sleep.", True)

    _add("kernel32.dll", "SwitchToThread", "BOOL", [], "thread",
         "sched_yield()", "trivial", "Direct sched_yield().", True)

    _add("kernel32.dll", "QueueUserAPC", "DWORD", [
        _p("pfnAPC", "PAPCFUNC"), _p("hThread", "HANDLE"),
        _p("dwData", "ULONG_PTR"),
    ], "thread", "pthread_kill() + signal handler", "complex",
        "Queue APC to target thread. Delivered when thread enters alertable wait.", True)

    _add("kernel32.dll", "SetThreadPriority", "BOOL", [
        _p("hThread", "HANDLE"), _p("nPriority", "int"),
    ], "thread", "pthread_setschedparam()", "moderate",
        "Map THREAD_PRIORITY_* to SCHED_OTHER nice values.", True)

    _add("kernel32.dll", "GetThreadPriority", "int", [
        _p("hThread", "HANDLE"),
    ], "thread", "pthread_getschedparam()", "moderate",
        "Reverse map from sched params to THREAD_PRIORITY_*.", True)

    # ===================================================================
    # REGISTRY  (advapi32.dll)  -- 10+ functions
    # ===================================================================
    _add("advapi32.dll", "RegOpenKeyExA", "LONG", [
        _p("hKey", "HKEY"), _p("lpSubKey", "LPCSTR"),
        _p("ulOptions", "DWORD"), _p("samDesired", "REGSAM"),
        _p("phkResult", "PHKEY", "out"),
    ], "registry", "custom registry (filesystem-backed)", "complex",
        "Open subkey in our filesystem-backed registry under "
        "/var/lib/pe-compat/registry/. Each key is a directory, values are files.", True)

    _add("advapi32.dll", "RegOpenKeyExW", "LONG", [
        _p("hKey", "HKEY"), _p("lpSubKey", "LPCWSTR"),
        _p("ulOptions", "DWORD"), _p("samDesired", "REGSAM"),
        _p("phkResult", "PHKEY", "out"),
    ], "registry", "custom registry (filesystem-backed)", "complex",
        "Wide-char variant.", True)

    _add("advapi32.dll", "RegCreateKeyExA", "LONG", [
        _p("hKey", "HKEY"), _p("lpSubKey", "LPCSTR"),
        _p("Reserved", "DWORD"), _p("lpClass", "LPSTR"),
        _p("dwOptions", "DWORD"), _p("samDesired", "REGSAM"),
        _p("lpSecurityAttributes", "LPSECURITY_ATTRIBUTES"),
        _p("phkResult", "PHKEY", "out"),
        _p("lpdwDisposition", "LPDWORD", "out"),
    ], "registry", "mkdir -p", "complex",
        "Create registry key path as directories. "
        "REG_CREATED_NEW_KEY or REG_OPENED_EXISTING_KEY in disposition.", True)

    _add("advapi32.dll", "RegCreateKeyExW", "LONG", [
        _p("hKey", "HKEY"), _p("lpSubKey", "LPCWSTR"),
        _p("Reserved", "DWORD"), _p("lpClass", "LPWSTR"),
        _p("dwOptions", "DWORD"), _p("samDesired", "REGSAM"),
        _p("lpSecurityAttributes", "LPSECURITY_ATTRIBUTES"),
        _p("phkResult", "PHKEY", "out"),
        _p("lpdwDisposition", "LPDWORD", "out"),
    ], "registry", "mkdir -p", "complex", "Wide-char variant.", True)

    _add("advapi32.dll", "RegQueryValueExA", "LONG", [
        _p("hKey", "HKEY"), _p("lpValueName", "LPCSTR"),
        _p("lpReserved", "LPDWORD"), _p("lpType", "LPDWORD", "out"),
        _p("lpData", "LPBYTE", "out"), _p("lpcbData", "LPDWORD", "inout"),
    ], "registry", "read file", "moderate",
        "Read value file. First 4 bytes = type tag, rest = data.", True)

    _add("advapi32.dll", "RegQueryValueExW", "LONG", [
        _p("hKey", "HKEY"), _p("lpValueName", "LPCWSTR"),
        _p("lpReserved", "LPDWORD"), _p("lpType", "LPDWORD", "out"),
        _p("lpData", "LPBYTE", "out"), _p("lpcbData", "LPDWORD", "inout"),
    ], "registry", "read file", "moderate", "Wide-char variant.", True)

    _add("advapi32.dll", "RegSetValueExA", "LONG", [
        _p("hKey", "HKEY"), _p("lpValueName", "LPCSTR"),
        _p("Reserved", "DWORD"), _p("dwType", "DWORD"),
        _p("lpData", "const BYTE*"), _p("cbData", "DWORD"),
    ], "registry", "write file", "moderate",
        "Write type tag + data to value file.", True)

    _add("advapi32.dll", "RegSetValueExW", "LONG", [
        _p("hKey", "HKEY"), _p("lpValueName", "LPCWSTR"),
        _p("Reserved", "DWORD"), _p("dwType", "DWORD"),
        _p("lpData", "const BYTE*"), _p("cbData", "DWORD"),
    ], "registry", "write file", "moderate", "Wide-char variant.", True)

    _add("advapi32.dll", "RegCloseKey", "LONG", [
        _p("hKey", "HKEY"),
    ], "registry", "close fd / free handle", "trivial",
        "Free the registry handle structure.", True)

    _add("advapi32.dll", "RegDeleteKeyA", "LONG", [
        _p("hKey", "HKEY"), _p("lpSubKey", "LPCSTR"),
    ], "registry", "rmdir()", "moderate",
        "Remove key directory. Must be empty (no subkeys).", True)

    _add("advapi32.dll", "RegDeleteKeyW", "LONG", [
        _p("hKey", "HKEY"), _p("lpSubKey", "LPCWSTR"),
    ], "registry", "rmdir()", "moderate", "Wide-char variant.", True)

    _add("advapi32.dll", "RegDeleteValueA", "LONG", [
        _p("hKey", "HKEY"), _p("lpValueName", "LPCSTR"),
    ], "registry", "unlink()", "trivial", "Unlink the value file.", True)

    _add("advapi32.dll", "RegDeleteValueW", "LONG", [
        _p("hKey", "HKEY"), _p("lpValueName", "LPCWSTR"),
    ], "registry", "unlink()", "trivial", "Wide-char variant.", True)

    _add("advapi32.dll", "RegEnumKeyExA", "LONG", [
        _p("hKey", "HKEY"), _p("dwIndex", "DWORD"),
        _p("lpName", "LPSTR", "out"), _p("lpcchName", "LPDWORD", "inout"),
        _p("lpReserved", "LPDWORD"), _p("lpClass", "LPSTR", "out"),
        _p("lpcchClass", "LPDWORD", "inout"),
        _p("lpftLastWriteTime", "PFILETIME", "out"),
    ], "registry", "readdir()", "moderate",
        "Enumerate subdirectories of the key directory.", True)

    _add("advapi32.dll", "RegEnumValueA", "LONG", [
        _p("hKey", "HKEY"), _p("dwIndex", "DWORD"),
        _p("lpValueName", "LPSTR", "out"), _p("lpcchValueName", "LPDWORD", "inout"),
        _p("lpReserved", "LPDWORD"), _p("lpType", "LPDWORD", "out"),
        _p("lpData", "LPBYTE", "out"), _p("lpcbData", "LPDWORD", "inout"),
    ], "registry", "readdir() + read()", "moderate",
        "Enumerate value files in the key directory.", True)

    _add("advapi32.dll", "RegGetValueA", "LONG", [
        _p("hkey", "HKEY"), _p("lpSubKey", "LPCSTR"),
        _p("lpValue", "LPCSTR"), _p("dwFlags", "DWORD"),
        _p("pdwType", "LPDWORD", "out"),
        _p("pvData", "PVOID", "out"), _p("pcbData", "LPDWORD", "inout"),
    ], "registry", "custom registry", "moderate",
        "Convenience wrapper: open subkey, query value, close.", True)

    # ===================================================================
    # PROCESS  (kernel32.dll)  -- 15+ functions
    # ===================================================================
    _add("kernel32.dll", "CreateProcessA", "BOOL", [
        _p("lpApplicationName", "LPCSTR"), _p("lpCommandLine", "LPSTR"),
        _p("lpProcessAttributes", "LPSECURITY_ATTRIBUTES"),
        _p("lpThreadAttributes", "LPSECURITY_ATTRIBUTES"),
        _p("bInheritHandles", "BOOL"),
        _p("dwCreationFlags", "DWORD"), _p("lpEnvironment", "LPVOID"),
        _p("lpCurrentDirectory", "LPCSTR"),
        _p("lpStartupInfo", "LPSTARTUPINFOA"),
        _p("lpProcessInformation", "LPPROCESS_INFORMATION", "out"),
    ], "process", "fork() + exec()", "complex",
        "Parse command line, set up redirected handles for stdin/stdout/stderr, "
        "fork+exec. If it's a PE, run through pe-loader. "
        "Fill PROCESS_INFORMATION with child pid.", True)

    _add("kernel32.dll", "CreateProcessW", "BOOL", [
        _p("lpApplicationName", "LPCWSTR"), _p("lpCommandLine", "LPWSTR"),
        _p("lpProcessAttributes", "LPSECURITY_ATTRIBUTES"),
        _p("lpThreadAttributes", "LPSECURITY_ATTRIBUTES"),
        _p("bInheritHandles", "BOOL"),
        _p("dwCreationFlags", "DWORD"), _p("lpEnvironment", "LPVOID"),
        _p("lpCurrentDirectory", "LPCWSTR"),
        _p("lpStartupInfo", "LPSTARTUPINFOW"),
        _p("lpProcessInformation", "LPPROCESS_INFORMATION", "out"),
    ], "process", "fork() + exec()", "complex", "Wide-char variant.", True)

    _add("kernel32.dll", "GetCurrentProcess", "HANDLE", [], "process",
         "getpid()", "trivial",
         "Return pseudo-handle (-1). Some callers pass this to DuplicateHandle.", True)

    _add("kernel32.dll", "GetCurrentProcessId", "DWORD", [], "process",
         "getpid()", "trivial", "Direct getpid().", True)

    _add("kernel32.dll", "TerminateProcess", "BOOL", [
        _p("hProcess", "HANDLE"), _p("uExitCode", "UINT"),
    ], "process", "kill(SIGKILL)", "moderate",
        "Extract pid from handle, kill(pid, SIGKILL).", True)

    _add("kernel32.dll", "ExitProcess", "void", [
        _p("uExitCode", "UINT"),
    ], "process", "exit()", "trivial", "Direct exit().", True)

    _add("kernel32.dll", "GetExitCodeProcess", "BOOL", [
        _p("hProcess", "HANDLE"), _p("lpExitCode", "LPDWORD", "out"),
    ], "process", "waitpid(WNOHANG)", "moderate",
        "Non-blocking waitpid. STILL_ACTIVE (259) if still running.", True)

    _add("kernel32.dll", "GetModuleHandleA", "HMODULE", [
        _p("lpModuleName", "LPCSTR"),
    ], "process", "dlopen(NULL) / dl_iterate_phdr()", "moderate",
        "NULL -> return main module base. Otherwise search loaded DLL list.", True)

    _add("kernel32.dll", "GetModuleHandleW", "HMODULE", [
        _p("lpModuleName", "LPCWSTR"),
    ], "process", "dlopen(NULL) / dl_iterate_phdr()", "moderate",
        "Wide-char variant.", True)

    _add("kernel32.dll", "GetModuleFileNameA", "DWORD", [
        _p("hModule", "HMODULE"), _p("lpFilename", "LPSTR", "out"),
        _p("nSize", "DWORD"),
    ], "process", "readlink(/proc/self/exe)", "moderate",
        "NULL module: readlink(/proc/self/exe). Otherwise lookup in DLL table.", True)

    _add("kernel32.dll", "GetModuleFileNameW", "DWORD", [
        _p("hModule", "HMODULE"), _p("lpFilename", "LPWSTR", "out"),
        _p("nSize", "DWORD"),
    ], "process", "readlink(/proc/self/exe)", "moderate", "Wide-char variant.", True)

    _add("kernel32.dll", "GetProcAddress", "FARPROC", [
        _p("hModule", "HMODULE"), _p("lpProcName", "LPCSTR"),
    ], "process", "dlsym()", "moderate",
        "Search PE export table for function. Handle ordinal imports "
        "(low 16 bits of lpProcName if < 0x10000).", True)

    _add("kernel32.dll", "LoadLibraryA", "HMODULE", [
        _p("lpLibFileName", "LPCSTR"),
    ], "process", "dlopen()", "complex",
        "Search DLL in app-dir, then .so stubs, then search path. "
        "If PE DLL found, load via pe_mapper. Otherwise dlopen .so stub.", True)

    _add("kernel32.dll", "LoadLibraryW", "HMODULE", [
        _p("lpLibFileName", "LPCWSTR"),
    ], "process", "dlopen()", "complex", "Wide-char variant.", True)

    _add("kernel32.dll", "LoadLibraryExA", "HMODULE", [
        _p("lpLibFileName", "LPCSTR"), _p("hFile", "HANDLE"),
        _p("dwFlags", "DWORD"),
    ], "process", "dlopen()", "complex",
        "Handle LOAD_LIBRARY_AS_DATAFILE, DONT_RESOLVE_DLL_REFERENCES, etc.", True)

    _add("kernel32.dll", "FreeLibrary", "BOOL", [
        _p("hLibModule", "HMODULE"),
    ], "process", "dlclose()", "moderate",
        "Decrement refcount. If zero, unload (dlclose or unmap PE).", True)

    _add("kernel32.dll", "GetCommandLineA", "LPSTR", [], "process",
         "/proc/self/cmdline", "trivial",
         "Return cached command line string.", True)

    _add("kernel32.dll", "GetCommandLineW", "LPWSTR", [], "process",
         "/proc/self/cmdline", "trivial",
         "Wide-char variant of cached command line.", True)

    _add("kernel32.dll", "GetEnvironmentVariableA", "DWORD", [
        _p("lpName", "LPCSTR"), _p("lpBuffer", "LPSTR", "out"),
        _p("nSize", "DWORD"),
    ], "process", "getenv()", "trivial", "Direct getenv().", True)

    _add("kernel32.dll", "GetEnvironmentVariableW", "DWORD", [
        _p("lpName", "LPCWSTR"), _p("lpBuffer", "LPWSTR", "out"),
        _p("nSize", "DWORD"),
    ], "process", "getenv()", "moderate",
        "Convert name to UTF-8, getenv(), convert result to UTF-16.", True)

    _add("kernel32.dll", "SetEnvironmentVariableA", "BOOL", [
        _p("lpName", "LPCSTR"), _p("lpValue", "LPCSTR"),
    ], "process", "setenv() / unsetenv()", "trivial",
        "NULL lpValue -> unsetenv(), otherwise setenv().", True)

    _add("kernel32.dll", "SetEnvironmentVariableW", "BOOL", [
        _p("lpName", "LPCWSTR"), _p("lpValue", "LPCWSTR"),
    ], "process", "setenv() / unsetenv()", "moderate", "Wide-char variant.", True)

    _add("kernel32.dll", "GetStartupInfoA", "void", [
        _p("lpStartupInfo", "LPSTARTUPINFOA", "out"),
    ], "process", "", "moderate",
        "Fill STARTUPINFOA with defaults. Map stdio handles.", True)

    _add("kernel32.dll", "GetStartupInfoW", "void", [
        _p("lpStartupInfo", "LPSTARTUPINFOW", "out"),
    ], "process", "", "moderate", "Wide-char variant.", True)

    _add("kernel32.dll", "OpenProcess", "HANDLE", [
        _p("dwDesiredAccess", "DWORD"), _p("bInheritHandle", "BOOL"),
        _p("dwProcessId", "DWORD"),
    ], "process", "kill(pid, 0) for existence check", "moderate",
        "Wrap target PID in a process handle. Check /proc/PID exists.", True)

    _add("kernel32.dll", "DuplicateHandle", "BOOL", [
        _p("hSourceProcessHandle", "HANDLE"),
        _p("hSourceHandle", "HANDLE"),
        _p("hTargetProcessHandle", "HANDLE"),
        _p("lpTargetHandle", "LPHANDLE", "out"),
        _p("dwDesiredAccess", "DWORD"),
        _p("bInheritHandle", "BOOL"),
        _p("dwOptions", "DWORD"),
    ], "process", "dup() / dup2()", "complex",
        "For file handles: dup(). For sync objects: increment refcount. "
        "DUPLICATE_CLOSE_SOURCE closes original.", True)

    # ===================================================================
    # NETWORK  (ws2_32.dll)  -- 20+ functions
    # ===================================================================
    _add("ws2_32.dll", "WSAStartup", "int", [
        _p("wVersionRequested", "WORD"),
        _p("lpWSAData", "LPWSADATA", "out"),
    ], "network", "", "trivial",
        "Fill WSADATA with version info. Linux sockets need no init.", True)

    _add("ws2_32.dll", "WSACleanup", "int", [], "network", "", "trivial",
        "No-op on Linux. Decrement global init counter.", True)

    _add("ws2_32.dll", "socket", "SOCKET", [
        _p("af", "int"), _p("type", "int"), _p("protocol", "int"),
    ], "network", "socket()", "trivial",
        "Direct socket(). Wrap Linux fd in SOCKET handle.", True)

    _add("ws2_32.dll", "bind", "int", [
        _p("s", "SOCKET"), _p("name", "const struct sockaddr*"),
        _p("namelen", "int"),
    ], "network", "bind()", "trivial", "Direct bind().", True)

    _add("ws2_32.dll", "listen", "int", [
        _p("s", "SOCKET"), _p("backlog", "int"),
    ], "network", "listen()", "trivial", "Direct listen().", True)

    _add("ws2_32.dll", "accept", "SOCKET", [
        _p("s", "SOCKET"), _p("addr", "struct sockaddr*", "out"),
        _p("addrlen", "int*", "inout"),
    ], "network", "accept()", "trivial", "Direct accept(). Wrap returned fd.", True)

    _add("ws2_32.dll", "connect", "int", [
        _p("s", "SOCKET"), _p("name", "const struct sockaddr*"),
        _p("namelen", "int"),
    ], "network", "connect()", "trivial", "Direct connect().", True)

    _add("ws2_32.dll", "send", "int", [
        _p("s", "SOCKET"), _p("buf", "const char*"),
        _p("len", "int"), _p("flags", "int"),
    ], "network", "send()", "trivial",
        "Direct send(). Translate MSG_* flags if needed.", True)

    _add("ws2_32.dll", "recv", "int", [
        _p("s", "SOCKET"), _p("buf", "char*", "out"),
        _p("len", "int"), _p("flags", "int"),
    ], "network", "recv()", "trivial", "Direct recv().", True)

    _add("ws2_32.dll", "sendto", "int", [
        _p("s", "SOCKET"), _p("buf", "const char*"),
        _p("len", "int"), _p("flags", "int"),
        _p("to", "const struct sockaddr*"), _p("tolen", "int"),
    ], "network", "sendto()", "trivial", "Direct sendto().", True)

    _add("ws2_32.dll", "recvfrom", "int", [
        _p("s", "SOCKET"), _p("buf", "char*", "out"),
        _p("len", "int"), _p("flags", "int"),
        _p("from", "struct sockaddr*", "out"), _p("fromlen", "int*", "inout"),
    ], "network", "recvfrom()", "trivial", "Direct recvfrom().", True)

    _add("ws2_32.dll", "closesocket", "int", [
        _p("s", "SOCKET"),
    ], "network", "close()", "trivial",
        "Extract fd from SOCKET handle, close().", True)

    _add("ws2_32.dll", "shutdown", "int", [
        _p("s", "SOCKET"), _p("how", "int"),
    ], "network", "shutdown()", "trivial",
        "SD_RECEIVE->SHUT_RD, SD_SEND->SHUT_WR, SD_BOTH->SHUT_RDWR.", True)

    _add("ws2_32.dll", "select", "int", [
        _p("nfds", "int"), _p("readfds", "fd_set*"),
        _p("writefds", "fd_set*"), _p("exceptfds", "fd_set*"),
        _p("timeout", "const struct timeval*"),
    ], "network", "select()", "moderate",
        "Direct select() but need to translate SOCKET handles to real fds.", True)

    _add("ws2_32.dll", "WSAPoll", "int", [
        _p("fdArray", "LPWSAPOLLFD"), _p("fds", "ULONG"),
        _p("timeout", "INT"),
    ], "network", "poll()", "moderate",
        "Map WSAPOLLFDs to struct pollfd. Direct poll().", True)

    _add("ws2_32.dll", "gethostbyname", "struct hostent*", [
        _p("name", "const char*"),
    ], "network", "gethostbyname()", "trivial",
        "Direct gethostbyname(). Note: not thread-safe, prefer getaddrinfo.", True)

    _add("ws2_32.dll", "getaddrinfo", "int", [
        _p("nodename", "const char*"), _p("servname", "const char*"),
        _p("hints", "const struct addrinfo*"),
        _p("res", "struct addrinfo**", "out"),
    ], "network", "getaddrinfo()", "trivial",
        "Direct getaddrinfo(). Struct layout matches.", True)

    _add("ws2_32.dll", "freeaddrinfo", "void", [
        _p("ai", "struct addrinfo*"),
    ], "network", "freeaddrinfo()", "trivial", "Direct freeaddrinfo().", True)

    _add("ws2_32.dll", "setsockopt", "int", [
        _p("s", "SOCKET"), _p("level", "int"),
        _p("optname", "int"), _p("optval", "const char*"),
        _p("optlen", "int"),
    ], "network", "setsockopt()", "moderate",
        "Translate Windows SO_* constants to Linux equivalents.", True)

    _add("ws2_32.dll", "getsockopt", "int", [
        _p("s", "SOCKET"), _p("level", "int"),
        _p("optname", "int"), _p("optval", "char*", "out"),
        _p("optlen", "int*", "inout"),
    ], "network", "getsockopt()", "moderate",
        "Translate option names.", True)

    _add("ws2_32.dll", "ioctlsocket", "int", [
        _p("s", "SOCKET"), _p("cmd", "long"),
        _p("argp", "u_long*"),
    ], "network", "ioctl() / fcntl()", "moderate",
        "FIONBIO -> fcntl(O_NONBLOCK). FIONREAD -> ioctl(FIONREAD).", True)

    _add("ws2_32.dll", "WSAGetLastError", "int", [], "network",
         "errno", "trivial",
         "Return translated errno. Map EAGAIN->WSAEWOULDBLOCK, etc.", True)

    _add("ws2_32.dll", "WSASend", "int", [
        _p("s", "SOCKET"), _p("lpBuffers", "LPWSABUF"),
        _p("dwBufferCount", "DWORD"),
        _p("lpNumberOfBytesSent", "LPDWORD", "out"),
        _p("dwFlags", "DWORD"), _p("lpOverlapped", "LPWSAOVERLAPPED"),
        _p("lpCompletionRoutine", "LPWSAOVERLAPPED_COMPLETION_ROUTINE"),
    ], "network", "writev()", "complex",
        "Scatter-gather I/O via writev(). Handle overlapped path.", True)

    _add("ws2_32.dll", "WSARecv", "int", [
        _p("s", "SOCKET"), _p("lpBuffers", "LPWSABUF"),
        _p("dwBufferCount", "DWORD"),
        _p("lpNumberOfBytesRecvd", "LPDWORD", "out"),
        _p("lpFlags", "LPDWORD"), _p("lpOverlapped", "LPWSAOVERLAPPED"),
        _p("lpCompletionRoutine", "LPWSAOVERLAPPED_COMPLETION_ROUTINE"),
    ], "network", "readv()", "complex",
        "Scatter-gather receive via readv(). Handle overlapped path.", True)

    _add("ws2_32.dll", "WSASocketA", "SOCKET", [
        _p("af", "int"), _p("type", "int"), _p("protocol", "int"),
        _p("lpProtocolInfo", "LPWSAPROTOCOL_INFOA"),
        _p("g", "GROUP"), _p("dwFlags", "DWORD"),
    ], "network", "socket()", "moderate",
        "Extended socket creation. Handle WSA_FLAG_OVERLAPPED.", True)

    _add("ws2_32.dll", "WSAIoctl", "int", [
        _p("s", "SOCKET"), _p("dwIoControlCode", "DWORD"),
        _p("lpvInBuffer", "LPVOID"), _p("cbInBuffer", "DWORD"),
        _p("lpvOutBuffer", "LPVOID", "out"), _p("cbOutBuffer", "DWORD"),
        _p("lpcbBytesReturned", "LPDWORD", "out"),
        _p("lpOverlapped", "LPWSAOVERLAPPED"),
        _p("lpCompletionRoutine", "LPWSAOVERLAPPED_COMPLETION_ROUTINE"),
    ], "network", "ioctl()", "complex",
        "Handle SIO_GET_EXTENSION_FUNCTION_POINTER for ConnectEx/AcceptEx/etc.", True)

    _add("ws2_32.dll", "gethostname", "int", [
        _p("name", "char*", "out"), _p("namelen", "int"),
    ], "network", "gethostname()", "trivial", "Direct gethostname().", True)

    _add("ws2_32.dll", "getnameinfo", "int", [
        _p("sa", "const struct sockaddr*"), _p("salen", "socklen_t"),
        _p("host", "char*", "out"), _p("hostlen", "DWORD"),
        _p("serv", "char*", "out"), _p("servlen", "DWORD"),
        _p("flags", "int"),
    ], "network", "getnameinfo()", "trivial", "Direct getnameinfo().", True)

    _add("ws2_32.dll", "inet_pton", "int", [
        _p("af", "int"), _p("src", "const char*"),
        _p("dst", "void*", "out"),
    ], "network", "inet_pton()", "trivial", "Direct inet_pton().", True)

    _add("ws2_32.dll", "inet_ntop", "const char*", [
        _p("af", "int"), _p("src", "const void*"),
        _p("dst", "char*", "out"), _p("size", "socklen_t"),
    ], "network", "inet_ntop()", "trivial", "Direct inet_ntop().", True)

    # ===================================================================
    # GDI  (gdi32.dll + user32.dll)  -- 15+ functions
    # ===================================================================
    _add("user32.dll", "GetDC", "HDC", [
        _p("hWnd", "HWND"),
    ], "gdi", "XOpenDisplay() / cairo surface", "complex",
        "Get device context for window. On our Wayland/X11 compositor, "
        "allocate a cairo surface or Xlib GC backed context.", True)

    _add("user32.dll", "ReleaseDC", "int", [
        _p("hWnd", "HWND"), _p("hDC", "HDC"),
    ], "gdi", "", "moderate",
        "Release the DC. Decrement refcount, flush pending draws.", True)

    _add("gdi32.dll", "CreateCompatibleDC", "HDC", [
        _p("hdc", "HDC"),
    ], "gdi", "cairo_create()", "moderate",
        "Create an off-screen compatible DC. Back with a pixmap or cairo surface.", True)

    _add("gdi32.dll", "DeleteDC", "BOOL", [
        _p("hdc", "HDC"),
    ], "gdi", "cairo_destroy()", "trivial", "Free the DC and its resources.", True)

    _add("gdi32.dll", "SelectObject", "HGDIOBJ", [
        _p("hdc", "HDC"), _p("h", "HGDIOBJ"),
    ], "gdi", "", "moderate",
        "Select font/pen/brush/bitmap into DC. Return previous object. "
        "Dispatch by GDI object type.", True)

    _add("gdi32.dll", "BitBlt", "BOOL", [
        _p("hdc", "HDC"), _p("x", "int"), _p("y", "int"),
        _p("cx", "int"), _p("cy", "int"),
        _p("hdcSrc", "HDC"), _p("x1", "int"), _p("y1", "int"),
        _p("rop", "DWORD"),
    ], "gdi", "memcpy / cairo_paint()", "complex",
        "Blit between DCs. Handle raster ops (SRCCOPY, SRCPAINT, etc.). "
        "Most games only use SRCCOPY = simple memcpy of pixel data.", True)

    _add("gdi32.dll", "StretchBlt", "BOOL", [
        _p("hdcDest", "HDC"), _p("xDest", "int"), _p("yDest", "int"),
        _p("wDest", "int"), _p("hDest", "int"),
        _p("hdcSrc", "HDC"), _p("xSrc", "int"), _p("ySrc", "int"),
        _p("wSrc", "int"), _p("hSrc", "int"), _p("rop", "DWORD"),
    ], "gdi", "cairo_scale() + cairo_paint()", "complex",
        "Scaled blit. Same as BitBlt but with source/dest scaling.", True)

    _add("gdi32.dll", "TextOutA", "BOOL", [
        _p("hdc", "HDC"), _p("x", "int"), _p("y", "int"),
        _p("lpString", "LPCSTR"), _p("c", "int"),
    ], "gdi", "XDrawString() / pango", "complex",
        "Render text using selected font. Use fontconfig+freetype or pango.", True)

    _add("gdi32.dll", "TextOutW", "BOOL", [
        _p("hdc", "HDC"), _p("x", "int"), _p("y", "int"),
        _p("lpString", "LPCWSTR"), _p("c", "int"),
    ], "gdi", "pango_layout_set_text()", "complex", "Wide-char variant.", True)

    _add("gdi32.dll", "SetTextColor", "COLORREF", [
        _p("hdc", "HDC"), _p("color", "COLORREF"),
    ], "gdi", "", "trivial", "Store text color in DC state.", True)

    _add("gdi32.dll", "SetBkColor", "COLORREF", [
        _p("hdc", "HDC"), _p("color", "COLORREF"),
    ], "gdi", "", "trivial", "Store background color in DC state.", True)

    _add("gdi32.dll", "GetTextMetricsA", "BOOL", [
        _p("hdc", "HDC"), _p("lptm", "LPTEXTMETRICA", "out"),
    ], "gdi", "freetype FT_Face metrics", "complex",
        "Query selected font metrics. Use freetype/fontconfig to get "
        "height, ascent, descent, avgCharWidth, etc.", True)

    _add("gdi32.dll", "GetTextMetricsW", "BOOL", [
        _p("hdc", "HDC"), _p("lptm", "LPTEXTMETRICW", "out"),
    ], "gdi", "freetype FT_Face metrics", "complex", "Wide-char variant.", True)

    _add("gdi32.dll", "CreateFontA", "HFONT", [
        _p("cHeight", "int"), _p("cWidth", "int"),
        _p("cEscapement", "int"), _p("cOrientation", "int"),
        _p("cWeight", "int"), _p("bItalic", "DWORD"),
        _p("bUnderline", "DWORD"), _p("bStrikeOut", "DWORD"),
        _p("iCharSet", "DWORD"), _p("iOutPrecision", "DWORD"),
        _p("iClipPrecision", "DWORD"), _p("iQuality", "DWORD"),
        _p("iPitchAndFamily", "DWORD"), _p("pszFaceName", "LPCSTR"),
    ], "gdi", "fontconfig + freetype", "complex",
        "Use fontconfig to find matching font, load with freetype.", True)

    _add("gdi32.dll", "CreateFontIndirectA", "HFONT", [
        _p("lplf", "const LOGFONTA*"),
    ], "gdi", "fontconfig + freetype", "complex",
        "Create font from LOGFONT structure.", True)

    _add("gdi32.dll", "CreatePen", "HPEN", [
        _p("iStyle", "int"), _p("cWidth", "int"),
        _p("color", "COLORREF"),
    ], "gdi", "", "trivial", "Allocate pen object with style/width/color.", True)

    _add("gdi32.dll", "CreateSolidBrush", "HBRUSH", [
        _p("color", "COLORREF"),
    ], "gdi", "", "trivial", "Allocate solid brush with color.", True)

    _add("gdi32.dll", "DeleteObject", "BOOL", [
        _p("ho", "HGDIOBJ"),
    ], "gdi", "", "trivial", "Free GDI object by type.", True)

    _add("gdi32.dll", "GetStockObject", "HGDIOBJ", [
        _p("i", "int"),
    ], "gdi", "", "moderate",
        "Return pre-created stock objects (DEFAULT_GUI_FONT, WHITE_BRUSH, etc.).", True)

    # ===================================================================
    # SYSTEM INFO  (kernel32.dll)  -- 10+ functions
    # ===================================================================
    _add("kernel32.dll", "GetSystemInfo", "void", [
        _p("lpSystemInfo", "LPSYSTEM_INFO", "out"),
    ], "system", "sysconf() / /proc/cpuinfo", "moderate",
        "Fill SYSTEM_INFO: page size from sysconf(_SC_PAGESIZE), "
        "CPU count from sysconf(_SC_NPROCESSORS_ONLN), "
        "processor architecture from uname.", True)

    _add("kernel32.dll", "GetVersionExA", "BOOL", [
        _p("lpVersionInformation", "LPOSVERSIONINFOA", "out"),
    ], "system", "", "trivial",
        "Return fake Windows 10 version info (10.0.19041). "
        "Required by almost every program.", True)

    _add("kernel32.dll", "GetVersionExW", "BOOL", [
        _p("lpVersionInformation", "LPOSVERSIONINFOW", "out"),
    ], "system", "", "trivial", "Wide-char variant.", True)

    _add("kernel32.dll", "GetVersion", "DWORD", [], "system", "", "trivial",
        "Return packed version DWORD for Windows 10.", True)

    _add("kernel32.dll", "GetTickCount", "DWORD", [], "system",
         "clock_gettime(CLOCK_MONOTONIC)", "trivial",
         "Milliseconds since boot. clock_gettime(CLOCK_MONOTONIC) truncated to 32-bit.", True)

    _add("kernel32.dll", "GetTickCount64", "ULONGLONG", [], "system",
         "clock_gettime(CLOCK_MONOTONIC)", "trivial",
         "64-bit variant. No overflow concern.", True)

    _add("kernel32.dll", "QueryPerformanceCounter", "BOOL", [
        _p("lpPerformanceCount", "PLARGE_INTEGER", "out"),
    ], "system", "clock_gettime(CLOCK_MONOTONIC)", "trivial",
        "Return nanosecond monotonic clock value.", True)

    _add("kernel32.dll", "QueryPerformanceFrequency", "BOOL", [
        _p("lpFrequency", "PLARGE_INTEGER", "out"),
    ], "system", "", "trivial",
        "Return 1000000000 (nanoseconds) or 10000000 (100ns ticks).", True)

    _add("kernel32.dll", "GetSystemTime", "void", [
        _p("lpSystemTime", "LPSYSTEMTIME", "out"),
    ], "system", "clock_gettime(CLOCK_REALTIME)", "moderate",
        "Get UTC time, fill SYSTEMTIME struct (year, month, day, etc.).", True)

    _add("kernel32.dll", "GetLocalTime", "void", [
        _p("lpSystemTime", "LPSYSTEMTIME", "out"),
    ], "system", "localtime_r()", "moderate",
        "Get local time via localtime_r(), fill SYSTEMTIME.", True)

    _add("kernel32.dll", "GetTimeZoneInformation", "DWORD", [
        _p("lpTimeZoneInformation", "LPTIME_ZONE_INFORMATION", "out"),
    ], "system", "tzset() + tm_gmtoff", "moderate",
        "Fill TIME_ZONE_INFORMATION from tzdata.", True)

    _add("kernel32.dll", "GetSystemTimeAsFileTime", "void", [
        _p("lpSystemTimeAsFileTime", "LPFILETIME", "out"),
    ], "system", "clock_gettime(CLOCK_REALTIME)", "trivial",
        "Convert to Windows FILETIME (100ns since 1601-01-01).", True)

    _add("kernel32.dll", "GetComputerNameA", "BOOL", [
        _p("lpBuffer", "LPSTR", "out"), _p("nSize", "LPDWORD", "inout"),
    ], "system", "gethostname()", "trivial",
        "Direct gethostname().", True)

    _add("kernel32.dll", "GetComputerNameW", "BOOL", [
        _p("lpBuffer", "LPWSTR", "out"), _p("nSize", "LPDWORD", "inout"),
    ], "system", "gethostname()", "moderate", "Wide-char variant.", True)

    _add("advapi32.dll", "GetUserNameA", "BOOL", [
        _p("lpBuffer", "LPSTR", "out"), _p("pcbBuffer", "LPDWORD", "inout"),
    ], "system", "getlogin_r() / getpwuid()", "trivial",
        "getlogin_r() or getpwuid(getuid())->pw_name.", True)

    _add("advapi32.dll", "GetUserNameW", "BOOL", [
        _p("lpBuffer", "LPWSTR", "out"), _p("pcbBuffer", "LPDWORD", "inout"),
    ], "system", "getlogin_r() / getpwuid()", "moderate", "Wide-char variant.", True)

    _add("kernel32.dll", "IsProcessorFeaturePresent", "BOOL", [
        _p("ProcessorFeature", "DWORD"),
    ], "system", "cpuid / /proc/cpuinfo", "moderate",
        "Check for SSE, SSE2, AVX, etc. Read /proc/cpuinfo or use cpuid.", True)

    _add("kernel32.dll", "GetNativeSystemInfo", "void", [
        _p("lpSystemInfo", "LPSYSTEM_INFO", "out"),
    ], "system", "sysconf() / uname()", "moderate",
        "Same as GetSystemInfo for native (non-WOW64) processes.", True)

    # ===================================================================
    # CONSOLE  (kernel32.dll)  -- 10+ functions
    # ===================================================================
    _add("kernel32.dll", "GetStdHandle", "HANDLE", [
        _p("nStdHandle", "DWORD"),
    ], "console", "STDIN_FILENO / STDOUT_FILENO / STDERR_FILENO", "trivial",
        "STD_INPUT_HANDLE=0, STD_OUTPUT_HANDLE=1, STD_ERROR_HANDLE=2.", True)

    _add("kernel32.dll", "WriteConsoleA", "BOOL", [
        _p("hConsoleOutput", "HANDLE"), _p("lpBuffer", "const void*"),
        _p("nNumberOfCharsToWrite", "DWORD"),
        _p("lpNumberOfCharsWritten", "LPDWORD", "out"),
        _p("lpReserved", "LPVOID"),
    ], "console", "write()", "trivial", "write() to fd 1 or 2.", True)

    _add("kernel32.dll", "WriteConsoleW", "BOOL", [
        _p("hConsoleOutput", "HANDLE"), _p("lpBuffer", "const void*"),
        _p("nNumberOfCharsToWrite", "DWORD"),
        _p("lpNumberOfCharsWritten", "LPDWORD", "out"),
        _p("lpReserved", "LPVOID"),
    ], "console", "write()", "moderate", "Convert UTF-16 to UTF-8, then write().", True)

    _add("kernel32.dll", "ReadConsoleA", "BOOL", [
        _p("hConsoleInput", "HANDLE"), _p("lpBuffer", "LPVOID", "out"),
        _p("nNumberOfCharsToRead", "DWORD"),
        _p("lpNumberOfCharsRead", "LPDWORD", "out"),
        _p("pInputControl", "PCONSOLE_READCONSOLE_CONTROL"),
    ], "console", "read()", "moderate", "read() from stdin.", True)

    _add("kernel32.dll", "AllocConsole", "BOOL", [], "console",
         "openpty()", "moderate",
         "Allocate a pseudo-terminal for the process.", True)

    _add("kernel32.dll", "FreeConsole", "BOOL", [], "console",
         "", "trivial", "Detach from console. Close pty fds.", True)

    _add("kernel32.dll", "SetConsoleMode", "BOOL", [
        _p("hConsoleHandle", "HANDLE"), _p("dwMode", "DWORD"),
    ], "console", "tcsetattr()", "moderate",
        "Map ENABLE_ECHO_INPUT to ECHO, ENABLE_LINE_INPUT to ICANON, etc.", True)

    _add("kernel32.dll", "GetConsoleMode", "BOOL", [
        _p("hConsoleHandle", "HANDLE"), _p("lpMode", "LPDWORD", "out"),
    ], "console", "tcgetattr()", "moderate",
        "Read terminal attributes and map to console mode flags.", True)

    _add("kernel32.dll", "SetConsoleTitleA", "BOOL", [
        _p("lpConsoleTitle", "LPCSTR"),
    ], "console", "printf(\"\\033]0;%s\\007\", title)", "trivial",
        "Set terminal title via ANSI escape sequence.", True)

    _add("kernel32.dll", "GetConsoleWindow", "HWND", [], "console",
         "", "trivial", "Return pseudo HWND for the console window.", True)

    # ===================================================================
    # STRING / LOCALE  (kernel32.dll)  -- frequently needed
    # ===================================================================
    _add("kernel32.dll", "MultiByteToWideChar", "int", [
        _p("CodePage", "UINT"), _p("dwFlags", "DWORD"),
        _p("lpMultiByteStr", "LPCCH"), _p("cbMultiByte", "int"),
        _p("lpWideCharStr", "LPWSTR", "out"), _p("cchWideChar", "int"),
    ], "string", "mbstowcs() / iconv()", "moderate",
        "Convert CP_ACP/CP_UTF8 to UTF-16LE. Use iconv for arbitrary codepages.", True)

    _add("kernel32.dll", "WideCharToMultiByte", "int", [
        _p("CodePage", "UINT"), _p("dwFlags", "DWORD"),
        _p("lpWideCharStr", "LPCWCH"), _p("cchWideChar", "int"),
        _p("lpMultiByteStr", "LPSTR", "out"), _p("cbMultiByte", "int"),
        _p("lpDefaultChar", "LPCCH"), _p("lpUsedDefaultChar", "LPBOOL", "out"),
    ], "string", "wcstombs() / iconv()", "moderate",
        "Convert UTF-16LE to CP_ACP/CP_UTF8. Critical for all wide-char APIs.", True)

    _add("kernel32.dll", "GetACP", "UINT", [], "string", "", "trivial",
        "Return 65001 (UTF-8) or system locale codepage.", True)

    _add("kernel32.dll", "lstrlenA", "int", [
        _p("lpString", "LPCSTR"),
    ], "string", "strlen()", "trivial", "Direct strlen().", True)

    _add("kernel32.dll", "lstrlenW", "int", [
        _p("lpString", "LPCWSTR"),
    ], "string", "wcslen()", "trivial",
        "Count uint16_t chars until null (not wcslen due to wchar_t size mismatch).", True)

    _add("kernel32.dll", "lstrcpyA", "LPSTR", [
        _p("lpString1", "LPSTR", "out"), _p("lpString2", "LPCSTR"),
    ], "string", "strcpy()", "trivial", "Direct strcpy().", True)

    _add("kernel32.dll", "lstrcmpA", "int", [
        _p("lpString1", "LPCSTR"), _p("lpString2", "LPCSTR"),
    ], "string", "strcmp()", "trivial", "Direct strcmp().", True)

    _add("kernel32.dll", "lstrcmpiA", "int", [
        _p("lpString1", "LPCSTR"), _p("lpString2", "LPCSTR"),
    ], "string", "strcasecmp()", "trivial", "Direct strcasecmp().", True)

    # ===================================================================
    # ERROR HANDLING  (kernel32.dll)
    # ===================================================================
    _add("kernel32.dll", "GetLastError", "DWORD", [], "error",
         "errno (translated)", "trivial",
         "Return thread-local Win32 error code. Map from errno if needed.", True)

    _add("kernel32.dll", "SetLastError", "void", [
        _p("dwErrCode", "DWORD"),
    ], "error", "", "trivial", "Set thread-local Win32 error code.", True)

    _add("kernel32.dll", "FormatMessageA", "DWORD", [
        _p("dwFlags", "DWORD"), _p("lpSource", "LPCVOID"),
        _p("dwMessageId", "DWORD"), _p("dwLanguageId", "DWORD"),
        _p("lpBuffer", "LPSTR", "out"), _p("nSize", "DWORD"),
        _p("Arguments", "va_list*"),
    ], "error", "strerror_r()", "moderate",
        "FORMAT_MESSAGE_FROM_SYSTEM: lookup Win32 error in our message table. "
        "FORMAT_MESSAGE_ALLOCATE_BUFFER: LocalAlloc the output.", False)

    _add("kernel32.dll", "FormatMessageW", "DWORD", [
        _p("dwFlags", "DWORD"), _p("lpSource", "LPCVOID"),
        _p("dwMessageId", "DWORD"), _p("dwLanguageId", "DWORD"),
        _p("lpBuffer", "LPWSTR", "out"), _p("nSize", "DWORD"),
        _p("Arguments", "va_list*"),
    ], "error", "strerror_r()", "moderate", "Wide-char variant.", False)

    _add("kernel32.dll", "RaiseException", "void", [
        _p("dwExceptionCode", "DWORD"), _p("dwExceptionFlags", "DWORD"),
        _p("nNumberOfArguments", "DWORD"),
        _p("lpArguments", "const ULONG_PTR*"),
    ], "error", "raise(SIGSEGV) / longjmp", "complex",
        "Dispatch through SEH chain. Unhandled exceptions become signals.", True)

    _add("kernel32.dll", "SetUnhandledExceptionFilter", "LPTOP_LEVEL_EXCEPTION_FILTER", [
        _p("lpTopLevelExceptionFilter", "LPTOP_LEVEL_EXCEPTION_FILTER"),
    ], "error", "signal(SIGSEGV, ...)", "moderate",
        "Install top-level SEH filter. Store globally.", True)

    _add("kernel32.dll", "AddVectoredExceptionHandler", "PVOID", [
        _p("First", "ULONG"), _p("Handler", "PVECTORED_EXCEPTION_HANDLER"),
    ], "error", "signal handling", "complex",
        "Add to VEH list. Called before frame-based SEH handlers.", True)

    _add("kernel32.dll", "RemoveVectoredExceptionHandler", "ULONG", [
        _p("Handle", "PVOID"),
    ], "error", "", "trivial", "Remove from VEH list.", True)

    # ===================================================================
    # SECURITY  (advapi32.dll)  -- commonly needed
    # ===================================================================
    _add("advapi32.dll", "OpenProcessToken", "BOOL", [
        _p("ProcessHandle", "HANDLE"), _p("DesiredAccess", "DWORD"),
        _p("TokenHandle", "PHANDLE", "out"),
    ], "security", "", "moderate",
        "Return a fake token handle. Games check this for admin detection.", True)

    _add("advapi32.dll", "GetTokenInformation", "BOOL", [
        _p("TokenHandle", "HANDLE"), _p("TokenInformationClass", "TOKEN_INFORMATION_CLASS"),
        _p("TokenInformation", "LPVOID", "out"),
        _p("TokenInformationLength", "DWORD"),
        _p("ReturnLength", "PDWORD", "out"),
    ], "security", "getuid() / getgroups()", "complex",
        "Fake token info. TokenUser -> fake SID, TokenElevation -> not elevated.", True)

    _add("advapi32.dll", "AdjustTokenPrivileges", "BOOL", [
        _p("TokenHandle", "HANDLE"), _p("DisableAllPrivileges", "BOOL"),
        _p("NewState", "PTOKEN_PRIVILEGES"),
        _p("BufferLength", "DWORD"),
        _p("PreviousState", "PTOKEN_PRIVILEGES", "out"),
        _p("ReturnLength", "PDWORD", "out"),
    ], "security", "", "trivial",
        "Always succeed. Privilege checks are meaningless on Linux.", True)

    _add("advapi32.dll", "LookupPrivilegeValueA", "BOOL", [
        _p("lpSystemName", "LPCSTR"), _p("lpName", "LPCSTR"),
        _p("lpLuid", "PLUID", "out"),
    ], "security", "", "trivial",
        "Return a fake LUID for the privilege name.", True)

    # ===================================================================
    # MODULE / PE LOADING  (ntdll.dll)  -- internal runtime
    # ===================================================================
    _add("ntdll.dll", "RtlInitUnicodeString", "void", [
        _p("DestinationString", "PUNICODE_STRING"),
        _p("SourceString", "PCWSTR"),
    ], "ntdll", "", "trivial",
        "Initialize UNICODE_STRING from wide char pointer.", True)

    _add("ntdll.dll", "NtQueryInformationProcess", "NTSTATUS", [
        _p("ProcessHandle", "HANDLE"),
        _p("ProcessInformationClass", "PROCESSINFOCLASS"),
        _p("ProcessInformation", "PVOID", "out"),
        _p("ProcessInformationLength", "ULONG"),
        _p("ReturnLength", "PULONG", "out"),
    ], "ntdll", "/proc/self/*", "complex",
        "Return process info. ProcessBasicInformation -> PEB address, "
        "ProcessDebugPort -> 0 (no debugger).", True)

    _add("ntdll.dll", "NtQuerySystemInformation", "NTSTATUS", [
        _p("SystemInformationClass", "SYSTEM_INFORMATION_CLASS"),
        _p("SystemInformation", "PVOID", "out"),
        _p("SystemInformationLength", "ULONG"),
        _p("ReturnLength", "PULONG", "out"),
    ], "ntdll", "/proc/* + sysinfo()", "complex",
        "SystemBasicInformation, SystemPerformanceInformation, etc. "
        "Anti-cheat queries this heavily.", False)

    _add("ntdll.dll", "RtlGetVersion", "NTSTATUS", [
        _p("lpVersionInformation", "PRTL_OSVERSIONINFOW", "out"),
    ], "ntdll", "", "trivial",
        "Always return Windows 10 build 19041. "
        "Not subject to manifest-based version lies.", True)

    _add("ntdll.dll", "NtClose", "NTSTATUS", [
        _p("Handle", "HANDLE"),
    ], "ntdll", "close()", "trivial", "Close any NT handle.", True)

    _add("ntdll.dll", "NtCreateFile", "NTSTATUS", [
        _p("FileHandle", "PHANDLE", "out"),
        _p("DesiredAccess", "ACCESS_MASK"),
        _p("ObjectAttributes", "POBJECT_ATTRIBUTES"),
        _p("IoStatusBlock", "PIO_STATUS_BLOCK", "out"),
        _p("AllocationSize", "PLARGE_INTEGER"),
        _p("FileAttributes", "ULONG"),
        _p("ShareAccess", "ULONG"),
        _p("CreateDisposition", "ULONG"),
        _p("CreateOptions", "ULONG"),
        _p("EaBuffer", "PVOID"), _p("EaLength", "ULONG"),
    ], "ntdll", "open()", "complex",
        "NT-level file open. Convert OBJECT_ATTRIBUTES path to POSIX path. "
        "Strip \\??\\C:\\ prefix.", False)

    # ===================================================================
    # MISCELLANEOUS commonly-needed APIs
    # ===================================================================
    _add("kernel32.dll", "GetCurrentDirectoryA", "DWORD", [
        _p("nBufferLength", "DWORD"), _p("lpBuffer", "LPSTR", "out"),
    ], "file_io", "getcwd()", "trivial", "Direct getcwd().", True)

    _add("kernel32.dll", "SetCurrentDirectoryA", "BOOL", [
        _p("lpPathName", "LPCSTR"),
    ], "file_io", "chdir()", "trivial", "Direct chdir().", True)

    _add("kernel32.dll", "GetWindowsDirectoryA", "UINT", [
        _p("lpBuffer", "LPSTR", "out"), _p("uSize", "UINT"),
    ], "system", "", "trivial",
        "Return fake C:\\Windows path or /usr/lib/pe-compat/windows.", True)

    _add("kernel32.dll", "GetSystemDirectoryA", "UINT", [
        _p("lpBuffer", "LPSTR", "out"), _p("uSize", "UINT"),
    ], "system", "", "trivial",
        "Return fake C:\\Windows\\System32 path.", True)

    _add("kernel32.dll", "IsDebuggerPresent", "BOOL", [], "process",
         "", "trivial", "Always return FALSE. Anti-debug check.", True)

    _add("kernel32.dll", "OutputDebugStringA", "void", [
        _p("lpOutputString", "LPCSTR"),
    ], "process", "fprintf(stderr, ...)", "trivial",
        "Write to stderr or syslog.", True)

    _add("kernel32.dll", "IsWow64Process", "BOOL", [
        _p("hProcess", "HANDLE"), _p("Wow64Process", "PBOOL", "out"),
    ], "process", "", "trivial",
        "Return FALSE (not running under WOW64).", True)

    _add("kernel32.dll", "GetProcessId", "DWORD", [
        _p("Process", "HANDLE"),
    ], "process", "", "trivial", "Extract PID from process handle.", True)

    _add("kernel32.dll", "FlsAlloc", "DWORD", [
        _p("lpCallback", "PFLS_CALLBACK_FUNCTION"),
    ], "thread", "pthread_key_create()", "moderate",
        "Fiber-local storage. Map to TLS since we emulate fibers as threads.", True)

    _add("kernel32.dll", "FlsFree", "BOOL", [
        _p("dwFlsIndex", "DWORD"),
    ], "thread", "pthread_key_delete()", "trivial", "Free FLS slot.", True)

    _add("kernel32.dll", "FlsGetValue", "PVOID", [
        _p("dwFlsIndex", "DWORD"),
    ], "thread", "pthread_getspecific()", "trivial", "Get FLS value.", True)

    _add("kernel32.dll", "FlsSetValue", "BOOL", [
        _p("dwFlsIndex", "DWORD"), _p("lpFlsData", "PVOID"),
    ], "thread", "pthread_setspecific()", "trivial", "Set FLS value.", True)

    _add("kernel32.dll", "InitializeSRWLock", "void", [
        _p("SRWLock", "PSRWLOCK"),
    ], "sync", "pthread_rwlock_init()", "trivial",
        "Init slim reader/writer lock. Backed by pthread_rwlock_t.", True)

    _add("kernel32.dll", "AcquireSRWLockExclusive", "void", [
        _p("SRWLock", "PSRWLOCK"),
    ], "sync", "pthread_rwlock_wrlock()", "trivial",
        "Write-lock the SRW lock.", True)

    _add("kernel32.dll", "AcquireSRWLockShared", "void", [
        _p("SRWLock", "PSRWLOCK"),
    ], "sync", "pthread_rwlock_rdlock()", "trivial",
        "Read-lock the SRW lock.", True)

    _add("kernel32.dll", "ReleaseSRWLockExclusive", "void", [
        _p("SRWLock", "PSRWLOCK"),
    ], "sync", "pthread_rwlock_unlock()", "trivial", "Unlock write lock.", True)

    _add("kernel32.dll", "ReleaseSRWLockShared", "void", [
        _p("SRWLock", "PSRWLOCK"),
    ], "sync", "pthread_rwlock_unlock()", "trivial", "Unlock read lock.", True)

    _add("kernel32.dll", "InitOnceInitialize", "void", [
        _p("InitOnce", "PINIT_ONCE"),
    ], "sync", "pthread_once_init", "trivial",
        "Zero-init the INIT_ONCE structure.", True)

    _add("kernel32.dll", "InitOnceExecuteOnce", "BOOL", [
        _p("InitOnce", "PINIT_ONCE"),
        _p("InitFn", "PINIT_ONCE_FN"),
        _p("Parameter", "PVOID"),
        _p("Context", "LPVOID*", "out"),
    ], "sync", "pthread_once()", "moderate",
        "Execute init function exactly once. Use pthread_once or CAS.", True)

    _add("kernel32.dll", "InitializeConditionVariable", "void", [
        _p("ConditionVariable", "PCONDITION_VARIABLE"),
    ], "sync", "pthread_cond_init()", "trivial", "Init condition variable.", True)

    _add("kernel32.dll", "SleepConditionVariableCS", "BOOL", [
        _p("ConditionVariable", "PCONDITION_VARIABLE"),
        _p("CriticalSection", "PCRITICAL_SECTION"),
        _p("dwMilliseconds", "DWORD"),
    ], "sync", "pthread_cond_timedwait()", "moderate",
        "Wait on condvar with CS held. Convert timeout to abstime.", True)

    _add("kernel32.dll", "SleepConditionVariableSRW", "BOOL", [
        _p("ConditionVariable", "PCONDITION_VARIABLE"),
        _p("SRWLock", "PSRWLOCK"),
        _p("dwMilliseconds", "DWORD"),
        _p("Flags", "ULONG"),
    ], "sync", "pthread_cond_timedwait()", "moderate",
        "Wait on condvar with SRW lock held.", True)

    _add("kernel32.dll", "WakeConditionVariable", "void", [
        _p("ConditionVariable", "PCONDITION_VARIABLE"),
    ], "sync", "pthread_cond_signal()", "trivial", "Signal one waiter.", True)

    _add("kernel32.dll", "WakeAllConditionVariable", "void", [
        _p("ConditionVariable", "PCONDITION_VARIABLE"),
    ], "sync", "pthread_cond_broadcast()", "trivial", "Signal all waiters.", True)

    # ===================================================================
    # WAITABLE TIMER  (kernel32.dll)
    # ===================================================================
    _add("kernel32.dll", "CreateWaitableTimerA", "HANDLE", [
        _p("lpTimerAttributes", "LPSECURITY_ATTRIBUTES"),
        _p("bManualReset", "BOOL"), _p("lpTimerName", "LPCSTR"),
    ], "sync", "timerfd_create()", "moderate",
        "Create waitable timer backed by timerfd.", True)

    _add("kernel32.dll", "SetWaitableTimer", "BOOL", [
        _p("hTimer", "HANDLE"), _p("lpDueTime", "const LARGE_INTEGER*"),
        _p("lPeriod", "LONG"),
        _p("pfnCompletionRoutine", "PTIMERAPCROUTINE"),
        _p("lpArgToCompletionRoutine", "LPVOID"),
        _p("fResume", "BOOL"),
    ], "sync", "timerfd_settime()", "moderate",
        "Set timer interval. Negative due time = relative.", True)

    _add("kernel32.dll", "CancelWaitableTimer", "BOOL", [
        _p("hTimer", "HANDLE"),
    ], "sync", "timerfd_settime(0)", "trivial", "Disarm the timer.", True)

    # ===================================================================
    # THREADPOOL  (kernel32.dll)  -- common in modern apps
    # ===================================================================
    _add("kernel32.dll", "CreateThreadpoolWork", "PTP_WORK", [
        _p("pfnwk", "PTP_WORK_CALLBACK"), _p("pv", "PVOID"),
        _p("pcbe", "PTP_CALLBACK_ENVIRON"),
    ], "thread", "custom thread pool", "complex",
        "Create work item for submission to thread pool. "
        "Our pool uses pthreads + work queue.", False)

    _add("kernel32.dll", "SubmitThreadpoolWork", "void", [
        _p("pwk", "PTP_WORK"),
    ], "thread", "", "moderate",
        "Enqueue work item to thread pool queue.", False)

    _add("kernel32.dll", "WaitForThreadpoolWorkCallbacks", "void", [
        _p("pwk", "PTP_WORK"), _p("fCancelPendingCallbacks", "BOOL"),
    ], "thread", "", "moderate",
        "Wait for all callbacks of this work item to complete.", False)

    _add("kernel32.dll", "CloseThreadpoolWork", "void", [
        _p("pwk", "PTP_WORK"),
    ], "thread", "", "trivial", "Free the work item.", False)

    _add("kernel32.dll", "CreateThreadpoolTimer", "PTP_TIMER", [
        _p("pfnti", "PTP_TIMER_CALLBACK"), _p("pv", "PVOID"),
        _p("pcbe", "PTP_CALLBACK_ENVIRON"),
    ], "thread", "timer_create() + thread pool", "complex",
        "Create a timer that fires callbacks in the thread pool.", False)

    _add("kernel32.dll", "SetThreadpoolTimer", "void", [
        _p("pti", "PTP_TIMER"), _p("pftDueTime", "PFILETIME"),
        _p("msPeriod", "DWORD"), _p("msWindowLength", "DWORD"),
    ], "thread", "timer_settime()", "moderate", "Set timer parameters.", False)

    _add("kernel32.dll", "CloseThreadpoolTimer", "void", [
        _p("pti", "PTP_TIMER"),
    ], "thread", "timer_delete()", "trivial", "Free the timer.", False)

    # ===================================================================
    # UNIMPLEMENTED but commonly requested APIs
    # ===================================================================
    _add("kernel32.dll", "GetLogicalDriveStringsA", "DWORD", [
        _p("nBufferLength", "DWORD"), _p("lpBuffer", "LPSTR", "out"),
    ], "file_io", "", "moderate",
        "Return fake drive strings (\"C:\\\\\", \"Z:\\\\\"). "
        "Map to / and /home or mount points.", False)

    _add("kernel32.dll", "GetDriveTypeA", "UINT", [
        _p("lpRootPathName", "LPCSTR"),
    ], "file_io", "statfs()", "trivial",
        "Return DRIVE_FIXED for most paths. DRIVE_CDROM for /dev/cdrom.", False)

    _add("kernel32.dll", "GetVolumeInformationA", "BOOL", [
        _p("lpRootPathName", "LPCSTR"),
        _p("lpVolumeNameBuffer", "LPSTR", "out"),
        _p("nVolumeNameSize", "DWORD"),
        _p("lpVolumeSerialNumber", "LPDWORD", "out"),
        _p("lpMaximumComponentLength", "LPDWORD", "out"),
        _p("lpFileSystemFlags", "LPDWORD", "out"),
        _p("lpFileSystemNameBuffer", "LPSTR", "out"),
        _p("nFileSystemNameSize", "DWORD"),
    ], "file_io", "statvfs()", "moderate",
        "Return fake volume info. NTFS filesystem name, 255 max component.", True)

    _add("user32.dll", "MessageBoxA", "int", [
        _p("hWnd", "HWND"), _p("lpText", "LPCSTR"),
        _p("lpCaption", "LPCSTR"), _p("uType", "UINT"),
    ], "ui", "zenity / kdialog / notify-send", "moderate",
        "Show dialog via zenity --question or kdialog. "
        "Parse MB_OK/MB_YESNO/MB_OKCANCEL for button config.", False)

    _add("user32.dll", "MessageBoxW", "int", [
        _p("hWnd", "HWND"), _p("lpText", "LPCWSTR"),
        _p("lpCaption", "LPCWSTR"), _p("uType", "UINT"),
    ], "ui", "zenity / kdialog", "moderate", "Wide-char variant.", False)

    _add("shell32.dll", "ShellExecuteA", "HINSTANCE", [
        _p("hwnd", "HWND"), _p("lpOperation", "LPCSTR"),
        _p("lpFile", "LPCSTR"), _p("lpParameters", "LPCSTR"),
        _p("lpDirectory", "LPCSTR"), _p("nShowCmd", "INT"),
    ], "shell", "xdg-open / fork+exec", "moderate",
        "\"open\" verb: xdg-open. \"runas\": pkexec. Others: fork+exec.", False)

    _add("shell32.dll", "SHGetFolderPathA", "HRESULT", [
        _p("hwnd", "HWND"), _p("csidl", "int"),
        _p("hToken", "HANDLE"), _p("dwFlags", "DWORD"),
        _p("pszPath", "LPSTR", "out"),
    ], "shell", "XDG base dirs", "moderate",
        "CSIDL_APPDATA -> $XDG_CONFIG_HOME, CSIDL_PERSONAL -> $HOME, "
        "CSIDL_LOCAL_APPDATA -> $XDG_DATA_HOME, etc.", False)

    _add("shell32.dll", "SHGetKnownFolderPath", "HRESULT", [
        _p("rfid", "REFKNOWNFOLDERID"), _p("dwFlags", "DWORD"),
        _p("hToken", "HANDLE"), _p("ppszPath", "PWSTR*", "out"),
    ], "shell", "XDG base dirs", "moderate",
        "Modern API. Map FOLDERID_* GUIDs to XDG paths.", False)

    _add("ole32.dll", "CoInitializeEx", "HRESULT", [
        _p("pvReserved", "LPVOID"), _p("dwCoInit", "DWORD"),
    ], "com", "", "moderate",
        "Initialize COM. Set thread apartment model. "
        "Track init state for CoUninitialize balance.", True)

    _add("ole32.dll", "CoUninitialize", "void", [], "com", "", "trivial",
        "Decrement COM init counter.", True)

    _add("ole32.dll", "CoCreateInstance", "HRESULT", [
        _p("rclsid", "REFCLSID"), _p("pUnkOuter", "LPUNKNOWN"),
        _p("dwClsContext", "DWORD"), _p("riid", "REFIID"),
        _p("ppv", "LPVOID*", "out"),
    ], "com", "", "complex",
        "Create COM object. Lookup CLSID in our registration table. "
        "Return stub interface or real implementation.", True)

    _add("oleaut32.dll", "SysAllocString", "BSTR", [
        _p("psz", "const OLECHAR*"),
    ], "com", "malloc() + length prefix", "moderate",
        "Allocate BSTR: 4-byte length prefix + UTF-16 data + null.", True)

    _add("oleaut32.dll", "SysFreeString", "void", [
        _p("bstrString", "BSTR"),
    ], "com", "free()", "trivial", "Free BSTR (back up 4 bytes for real pointer).", True)

    _add("oleaut32.dll", "SysStringLen", "UINT", [
        _p("bstr", "BSTR"),
    ], "com", "", "trivial", "Read length prefix from BSTR.", True)

    _add("version.dll", "GetFileVersionInfoA", "BOOL", [
        _p("lptstrFilename", "LPCSTR"), _p("dwHandle", "DWORD"),
        _p("dwLen", "DWORD"), _p("lpData", "LPVOID", "out"),
    ], "version", "", "complex",
        "Extract VERSION_INFO resource from PE file.", True)

    _add("version.dll", "GetFileVersionInfoSizeA", "DWORD", [
        _p("lptstrFilename", "LPCSTR"),
        _p("lpdwHandle", "LPDWORD", "out"),
    ], "version", "", "moderate",
        "Return size needed for GetFileVersionInfoA buffer.", True)

    _add("version.dll", "VerQueryValueA", "BOOL", [
        _p("pBlock", "LPCVOID"), _p("lpSubBlock", "LPCSTR"),
        _p("lplpBuffer", "LPVOID*", "out"),
        _p("puLen", "PUINT", "out"),
    ], "version", "", "moderate",
        "Query version info sub-block (\\\\, \\\\StringFileInfo, etc.).", True)

    return sigs


# ---------------------------------------------------------------------------
# Database class
# ---------------------------------------------------------------------------

_DB_VERSION = 1


class WinApiDatabase:
    """Queryable Windows API signature database."""

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path or "/var/lib/ai-control/win_api_db.json"
        self._signatures: dict[str, WinApiSignature] = {}
        self._by_dll: dict[str, list[str]] = {}          # dll -> [keys]
        self._by_category: dict[str, list[str]] = {}     # cat -> [keys]
        self._by_complexity: dict[str, list[str]] = {}   # cpx -> [keys]
        self._load()

    @staticmethod
    def _key(dll: str, name: str) -> str:
        return f"{dll.lower()}::{name}"

    def _index_sig(self, key: str, sig: WinApiSignature):
        dll = sig.dll.lower()
        self._by_dll.setdefault(dll, []).append(key)
        self._by_category.setdefault(sig.category, []).append(key)
        self._by_complexity.setdefault(sig.complexity, []).append(key)

    def _load(self):
        """Load from persisted JSON, falling back to built-in defaults."""
        loaded = False
        if os.path.exists(self._db_path):
            try:
                with open(self._db_path) as f:
                    data = json.load(f)
                if data.get("version") == _DB_VERSION:
                    for entry in data.get("signatures", []):
                        sig = WinApiSignature(**entry)
                        key = self._key(sig.dll, sig.name)
                        self._signatures[key] = sig
                        self._index_sig(key, sig)
                    loaded = True
                    logger.info("Loaded %d API signatures from %s",
                                len(self._signatures), self._db_path)
            except Exception as e:
                logger.warning("Failed to load API db from %s: %s",
                               self._db_path, e)

        if not loaded:
            self._load_defaults()

    def _load_defaults(self):
        """Populate from the built-in signature list."""
        self._signatures.clear()
        self._by_dll.clear()
        self._by_category.clear()
        self._by_complexity.clear()
        for entry in _build_default_signatures():
            sig = WinApiSignature(**entry)
            key = self._key(sig.dll, sig.name)
            self._signatures[key] = sig
            self._index_sig(key, sig)
        logger.info("Loaded %d built-in API signatures", len(self._signatures))

    def save(self):
        """Persist current state to disk."""
        try:
            os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
            data = {
                "version": _DB_VERSION,
                "signatures": [sig.to_dict() for sig in self._signatures.values()],
            }
            with open(self._db_path, "w") as f:
                json.dump(data, f, indent=2)
            logger.info("Saved %d API signatures to %s",
                        len(self._signatures), self._db_path)
        except OSError as e:
            logger.error("Failed to save API db: %s", e)

    # -- Query API -------------------------------------------------------

    def lookup(self, dll: str, func: str) -> Optional[WinApiSignature]:
        """Look up a specific function by DLL and name."""
        return self._signatures.get(self._key(dll, func))

    def search(self, query: str) -> list[WinApiSignature]:
        """Search signatures by name, DLL, category, or notes (case-insensitive)."""
        q = query.lower()
        results = []
        for sig in self._signatures.values():
            if (q in sig.name.lower() or
                q in sig.dll.lower() or
                q in sig.category.lower() or
                q in sig.notes.lower() or
                q in sig.linux_equivalent.lower()):
                results.append(sig)
        return results

    def get_unimplemented(self, dll: str = None) -> list[WinApiSignature]:
        """Get all unimplemented APIs, optionally filtered by DLL."""
        results = []
        for sig in self._signatures.values():
            if not sig.implemented:
                if dll is None or sig.dll.lower() == dll.lower():
                    results.append(sig)
        return results

    def get_by_category(self, category: str) -> list[WinApiSignature]:
        """Get all APIs in a functional category."""
        keys = self._by_category.get(category, [])
        return [self._signatures[k] for k in keys if k in self._signatures]

    def get_by_complexity(self, complexity: str) -> list[WinApiSignature]:
        """Get all APIs of a given complexity level."""
        keys = self._by_complexity.get(complexity, [])
        return [self._signatures[k] for k in keys if k in self._signatures]

    def get_by_dll(self, dll: str) -> list[WinApiSignature]:
        """Get all APIs for a specific DLL."""
        keys = self._by_dll.get(dll.lower(), [])
        return [self._signatures[k] for k in keys if k in self._signatures]

    def mark_implemented(self, dll: str, func: str):
        """Mark a function as implemented."""
        key = self._key(dll, func)
        sig = self._signatures.get(key)
        if sig:
            sig.implemented = True

    def mark_unimplemented(self, dll: str, func: str):
        """Mark a function as not yet implemented."""
        key = self._key(dll, func)
        sig = self._signatures.get(key)
        if sig:
            sig.implemented = False

    def add_signature(self, sig: WinApiSignature):
        """Add or update a signature in the database."""
        key = self._key(sig.dll, sig.name)
        existing = self._signatures.get(key)
        if existing:
            # Remove old index entries
            dll = existing.dll.lower()
            for idx in (self._by_dll, self._by_category, self._by_complexity):
                for bucket in idx.values():
                    try:
                        bucket.remove(key)
                    except ValueError:
                        pass
        self._signatures[key] = sig
        self._index_sig(key, sig)

    def get_stats(self) -> dict:
        """Get coverage statistics."""
        total = len(self._signatures)
        implemented = sum(1 for s in self._signatures.values() if s.implemented)
        unimplemented = total - implemented

        # Per-DLL breakdown
        dll_stats = {}
        for dll, keys in sorted(self._by_dll.items()):
            sigs = [self._signatures[k] for k in keys if k in self._signatures]
            impl = sum(1 for s in sigs if s.implemented)
            dll_stats[dll] = {
                "total": len(sigs),
                "implemented": impl,
                "unimplemented": len(sigs) - impl,
                "coverage_pct": round(impl / max(len(sigs), 1) * 100, 1),
            }

        # Per-category breakdown
        cat_stats = {}
        for cat, keys in sorted(self._by_category.items()):
            sigs = [self._signatures[k] for k in keys if k in self._signatures]
            impl = sum(1 for s in sigs if s.implemented)
            cat_stats[cat] = {
                "total": len(sigs),
                "implemented": impl,
                "unimplemented": len(sigs) - impl,
                "coverage_pct": round(impl / max(len(sigs), 1) * 100, 1),
            }

        # Per-complexity breakdown
        cpx_stats = {}
        for cpx, keys in sorted(self._by_complexity.items()):
            sigs = [self._signatures[k] for k in keys if k in self._signatures]
            impl = sum(1 for s in sigs if s.implemented)
            cpx_stats[cpx] = {
                "total": len(sigs),
                "implemented": impl,
                "unimplemented": len(sigs) - impl,
            }

        return {
            "total": total,
            "implemented": implemented,
            "unimplemented": unimplemented,
            "coverage_pct": round(implemented / max(total, 1) * 100, 1),
            "by_dll": dll_stats,
            "by_category": cat_stats,
            "by_complexity": cpx_stats,
        }

    def get_all_dlls(self) -> list[str]:
        """Return list of all DLLs in the database."""
        return sorted(self._by_dll.keys())

    def get_all_categories(self) -> list[str]:
        """Return list of all categories."""
        return sorted(self._by_category.keys())

    def __len__(self) -> int:
        return len(self._signatures)

    def __contains__(self, item: tuple) -> bool:
        """Check if (dll, func) exists: `('kernel32.dll', 'CreateFileA') in db`."""
        if isinstance(item, tuple) and len(item) == 2:
            return self._key(item[0], item[1]) in self._signatures
        return False
