"""
Syscall-to-WinAPI Translator -- Maps Linux syscalls to Windows equivalents.

This is the Rosetta Stone between what the PE process does at the Linux
level and what it thinks it's doing at the Windows level.

The PE loader runs Windows executables on Linux by translating Win32 API
calls into Linux syscalls.  When we observe those syscalls (via strace,
/proc, or the trust kernel module), this translator maps them back to the
Windows API the process *intended* to call.

Also decodes Windows IOCTL command codes into human-readable
DeviceIoControl names, using the standard (DeviceType, Function, Method,
Access) bit layout.
"""

import logging
import os
from typing import Optional

logger = logging.getLogger("ai-control.syscall_translator")


# ---------------------------------------------------------------------------
# Full Linux x86-64 syscall -> Windows API mapping
# ---------------------------------------------------------------------------
# Source: Linux x86-64 syscall numbers from <asm/unistd_64.h>
# Mapping: each entry names the closest Windows API equivalent the PE
# loader would have used to generate this syscall, plus a semantic
# category and the expected argument names.

SYSCALL_MAP: dict[int, dict] = {
    # ---- File I/O ----
    0:   {"win_api": "ReadFile",
          "category": "file_io",
          "args": ["fd", "buf", "count"],
          "note": "NtReadFile -> sys_read"},
    1:   {"win_api": "WriteFile",
          "category": "file_io",
          "args": ["fd", "buf", "count"],
          "note": "NtWriteFile -> sys_write"},
    2:   {"win_api": "CreateFileA (open)",
          "category": "file_io",
          "args": ["path", "flags", "mode"],
          "note": "NtCreateFile -> sys_open"},
    3:   {"win_api": "CloseHandle",
          "category": "file_io",
          "args": ["fd"],
          "note": "NtClose -> sys_close"},
    4:   {"win_api": "GetFileAttributes (stat)",
          "category": "file_io",
          "args": ["path", "statbuf"],
          "note": "NtQueryAttributesFile -> sys_stat"},
    5:   {"win_api": "GetFileAttributes (fstat)",
          "category": "file_io",
          "args": ["fd", "statbuf"],
          "note": "NtQueryInformationFile -> sys_fstat"},
    6:   {"win_api": "GetFileAttributes (lstat)",
          "category": "file_io",
          "args": ["path", "statbuf"],
          "note": "NtQueryAttributesFile -> sys_lstat"},
    7:   {"win_api": "DeviceIoControl (poll)",
          "category": "file_io",
          "args": ["fds", "nfds", "timeout"],
          "note": "WSAPoll -> sys_poll"},
    8:   {"win_api": "SetFilePointer",
          "category": "file_io",
          "args": ["fd", "offset", "whence"],
          "note": "NtSetInformationFile -> sys_lseek"},
    9:   {"win_api": "VirtualAlloc / MapViewOfFile",
          "category": "memory",
          "args": ["addr", "len", "prot", "flags", "fd", "offset"],
          "note": "NtMapViewOfSection / NtAllocateVirtualMemory -> sys_mmap"},
    10:  {"win_api": "VirtualProtect",
          "category": "memory",
          "args": ["addr", "len", "prot"],
          "note": "NtProtectVirtualMemory -> sys_mprotect"},
    11:  {"win_api": "VirtualFree / UnmapViewOfFile",
          "category": "memory",
          "args": ["addr", "len"],
          "note": "NtUnmapViewOfSection -> sys_munmap"},
    12:  {"win_api": "HeapAlloc (brk)",
          "category": "memory",
          "args": ["brk"],
          "note": "RtlAllocateHeap -> sys_brk"},
    13:  {"win_api": "SetConsoleCtrlHandler (rt_sigaction)",
          "category": "system",
          "args": ["sig", "act", "oact", "sigsetsize"],
          "note": "SEH / VEH -> sys_rt_sigaction"},
    14:  {"win_api": "SetConsoleCtrlHandler (rt_sigprocmask)",
          "category": "system",
          "args": ["how", "set", "oldset", "sigsetsize"],
          "note": "Signal mask -> sys_rt_sigprocmask"},
    16:  {"win_api": "DeviceIoControl",
          "category": "driver",
          "args": ["fd", "cmd", "arg"],
          "note": "NtDeviceIoControlFile -> sys_ioctl"},
    17:  {"win_api": "ReadFile (pread64)",
          "category": "file_io",
          "args": ["fd", "buf", "count", "offset"],
          "note": "NtReadFile with ByteOffset -> sys_pread64"},
    18:  {"win_api": "WriteFile (pwrite64)",
          "category": "file_io",
          "args": ["fd", "buf", "count", "offset"],
          "note": "NtWriteFile with ByteOffset -> sys_pwrite64"},
    19:  {"win_api": "ReadFileScatter (readv)",
          "category": "file_io",
          "args": ["fd", "iov", "iovcnt"],
          "note": "NtReadFile scatter -> sys_readv"},
    20:  {"win_api": "WriteFileGather (writev)",
          "category": "file_io",
          "args": ["fd", "iov", "iovcnt"],
          "note": "NtWriteFile gather -> sys_writev"},
    21:  {"win_api": "SetFileAttributes / SetCurrentDirectory (access)",
          "category": "file_io",
          "args": ["path", "mode"],
          "note": "NtQueryAttributesFile -> sys_access"},
    22:  {"win_api": "CreatePipe",
          "category": "file_io",
          "args": ["pipefd"],
          "note": "NtCreateNamedPipeFile -> sys_pipe"},
    23:  {"win_api": "WaitForMultipleObjects (select)",
          "category": "file_io",
          "args": ["nfds", "readfds", "writefds", "exceptfds", "timeout"],
          "note": "WSASelect -> sys_select"},
    32:  {"win_api": "DuplicateHandle (dup)",
          "category": "file_io",
          "args": ["oldfd"],
          "note": "NtDuplicateObject -> sys_dup"},
    33:  {"win_api": "DuplicateHandle (dup2)",
          "category": "file_io",
          "args": ["oldfd", "newfd"],
          "note": "NtDuplicateObject -> sys_dup2"},
    35:  {"win_api": "Sleep (nanosleep)",
          "category": "system",
          "args": ["req", "rem"],
          "note": "NtDelayExecution -> sys_nanosleep"},

    # ---- Network ----
    41:  {"win_api": "WSASocket / socket",
          "category": "network",
          "args": ["domain", "type", "protocol"],
          "note": "Winsock WSASocket -> sys_socket"},
    42:  {"win_api": "connect",
          "category": "network",
          "args": ["fd", "addr", "addrlen"],
          "note": "Winsock connect -> sys_connect"},
    43:  {"win_api": "accept",
          "category": "network",
          "args": ["fd", "addr", "addrlen"],
          "note": "Winsock accept -> sys_accept"},
    44:  {"win_api": "send / sendto",
          "category": "network",
          "args": ["fd", "buf", "len", "flags", "addr", "addrlen"],
          "note": "Winsock sendto -> sys_sendto"},
    45:  {"win_api": "recv / recvfrom",
          "category": "network",
          "args": ["fd", "buf", "len", "flags", "addr", "addrlen"],
          "note": "Winsock recvfrom -> sys_recvfrom"},
    46:  {"win_api": "WSASend (sendmsg)",
          "category": "network",
          "args": ["fd", "msg", "flags"],
          "note": "WSASend -> sys_sendmsg"},
    47:  {"win_api": "WSARecv (recvmsg)",
          "category": "network",
          "args": ["fd", "msg", "flags"],
          "note": "WSARecv -> sys_recvmsg"},
    48:  {"win_api": "shutdown",
          "category": "network",
          "args": ["fd", "how"],
          "note": "Winsock shutdown -> sys_shutdown"},
    49:  {"win_api": "bind",
          "category": "network",
          "args": ["fd", "addr", "addrlen"],
          "note": "Winsock bind -> sys_bind"},
    50:  {"win_api": "listen",
          "category": "network",
          "args": ["fd", "backlog"],
          "note": "Winsock listen -> sys_listen"},
    51:  {"win_api": "getsockname",
          "category": "network",
          "args": ["fd", "addr", "addrlen"],
          "note": "Winsock getsockname -> sys_getsockname"},
    52:  {"win_api": "getpeername",
          "category": "network",
          "args": ["fd", "addr", "addrlen"],
          "note": "Winsock getpeername -> sys_getpeername"},
    53:  {"win_api": "WSASocketPair (socketpair)",
          "category": "network",
          "args": ["domain", "type", "protocol", "sv"],
          "note": "No direct Win32 equivalent -> sys_socketpair"},
    54:  {"win_api": "setsockopt",
          "category": "network",
          "args": ["fd", "level", "optname", "optval", "optlen"],
          "note": "Winsock setsockopt -> sys_setsockopt"},
    55:  {"win_api": "getsockopt",
          "category": "network",
          "args": ["fd", "level", "optname", "optval", "optlen"],
          "note": "Winsock getsockopt -> sys_getsockopt"},

    # ---- Process / Thread ----
    56:  {"win_api": "CreateThread / CreateRemoteThread (clone)",
          "category": "thread",
          "args": ["flags", "stack", "parent_tid", "child_tid", "tls"],
          "note": "NtCreateThreadEx -> sys_clone"},
    57:  {"win_api": "CreateProcess (fork)",
          "category": "process",
          "args": [],
          "note": "NtCreateProcess -> sys_fork"},
    59:  {"win_api": "CreateProcess (execve)",
          "category": "process",
          "args": ["path", "argv", "envp"],
          "note": "NtCreateProcess + NtCreateThread -> sys_execve"},
    60:  {"win_api": "ExitProcess / ExitThread",
          "category": "process",
          "args": ["status"],
          "note": "NtTerminateProcess -> sys_exit"},
    61:  {"win_api": "WaitForSingleObject (wait4)",
          "category": "thread",
          "args": ["pid", "wstatus", "options", "rusage"],
          "note": "NtWaitForSingleObject -> sys_wait4"},
    62:  {"win_api": "TerminateProcess",
          "category": "process",
          "args": ["pid", "sig"],
          "note": "NtTerminateProcess -> sys_kill"},
    63:  {"win_api": "GetStdHandle (dup2 for stdin/stdout)",
          "category": "file_io",
          "args": ["oldfd", "newfd"],
          "note": "GetStdHandle -> sys_dup2 (legacy)"},

    # ---- Memory ----
    25:  {"win_api": "VirtualQuery (mremap)",
          "category": "memory",
          "args": ["old_addr", "old_size", "new_size", "flags", "new_addr"],
          "note": "NtQueryVirtualMemory + remap -> sys_mremap"},
    26:  {"win_api": "VirtualProtect (msync)",
          "category": "memory",
          "args": ["addr", "len", "flags"],
          "note": "NtFlushVirtualMemory -> sys_msync"},
    27:  {"win_api": "VirtualLock (mincore)",
          "category": "memory",
          "args": ["addr", "len", "vec"],
          "note": "VirtualQuery -> sys_mincore"},
    28:  {"win_api": "SetProcessWorkingSetSize (madvise)",
          "category": "memory",
          "args": ["addr", "len", "advice"],
          "note": "No direct Win32 equivalent -> sys_madvise"},

    # ---- Filesystem ----
    72:  {"win_api": "FlushFileBuffers (fsync)",
          "category": "file_io",
          "args": ["fd"],
          "note": "NtFlushBuffersFile -> sys_fsync"},
    73:  {"win_api": "FlushFileBuffers (fdatasync)",
          "category": "file_io",
          "args": ["fd"],
          "note": "NtFlushBuffersFile -> sys_fdatasync"},
    76:  {"win_api": "SetEndOfFile (truncate)",
          "category": "file_io",
          "args": ["path", "length"],
          "note": "NtSetInformationFile -> sys_truncate"},
    77:  {"win_api": "SetEndOfFile (ftruncate)",
          "category": "file_io",
          "args": ["fd", "length"],
          "note": "NtSetInformationFile -> sys_ftruncate"},
    78:  {"win_api": "GetCurrentDirectory (getcwd)",
          "category": "file_io",
          "args": ["buf", "size"],
          "note": "GetCurrentDirectoryA -> sys_getcwd"},
    79:  {"win_api": "SetCurrentDirectory (chdir)",
          "category": "file_io",
          "args": ["path"],
          "note": "SetCurrentDirectoryA -> sys_chdir"},
    80:  {"win_api": "CreateDirectory (mkdir)",
          "category": "file_io",
          "args": ["path", "mode"],
          "note": "NtCreateFile (directory) -> sys_mkdir"},
    82:  {"win_api": "MoveFile (rename)",
          "category": "file_io",
          "args": ["oldpath", "newpath"],
          "note": "NtSetInformationFile(FileRename) -> sys_rename"},
    83:  {"win_api": "RemoveDirectory (rmdir)",
          "category": "file_io",
          "args": ["path"],
          "note": "NtSetInformationFile(FileDisposition) -> sys_rmdir"},
    85:  {"win_api": "CreateHardLink (link)",
          "category": "file_io",
          "args": ["oldpath", "newpath"],
          "note": "NtSetInformationFile(FileLink) -> sys_link"},
    86:  {"win_api": "CreateSymbolicLink (symlink)",
          "category": "file_io",
          "args": ["target", "linkpath"],
          "note": "NtCreateFile (symlink) -> sys_symlink"},
    87:  {"win_api": "DeleteFile (unlink)",
          "category": "file_io",
          "args": ["path"],
          "note": "NtSetInformationFile(FileDisposition) -> sys_unlink"},
    89:  {"win_api": "GetFullPathName (readlink)",
          "category": "file_io",
          "args": ["path", "buf", "bufsiz"],
          "note": "GetFinalPathNameByHandle -> sys_readlink"},
    90:  {"win_api": "SetFileAttributes (chmod)",
          "category": "file_io",
          "args": ["path", "mode"],
          "note": "NtSetInformationFile(FileBasicInfo) -> sys_chmod"},
    91:  {"win_api": "SetFileAttributes (fchmod)",
          "category": "file_io",
          "args": ["fd", "mode"],
          "note": "NtSetInformationFile(FileBasicInfo) -> sys_fchmod"},

    # ---- Synchronization ----
    202: {"win_api": "WaitForSingleObject / WaitForMultipleObjects (futex)",
          "category": "sync",
          "args": ["uaddr", "futex_op", "val", "timeout", "uaddr2", "val3"],
          "note": "NtWaitForKeyedEvent / NtReleaseKeyedEvent -> sys_futex"},

    # ---- Time ----
    228: {"win_api": "QueryPerformanceCounter (clock_gettime)",
          "category": "system",
          "args": ["clockid", "tp"],
          "note": "QueryPerformanceCounter / GetSystemTimeAsFileTime -> sys_clock_gettime"},
    229: {"win_api": "QueryPerformanceFrequency (clock_getres)",
          "category": "system",
          "args": ["clockid", "res"],
          "note": "QueryPerformanceFrequency -> sys_clock_getres"},
    230: {"win_api": "GetTickCount64 (clock_nanosleep)",
          "category": "system",
          "args": ["clockid", "flags", "req", "rem"],
          "note": "NtDelayExecution -> sys_clock_nanosleep"},
    96:  {"win_api": "GetSystemTime (gettimeofday)",
          "category": "system",
          "args": ["tv", "tz"],
          "note": "GetSystemTimeAsFileTime -> sys_gettimeofday"},

    # ---- Process info ----
    39:  {"win_api": "GetCurrentProcessId",
          "category": "process",
          "args": [],
          "note": "GetCurrentProcessId -> sys_getpid"},
    102: {"win_api": "GetCurrentProcessId (getuid -> fake admin)",
          "category": "process",
          "args": [],
          "note": "PE processes may see uid=0 for admin -> sys_getuid"},
    104: {"win_api": "GetCurrentProcessId (getgid)",
          "category": "process",
          "args": [],
          "note": "No Win32 equivalent -> sys_getgid"},
    110: {"win_api": "GetCurrentThreadId (getppid)",
          "category": "process",
          "args": [],
          "note": "Process.ParentProcessId -> sys_getppid"},
    186: {"win_api": "GetCurrentThreadId (gettid)",
          "category": "thread",
          "args": [],
          "note": "GetCurrentThreadId -> sys_gettid"},

    # ---- Epoll (I/O completion ports) ----
    213: {"win_api": "CreateIoCompletionPort (epoll_create)",
          "category": "file_io",
          "args": ["size"],
          "note": "CreateIoCompletionPort -> sys_epoll_create"},
    232: {"win_api": "CreateIoCompletionPort (epoll_create1)",
          "category": "file_io",
          "args": ["flags"],
          "note": "CreateIoCompletionPort -> sys_epoll_create1"},
    233: {"win_api": "PostQueuedCompletionStatus (epoll_ctl)",
          "category": "file_io",
          "args": ["epfd", "op", "fd", "event"],
          "note": "IOCP association -> sys_epoll_ctl (via epoll_wait)"},
    281: {"win_api": "GetQueuedCompletionStatusEx (epoll_pwait)",
          "category": "file_io",
          "args": ["epfd", "events", "maxevents", "timeout", "sigmask"],
          "note": "GetQueuedCompletionStatusEx -> sys_epoll_pwait"},

    # ---- openat family (modern file operations) ----
    257: {"win_api": "CreateFileA/W (openat)",
          "category": "file_io",
          "args": ["dirfd", "path", "flags", "mode"],
          "note": "NtCreateFile with RootDirectory -> sys_openat"},
    258: {"win_api": "CreateDirectory (mkdirat)",
          "category": "file_io",
          "args": ["dirfd", "path", "mode"],
          "note": "NtCreateFile (directory) -> sys_mkdirat"},
    259: {"win_api": "CreateHardLink (mknodat)",
          "category": "file_io",
          "args": ["dirfd", "path", "mode", "dev"],
          "note": "No direct Win32 equivalent -> sys_mknodat"},
    260: {"win_api": "SetFileOwner (fchownat)",
          "category": "file_io",
          "args": ["dirfd", "path", "uid", "gid", "flags"],
          "note": "No Win32 equivalent -> sys_fchownat"},
    262: {"win_api": "GetFileAttributes (newfstatat)",
          "category": "file_io",
          "args": ["dirfd", "path", "statbuf", "flags"],
          "note": "NtQueryAttributesFile -> sys_newfstatat"},
    263: {"win_api": "DeleteFile (unlinkat)",
          "category": "file_io",
          "args": ["dirfd", "path", "flags"],
          "note": "NtSetInformationFile(FileDisposition) -> sys_unlinkat"},
    264: {"win_api": "MoveFile (renameat)",
          "category": "file_io",
          "args": ["olddirfd", "oldpath", "newdirfd", "newpath"],
          "note": "NtSetInformationFile(FileRename) -> sys_renameat"},
    265: {"win_api": "CreateHardLink (linkat)",
          "category": "file_io",
          "args": ["olddirfd", "oldpath", "newdirfd", "newpath", "flags"],
          "note": "NtSetInformationFile(FileLink) -> sys_linkat"},
    266: {"win_api": "CreateSymbolicLink (symlinkat)",
          "category": "file_io",
          "args": ["target", "newdirfd", "linkpath"],
          "note": "NtCreateFile (symlink) -> sys_symlinkat"},
    267: {"win_api": "GetFullPathName (readlinkat)",
          "category": "file_io",
          "args": ["dirfd", "path", "buf", "bufsiz"],
          "note": "GetFinalPathNameByHandle -> sys_readlinkat"},
    268: {"win_api": "SetFileAttributes (fchmodat)",
          "category": "file_io",
          "args": ["dirfd", "path", "mode"],
          "note": "NtSetInformationFile(FileBasicInfo) -> sys_fchmodat"},
    269: {"win_api": "GetFileAttributes (faccessat)",
          "category": "file_io",
          "args": ["dirfd", "path", "mode"],
          "note": "NtQueryAttributesFile -> sys_faccessat"},

    # ---- getdents (directory listing) ----
    217: {"win_api": "FindFirstFile / FindNextFile (getdents64)",
          "category": "file_io",
          "args": ["fd", "dirp", "count"],
          "note": "NtQueryDirectoryFile -> sys_getdents64"},

    # ---- Process creation (modern) ----
    435: {"win_api": "CreateProcess (clone3)",
          "category": "thread",
          "args": ["cl_args", "size"],
          "note": "NtCreateThreadEx -> sys_clone3"},

    # ---- Eventfd / signalfd (Win32 events) ----
    284: {"win_api": "CreateEvent (eventfd)",
          "category": "sync",
          "args": ["initval", "flags"],
          "note": "NtCreateEvent -> sys_eventfd"},
    290: {"win_api": "CreateEvent (eventfd2)",
          "category": "sync",
          "args": ["initval", "flags"],
          "note": "NtCreateEvent -> sys_eventfd2"},

    # ---- Timerfd (Win32 waitable timers) ----
    283: {"win_api": "CreateWaitableTimer (timerfd_create)",
          "category": "sync",
          "args": ["clockid", "flags"],
          "note": "NtCreateTimer -> sys_timerfd_create"},
    286: {"win_api": "SetWaitableTimer (timerfd_settime)",
          "category": "sync",
          "args": ["fd", "flags", "new_value", "old_value"],
          "note": "NtSetTimer -> sys_timerfd_settime"},
    287: {"win_api": "QueryWaitableTimer (timerfd_gettime)",
          "category": "sync",
          "args": ["fd", "curr_value"],
          "note": "NtQueryTimer -> sys_timerfd_gettime"},

    # ---- Misc system calls ----
    158: {"win_api": "SetPriorityClass / SetThreadPriority (arch_prctl)",
          "category": "system",
          "args": ["code", "addr"],
          "note": "Thread context setup (FS/GS base) -> sys_arch_prctl"},
    231: {"win_api": "ExitThread (exit_group)",
          "category": "process",
          "args": ["status"],
          "note": "NtTerminateProcess (all threads) -> sys_exit_group"},
    302: {"win_api": "NtSetInformationProcess (prlimit64)",
          "category": "system",
          "args": ["pid", "resource", "new_limit", "old_limit"],
          "note": "NtSetInformationProcess -> sys_prlimit64"},
    218: {"win_api": "FlushInstructionCache (set_tid_address)",
          "category": "thread",
          "args": ["tidptr"],
          "note": "Thread setup -> sys_set_tid_address"},
    273: {"win_api": "TlsAlloc / TlsSetValue (set_robust_list)",
          "category": "thread",
          "args": ["head", "len"],
          "note": "Robust futex list -> sys_set_robust_list"},
    274: {"win_api": "TlsGetValue (get_robust_list)",
          "category": "thread",
          "args": ["pid", "head_ptr", "len_ptr"],
          "note": "Robust futex list -> sys_get_robust_list"},
    204: {"win_api": "NtSetSystemTime (sched_getaffinity)",
          "category": "system",
          "args": ["pid", "cpusetsize", "mask"],
          "note": "GetProcessAffinityMask -> sys_sched_getaffinity"},
    203: {"win_api": "SetProcessAffinityMask (sched_setaffinity)",
          "category": "system",
          "args": ["pid", "cpusetsize", "mask"],
          "note": "SetProcessAffinityMask -> sys_sched_setaffinity"},
    24:  {"win_api": "SwitchToThread (sched_yield)",
          "category": "thread",
          "args": [],
          "note": "SwitchToThread -> sys_sched_yield"},
    318: {"win_api": "GetSystemInfo (getrandom)",
          "category": "system",
          "args": ["buf", "buflen", "flags"],
          "note": "BCryptGenRandom / RtlGenRandom -> sys_getrandom"},
    334: {"win_api": "GetFileInformationByHandle (statx)",
          "category": "file_io",
          "args": ["dirfd", "path", "flags", "mask", "statxbuf"],
          "note": "NtQueryInformationFile -> sys_statx"},
}


# ---------------------------------------------------------------------------
# Windows IOCTL code decoder
# ---------------------------------------------------------------------------
# IOCTL layout (32-bit):
#   [31..16] DeviceType  [15..14] Access  [13..2] Function  [1..0] Method
#
# Method: 0=BUFFERED, 1=IN_DIRECT, 2=OUT_DIRECT, 3=NEITHER
# Access: 0=ANY, 1=READ, 2=WRITE, 3=READ_WRITE

IOCTL_METHODS = ["BUFFERED", "IN_DIRECT", "OUT_DIRECT", "NEITHER"]
IOCTL_ACCESS = ["ANY", "READ", "WRITE", "READ_WRITE"]

IOCTL_DEVICE_TYPES: dict[int, str] = {
    0x0001: "BEEP",
    0x0002: "CD_ROM",
    0x0003: "CD_ROM_FILE_SYSTEM",
    0x0004: "CONTROLLER",
    0x0005: "DATALINK",
    0x0006: "DFS",
    0x0007: "DISK",
    0x0008: "DISK_FILE_SYSTEM",
    0x0009: "FILE_SYSTEM",
    0x000A: "INPORT_PORT",
    0x000B: "KEYBOARD",  # also HID
    0x000C: "MAILSLOT",
    0x000D: "MIDI_IN",  # also SCSI
    0x000E: "MIDI_OUT",
    0x000F: "MOUSE",
    0x0010: "MULTI_UNC_PROVIDER",
    0x0011: "NAMED_PIPE",
    0x0012: "NETWORK",
    0x0013: "NETWORK_BROWSER",
    0x0014: "NETWORK_FILE_SYSTEM",
    0x0015: "NULL",
    0x0016: "PARALLEL_PORT",
    0x0017: "PHYSICAL_NETCARD",
    0x0018: "PRINTER",
    0x0019: "SCANNER",
    0x001A: "SERIAL_MOUSE_PORT",
    0x001B: "SERIAL_PORT",
    0x001C: "SCREEN",
    0x001D: "SOUND",
    0x001E: "STREAMS",
    0x001F: "TAPE",
    0x0020: "TAPE_FILE_SYSTEM",
    0x0021: "TRANSPORT",
    0x0022: "UNKNOWN",  # also USB
    0x0024: "VIDEO",
    0x0025: "VIRTUAL_DISK",
    0x0027: "WAVE_IN",
    0x0028: "WAVE_OUT",
    0x002D: "MASS_STORAGE",  # also STORAGE
    0x0030: "SMARTCARD",
    0x0031: "ACPI",
    0x0032: "DVD",
    0x0033: "FULLSCREEN_VIDEO",
    0x0034: "DFS_FILE_SYSTEM",
    0x0035: "DFS_VOLUME",
    0x0041: "FIPS",
    0x0050: "CONSOLE",
    0x0053: "SERENUM",
    0x0056: "VOLUME",
    0x0059: "MODEM",
}

KNOWN_IOCTLS: dict[int, str] = {
    # ---- Storage ----
    0x002D0004: "IOCTL_STORAGE_QUERY_PROPERTY",
    0x002D1400: "IOCTL_STORAGE_GET_DEVICE_NUMBER",
    0x002D0C14: "IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER",
    0x002D1080: "IOCTL_STORAGE_GET_HOTPLUG_INFO",
    0x002D4800: "IOCTL_STORAGE_CHECK_VERIFY",
    0x002D0014: "IOCTL_STORAGE_GET_MEDIA_TYPES",
    0x002D0C10: "IOCTL_STORAGE_GET_MEDIA_TYPES_EX",
    0x002D5140: "IOCTL_STORAGE_EJECT_MEDIA",

    # ---- Disk ----
    0x00070000: "IOCTL_DISK_GET_DRIVE_GEOMETRY",
    0x00070048: "IOCTL_DISK_GET_PARTITION_INFO_EX",
    0x00074004: "IOCTL_DISK_GET_DRIVE_LAYOUT_EX",
    0x00070050: "IOCTL_DISK_GET_LENGTH_INFO",
    0x00070040: "IOCTL_DISK_GET_PARTITION_INFO",
    0x00074000: "IOCTL_DISK_GET_DRIVE_LAYOUT",
    0x0007C028: "IOCTL_DISK_SET_PARTITION_INFO_EX",
    0x00070024: "IOCTL_DISK_GET_DRIVE_GEOMETRY_EX",
    0x00074800: "IOCTL_DISK_VERIFY",
    0x00070060: "IOCTL_DISK_IS_WRITABLE",

    # ---- Volume ----
    0x00560000: "IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS",
    0x00560004: "IOCTL_VOLUME_IS_CLUSTERED",
    0x00560008: "IOCTL_VOLUME_GET_GPT_ATTRIBUTES",

    # ---- SCSI ----
    0x000D0004: "IOCTL_SCSI_PASS_THROUGH",
    0x000D0008: "IOCTL_SCSI_MINIPORT",
    0x000D1004: "IOCTL_SCSI_GET_INQUIRY_DATA",
    0x000D1008: "IOCTL_SCSI_GET_CAPABILITIES",
    0x000D0044: "IOCTL_SCSI_PASS_THROUGH_DIRECT",
    0x000D1010: "IOCTL_SCSI_GET_ADDRESS",

    # ---- HID ----
    0x000B0003: "IOCTL_HID_GET_PRODUCT_STRING",
    0x000B0023: "IOCTL_HID_GET_MANUFACTURER_STRING",
    0x000B0193: "IOCTL_HID_GET_INDEXED_STRING",
    0x000B0192: "IOCTL_HID_GET_FEATURE",
    0x000B0191: "IOCTL_HID_SET_FEATURE",
    0x000B0001: "IOCTL_HID_GET_COLLECTION_INFORMATION",
    0x000B0002: "IOCTL_HID_GET_COLLECTION_DESCRIPTOR",
    0x000B0152: "IOCTL_HID_GET_INPUT_REPORT",
    0x000B0155: "IOCTL_HID_SET_OUTPUT_REPORT",
    0x000B0013: "IOCTL_HID_GET_SERIALNUMBER_STRING",
    0x000B0030: "IOCTL_HID_GET_PHYSICAL_DESCRIPTOR",
    0x000B0100: "IOCTL_HID_GET_DRIVER_CONFIG",

    # ---- Serial ----
    0x001B0004: "IOCTL_SERIAL_GET_BAUD_RATE",
    0x001B0008: "IOCTL_SERIAL_GET_LINE_CONTROL",
    0x001B0010: "IOCTL_SERIAL_GET_TIMEOUTS",
    0x001B0014: "IOCTL_SERIAL_SET_BAUD_RATE",
    0x001B0018: "IOCTL_SERIAL_SET_LINE_CONTROL",
    0x001B001C: "IOCTL_SERIAL_SET_TIMEOUTS",

    # ---- USB ----
    0x00220003: "IOCTL_USB_GET_NODE_INFORMATION",
    0x00220004: "IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION",
    0x00220007: "IOCTL_USB_GET_NODE_CONNECTION_INFORMATION",
    0x00220015: "IOCTL_USB_GET_ROOT_HUB_NAME",
    0x00220020: "IOCTL_USB_GET_NODE_CONNECTION_NAME",

    # ---- Console ----
    0x00500016: "IOCTL_CONSOLE_GET_SCREEN_BUFFER_INFO",
    0x00500050: "IOCTL_CONSOLE_SET_TEXT_ATTRIBUTE",

    # ---- File System ----
    0x00090028: "FSCTL_GET_REPARSE_POINT",
    0x000900A4: "FSCTL_SET_REPARSE_POINT",
    0x000900AC: "FSCTL_DELETE_REPARSE_POINT",
    0x00090060: "FSCTL_GET_VOLUME_INFORMATION",
    0x00090064: "FSCTL_SET_SPARSE",
    0x000900C0: "FSCTL_SET_ZERO_DATA",
    0x000900D4: "FSCTL_QUERY_ALLOCATED_RANGES",

    # ---- Smartcard ----
    0x00310004: "IOCTL_SMARTCARD_POWER",
    0x00310008: "IOCTL_SMARTCARD_GET_ATTRIBUTE",
    0x0031000C: "IOCTL_SMARTCARD_SET_ATTRIBUTE",
    0x00310010: "IOCTL_SMARTCARD_CONFISCATE",
    0x00310014: "IOCTL_SMARTCARD_TRANSMIT",

    # ---- DVD / CD-ROM ----
    0x00330000: "IOCTL_DVD_START_SESSION",
    0x0033000C: "IOCTL_DVD_READ_KEY",
    0x00020014: "IOCTL_CDROM_READ_TOC",
    0x00024000: "IOCTL_CDROM_GET_CONFIGURATION",

    # ---- Network NDIS ----
    0x00120003: "IOCTL_NDIS_QUERY_GLOBAL_STATS",
    0x00170002: "IOCTL_NDISUIO_QUERY_OID_VALUE",
}


# ---------------------------------------------------------------------------
# NT Syscall -> Win32 API map  (for NtXxx calls from ntdll)
# ---------------------------------------------------------------------------
# These are the actual NT service calls that the PE loader's syscall_map.h
# defines.  They complement the Linux syscall map above.
NT_SYSCALL_MAP: dict[int, dict] = {
    0x000F: {"win_api": "NtClose",
             "category": "handle",
             "args": ["Handle"]},
    0x0055: {"win_api": "NtCreateFile",
             "category": "file_io",
             "args": ["FileHandle", "DesiredAccess", "ObjectAttributes",
                      "IoStatusBlock", "AllocationSize", "FileAttributes",
                      "ShareAccess", "CreateDisposition", "CreateOptions"]},
    0x0006: {"win_api": "NtReadFile",
             "category": "file_io",
             "args": ["FileHandle", "Event", "ApcRoutine", "ApcContext",
                      "IoStatusBlock", "Buffer", "Length", "ByteOffset", "Key"]},
    0x0008: {"win_api": "NtWriteFile",
             "category": "file_io",
             "args": ["FileHandle", "Event", "ApcRoutine", "ApcContext",
                      "IoStatusBlock", "Buffer", "Length", "ByteOffset", "Key"]},
    0x0018: {"win_api": "NtAllocateVirtualMemory",
             "category": "memory",
             "args": ["ProcessHandle", "BaseAddress", "ZeroBits",
                      "RegionSize", "AllocationType", "Protect"]},
    0x001E: {"win_api": "NtFreeVirtualMemory",
             "category": "memory",
             "args": ["ProcessHandle", "BaseAddress", "RegionSize", "FreeType"]},
    0x0050: {"win_api": "NtProtectVirtualMemory",
             "category": "memory",
             "args": ["ProcessHandle", "BaseAddress", "RegionSize",
                      "NewProtect", "OldProtect"]},
    0x0023: {"win_api": "NtQueryVirtualMemory",
             "category": "memory",
             "args": ["ProcessHandle", "BaseAddress", "InfoClass",
                      "MemoryInformation", "Length", "ResultLength"]},
    0x004B: {"win_api": "NtCreateThreadEx",
             "category": "thread",
             "args": ["ThreadHandle", "DesiredAccess", "ObjectAttributes",
                      "ProcessHandle", "StartRoutine", "Argument"]},
    0x0053: {"win_api": "NtTerminateThread",
             "category": "thread",
             "args": ["ThreadHandle", "ExitStatus"]},
    0x002C: {"win_api": "NtTerminateProcess",
             "category": "process",
             "args": ["ProcessHandle", "ExitStatus"]},
    0x0004: {"win_api": "NtWaitForSingleObject",
             "category": "sync",
             "args": ["Handle", "Alertable", "Timeout"]},
    0x000B: {"win_api": "NtWaitForMultipleObjects",
             "category": "sync",
             "args": ["Count", "Handles", "WaitType", "Alertable", "Timeout"]},
    0x000E: {"win_api": "NtSetEvent",
             "category": "sync",
             "args": ["EventHandle", "PreviousState"]},
    0x0048: {"win_api": "NtCreateEvent",
             "category": "sync",
             "args": ["EventHandle", "DesiredAccess", "ObjectAttributes",
                      "EventType", "InitialState"]},
    0x0012: {"win_api": "NtOpenKey",
             "category": "registry",
             "args": ["KeyHandle", "DesiredAccess", "ObjectAttributes"]},
    0x0016: {"win_api": "NtQueryValueKey",
             "category": "registry",
             "args": ["KeyHandle", "ValueName", "InfoClass",
                      "KeyValueInformation", "Length", "ResultLength"]},
    0x0017: {"win_api": "NtSetValueKey",
             "category": "registry",
             "args": ["KeyHandle", "ValueName", "TitleIndex",
                      "Type", "Data", "DataSize"]},
    0x0019: {"win_api": "NtQueryInformationProcess",
             "category": "process",
             "args": ["ProcessHandle", "ProcessInformationClass",
                      "ProcessInformation", "Length", "ReturnLength"]},
    0x0025: {"win_api": "NtQueryInformationThread",
             "category": "thread",
             "args": ["ThreadHandle", "ThreadInformationClass",
                      "ThreadInformation", "Length", "ReturnLength"]},
    0x0036: {"win_api": "NtQuerySystemInformation",
             "category": "system",
             "args": ["SystemInformationClass", "SystemInformation",
                      "Length", "ReturnLength"]},
    0x0034: {"win_api": "NtDelayExecution",
             "category": "system",
             "args": ["Alertable", "DelayInterval"]},
    0x004A: {"win_api": "NtCreateSection",
             "category": "memory",
             "args": ["SectionHandle", "DesiredAccess", "ObjectAttributes",
                      "MaximumSize", "SectionPageProtection",
                      "AllocationAttributes", "FileHandle"]},
    0x0028: {"win_api": "NtMapViewOfSection",
             "category": "memory",
             "args": ["SectionHandle", "ProcessHandle", "BaseAddress",
                      "ZeroBits", "CommitSize", "SectionOffset",
                      "ViewSize", "InheritDisposition", "AllocationType",
                      "Win32Protect"]},
    0x002A: {"win_api": "NtUnmapViewOfSection",
             "category": "memory",
             "args": ["ProcessHandle", "BaseAddress"]},
    0x0026: {"win_api": "NtOpenProcess",
             "category": "process",
             "args": ["ProcessHandle", "DesiredAccess",
                      "ObjectAttributes", "ClientId"]},
    0x0132: {"win_api": "NtOpenThread",
             "category": "thread",
             "args": ["ThreadHandle", "DesiredAccess",
                      "ObjectAttributes", "ClientId"]},
    0x0010: {"win_api": "NtQueryObject",
             "category": "handle",
             "args": ["Handle", "ObjectInformationClass",
                      "ObjectInformation", "Length", "ReturnLength"]},
    0x003C: {"win_api": "NtDuplicateObject",
             "category": "handle",
             "args": ["SourceProcessHandle", "SourceHandle",
                      "TargetProcessHandle", "TargetHandle",
                      "DesiredAccess", "HandleAttributes", "Options"]},
    0x0165: {"win_api": "NtCreateMutant",
             "category": "sync",
             "args": ["MutantHandle", "DesiredAccess",
                      "ObjectAttributes", "InitialOwner"]},
    0x001D: {"win_api": "NtReleaseMutant",
             "category": "sync",
             "args": ["MutantHandle", "PreviousCount"]},
}


# ---------------------------------------------------------------------------
# Path translation mappings
# ---------------------------------------------------------------------------
# PE processes run in a jail under ~/.pe-compat/drives/.
# These prefixes map Linux paths back to Windows drive letters.

_DRIVE_PREFIX = "/home/arch/.pe-compat/drives/"
_DRIVE_PREFIXES = [
    ("/home/arch/.pe-compat/drives/c/", "C:\\"),
    ("/home/arch/.pe-compat/drives/d/", "D:\\"),
    ("/home/arch/.pe-compat/drives/e/", "E:\\"),
    ("/home/arch/.pe-compat/drives/z/", "Z:\\"),
    # Generic fallback
    ("/tmp/", "C:\\Windows\\Temp\\"),
    ("/dev/null", "NUL"),
    ("/dev/zero", "\\\\.\\ZERO"),
]

# Windows special folder mappings (Linux path fragment -> Win env variable)
_SPECIAL_FOLDERS: dict[str, str] = {
    "Windows/System32": "%SystemRoot%\\System32",
    "Windows/SysWOW64": "%SystemRoot%\\SysWOW64",
    "Windows/Temp": "%TEMP%",
    "Users/arch/AppData/Local": "%LOCALAPPDATA%",
    "Users/arch/AppData/Roaming": "%APPDATA%",
    "Users/arch/Desktop": "%USERPROFILE%\\Desktop",
    "Users/arch/Documents": "%USERPROFILE%\\Documents",
    "Program Files": "%ProgramFiles%",
    "Program Files (x86)": "%ProgramFiles(x86)%",
}


class SyscallTranslator:
    """
    Translates Linux syscall numbers and arguments into Windows API
    equivalents, decodes Windows IOCTL codes, and maps Linux file paths
    to Windows paths for PE process debugging.
    """

    def translate(self, syscall_nr: int, args: Optional[list] = None) -> dict:
        """
        Translate a Linux x86-64 syscall number to its Windows API equivalent.

        Args:
            syscall_nr: Linux syscall number (from <asm/unistd_64.h>)
            args: Optional list of argument values

        Returns:
            dict with win_api, category, decoded_args, note
        """
        entry = SYSCALL_MAP.get(syscall_nr)
        if not entry:
            return {
                "syscall_nr": syscall_nr,
                "win_api": f"Unknown (syscall {syscall_nr})",
                "category": "unknown",
            }

        result = {
            "syscall_nr": syscall_nr,
            "win_api": entry["win_api"],
            "category": entry["category"],
        }
        if "note" in entry:
            result["note"] = entry["note"]

        if args and "args" in entry:
            result["decoded_args"] = {}
            for i, name in enumerate(entry["args"]):
                if i < len(args):
                    result["decoded_args"][name] = args[i]
        return result

    def translate_nt(self, nt_number: int, args: Optional[list] = None) -> dict:
        """
        Translate a Windows NT syscall number to its NtXxx name.

        These are the native system service numbers used by ntdll.dll
        (matching syscall_map.h in pe-loader/).

        Args:
            nt_number: NT system service number (e.g. 0x0055 for NtCreateFile)
            args: Optional list of argument values

        Returns:
            dict with win_api, category, decoded_args
        """
        entry = NT_SYSCALL_MAP.get(nt_number)
        if not entry:
            return {
                "nt_number": nt_number,
                "nt_hex": f"0x{nt_number:04X}",
                "win_api": f"NtUnknown (0x{nt_number:04X})",
                "category": "unknown",
            }

        result = {
            "nt_number": nt_number,
            "nt_hex": f"0x{nt_number:04X}",
            "win_api": entry["win_api"],
            "category": entry["category"],
        }

        if args and "args" in entry:
            result["decoded_args"] = {}
            for i, name in enumerate(entry["args"]):
                if i < len(args):
                    result["decoded_args"][name] = args[i]
        return result

    def decode_ioctl(self, cmd: int) -> dict:
        """
        Decode a Windows IOCTL code into its components.

        IOCTL layout (32-bit word):
            [31..16]  DeviceType
            [15..14]  RequiredAccess
            [13..2]   FunctionCode
            [1..0]    TransferType (Method)

        Args:
            cmd: 32-bit IOCTL code

        Returns:
            dict with name, code, device_type, function, method, access
        """
        cmd = cmd & 0xFFFFFFFF  # ensure 32-bit

        name = KNOWN_IOCTLS.get(cmd)
        device_type = (cmd >> 16) & 0xFFFF
        access = (cmd >> 14) & 0x3
        function = (cmd >> 2) & 0xFFF
        method = cmd & 0x3

        device_name = IOCTL_DEVICE_TYPES.get(device_type,
                                              f"UNKNOWN(0x{device_type:04X})")

        return {
            "name": name or f"IOCTL_UNKNOWN_{cmd:#010x}",
            "known": name is not None,
            "code": f"0x{cmd:08X}",
            "code_int": cmd,
            "device_type": device_type,
            "device_name": device_name,
            "function": function,
            "method": IOCTL_METHODS[method],
            "access": IOCTL_ACCESS[access],
        }

    def translate_file_path(self, linux_path: str) -> dict:
        """
        Translate a Linux path back to a Windows path for display.

        PE processes access files through a virtual drive structure:
            /home/arch/.pe-compat/drives/c/Windows/System32/ntdll.dll
            -> C:\\Windows\\System32\\ntdll.dll

        Args:
            linux_path: Linux filesystem path

        Returns:
            dict with linux_path, win_path, special_folder (if applicable)
        """
        win_path = linux_path  # fallback

        for prefix, drive in _DRIVE_PREFIXES:
            if linux_path.startswith(prefix):
                remainder = linux_path[len(prefix):]
                if drive.endswith("\\"):
                    win_path = drive + remainder.replace("/", "\\")
                else:
                    win_path = drive
                break
        else:
            # No drive match -- still convert to Windows-style
            if linux_path.startswith("/"):
                win_path = linux_path  # keep as-is for non-drive paths

        # Check for special folder match
        special = None
        for fragment, env_var in _SPECIAL_FOLDERS.items():
            if fragment in win_path.replace("\\", "/"):
                special = env_var
                break

        return {
            "linux_path": linux_path,
            "win_path": win_path,
            "special_folder": special,
        }

    def get_stats(self) -> dict:
        """Return translation table statistics."""
        linux_categories = {}
        for entry in SYSCALL_MAP.values():
            cat = entry["category"]
            linux_categories[cat] = linux_categories.get(cat, 0) + 1

        nt_categories = {}
        for entry in NT_SYSCALL_MAP.values():
            cat = entry["category"]
            nt_categories[cat] = nt_categories.get(cat, 0) + 1

        return {
            "linux_syscalls_mapped": len(SYSCALL_MAP),
            "nt_syscalls_mapped": len(NT_SYSCALL_MAP),
            "known_ioctls": len(KNOWN_IOCTLS),
            "device_types": len(IOCTL_DEVICE_TYPES),
            "linux_categories": linux_categories,
            "nt_categories": nt_categories,
            "drive_prefixes": len(_DRIVE_PREFIXES),
        }

    def search(self, query: str) -> dict:
        """
        Search the translation tables for a syscall or API name.

        Args:
            query: Search string (matches against win_api names, notes,
                   and categories; case-insensitive)

        Returns:
            dict with matching linux_syscalls, nt_syscalls, and ioctls
        """
        q = query.lower()

        linux_matches = []
        for nr, entry in SYSCALL_MAP.items():
            if (q in entry["win_api"].lower()
                    or q in entry["category"].lower()
                    or q in entry.get("note", "").lower()):
                linux_matches.append({"syscall_nr": nr, **entry})

        nt_matches = []
        for nr, entry in NT_SYSCALL_MAP.items():
            if (q in entry["win_api"].lower()
                    or q in entry["category"].lower()):
                nt_matches.append({"nt_number": nr,
                                   "nt_hex": f"0x{nr:04X}", **entry})

        ioctl_matches = []
        for code, name in KNOWN_IOCTLS.items():
            if q in name.lower():
                ioctl_matches.append({"code": f"0x{code:08X}",
                                      "code_int": code,
                                      "name": name})

        return {
            "query": query,
            "linux_syscalls": linux_matches,
            "nt_syscalls": nt_matches,
            "ioctls": ioctl_matches,
            "total_matches": (len(linux_matches) + len(nt_matches)
                              + len(ioctl_matches)),
        }
