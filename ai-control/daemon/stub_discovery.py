"""
Auto-Stub Discovery Engine

Analyzes running PE executables to discover:
1. Which Windows APIs they import and call
2. Which of those are currently unimplemented (hitting diagnostic stubs)
3. What drivers/services they expect
4. Priority ranking for what to implement next

This replaces manual reverse engineering with automated runtime analysis.
The AI can use this to understand what a program needs and suggest fixes.

Data sources:
  - /proc/PID/maps         : which .so DLL stubs are loaded
  - /proc/PID/exe          : original PE binary path
  - PE import tables       : static analysis via pe_dump / direct parsing
  - pe_event bus           : real-time PE_EVT_UNIMPLEMENTED_API events
  - /tmp/pe-loader-*.log   : stderr captures from pe_import.c diagnostics
  - journalctl             : fallback for stderr from binfmt_misc launches
"""

import asyncio
import json
import logging
import os
import re
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("ai-control.stub_discovery")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ImportEntry:
    dll_name: str           # "kernel32.dll"
    function_name: str      # "CreateFileA"
    ordinal: int = -1       # Ordinal import (-1 = by name)
    resolved: bool = True   # True if resolved to real impl, False if stub
    call_count: int = 0     # How many times the stub was called at runtime
    category: str = ""      # e.g. "file", "thread", "memory", "gdi"


@dataclass
class DllDependency:
    name: str               # "kernel32.dll"
    so_stub: str = ""       # "libpe_kernel32.so" (empty if no stub exists)
    loaded: bool = False    # True if the .so was found in /proc/PID/maps
    imports: list[ImportEntry] = field(default_factory=list)
    resolved_count: int = 0
    stub_count: int = 0
    missing_count: int = 0  # Could not resolve at all (no .so loaded)


@dataclass
class ProcessProfile:
    pid: int
    exe_path: str
    exe_name: str
    dependencies: dict[str, DllDependency] = field(default_factory=dict)
    total_imports: int = 0
    resolved_imports: int = 0
    stubbed_imports: int = 0
    missing_imports: int = 0
    scan_time: float = 0.0
    recommendations: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serializable summary."""
        return {
            "pid": self.pid,
            "exe_path": self.exe_path,
            "exe_name": self.exe_name,
            "total_imports": self.total_imports,
            "resolved_imports": self.resolved_imports,
            "stubbed_imports": self.stubbed_imports,
            "missing_imports": self.missing_imports,
            "scan_time": round(self.scan_time, 3),
            "dll_count": len(self.dependencies),
            "recommendation_count": len(self.recommendations),
            "errors": self.errors,
        }

    def to_full_dict(self) -> dict:
        """Full serializable profile including per-DLL breakdown."""
        deps = {}
        for name, dep in self.dependencies.items():
            deps[name] = {
                "so_stub": dep.so_stub,
                "loaded": dep.loaded,
                "resolved": dep.resolved_count,
                "stubbed": dep.stub_count,
                "missing": dep.missing_count,
                "imports": [
                    {
                        "function": imp.function_name,
                        "ordinal": imp.ordinal,
                        "resolved": imp.resolved,
                        "call_count": imp.call_count,
                        "category": imp.category,
                    }
                    for imp in dep.imports
                ],
            }
        return {
            **self.to_dict(),
            "dependencies": deps,
            "recommendations": self.recommendations,
        }


# ---------------------------------------------------------------------------
# Windows API categorization (for priority scoring)
# ---------------------------------------------------------------------------

_API_CATEGORIES = {
    # File I/O
    "CreateFile": "file", "ReadFile": "file", "WriteFile": "file",
    "CloseHandle": "handle", "DeleteFile": "file", "CopyFile": "file",
    "MoveFile": "file", "GetFileAttributes": "file", "FindFirstFile": "file",
    "FindNextFile": "file", "FindClose": "file", "SetFilePointer": "file",
    "GetFileSize": "file", "GetTempPath": "file", "GetTempFileName": "file",
    "CreateDirectory": "file", "RemoveDirectory": "file",
    "GetCurrentDirectory": "file", "SetCurrentDirectory": "file",
    "GetFullPathName": "file",
    # Memory
    "VirtualAlloc": "memory", "VirtualFree": "memory",
    "VirtualProtect": "memory", "VirtualQuery": "memory",
    "HeapCreate": "memory", "HeapDestroy": "memory",
    "HeapAlloc": "memory", "HeapFree": "memory", "HeapReAlloc": "memory",
    "GlobalAlloc": "memory", "GlobalFree": "memory", "GlobalLock": "memory",
    "GlobalUnlock": "memory", "LocalAlloc": "memory", "LocalFree": "memory",
    # Thread/sync
    "CreateThread": "thread", "ExitThread": "thread",
    "GetCurrentThread": "thread", "GetCurrentThreadId": "thread",
    "SuspendThread": "thread", "ResumeThread": "thread",
    "CreateMutex": "sync", "ReleaseMutex": "sync",
    "CreateEvent": "sync", "SetEvent": "sync", "ResetEvent": "sync",
    "WaitForSingleObject": "sync", "WaitForMultipleObjects": "sync",
    "CreateSemaphore": "sync", "ReleaseSemaphore": "sync",
    "InitializeCriticalSection": "sync", "EnterCriticalSection": "sync",
    "LeaveCriticalSection": "sync", "DeleteCriticalSection": "sync",
    "Sleep": "sync", "SleepEx": "sync",
    # Process
    "CreateProcess": "process", "ExitProcess": "process",
    "GetExitCodeProcess": "process", "GetCurrentProcess": "process",
    "GetCurrentProcessId": "process", "TerminateProcess": "process",
    "GetCommandLine": "process", "GetEnvironmentVariable": "process",
    "SetEnvironmentVariable": "process", "GetModuleFileName": "process",
    "GetModuleHandle": "process", "LoadLibrary": "process",
    "GetProcAddress": "process", "FreeLibrary": "process",
    # System info
    "GetSystemInfo": "sysinfo", "GetVersionEx": "sysinfo",
    "GetTickCount": "sysinfo", "GetTickCount64": "sysinfo",
    "QueryPerformanceCounter": "sysinfo", "QueryPerformanceFrequency": "sysinfo",
    "GetSystemTime": "sysinfo", "GetLocalTime": "sysinfo",
    "GetTimeZoneInformation": "sysinfo", "GetComputerName": "sysinfo",
    "GetUserName": "sysinfo", "GetSystemDirectory": "sysinfo",
    "GetWindowsDirectory": "sysinfo", "IsProcessorFeaturePresent": "sysinfo",
    # Console
    "GetStdHandle": "console", "WriteConsole": "console",
    "ReadConsole": "console", "SetConsoleMode": "console",
    "AllocConsole": "console", "FreeConsole": "console",
    "SetConsoleTitleA": "console", "SetConsoleTitleW": "console",
    # Registry
    "RegOpenKey": "registry", "RegCloseKey": "registry",
    "RegQueryValue": "registry", "RegSetValue": "registry",
    "RegCreateKey": "registry", "RegDeleteKey": "registry",
    "RegEnumKey": "registry", "RegEnumValue": "registry",
    # GUI
    "CreateWindowEx": "gui", "ShowWindow": "gui", "UpdateWindow": "gui",
    "GetMessage": "gui", "DispatchMessage": "gui", "DefWindowProc": "gui",
    "SetWindowPos": "gui", "MoveWindow": "gui", "DestroyWindow": "gui",
    "RegisterClass": "gui", "PostMessage": "gui", "SendMessage": "gui",
    "PeekMessage": "gui", "TranslateMessage": "gui", "PostQuitMessage": "gui",
    "GetDC": "gui", "ReleaseDC": "gui", "BeginPaint": "gui", "EndPaint": "gui",
    "SetTimer": "gui", "KillTimer": "gui", "MessageBox": "gui",
    "GetClientRect": "gui", "GetWindowRect": "gui",
    # GDI
    "CreateCompatibleDC": "gdi", "BitBlt": "gdi", "StretchBlt": "gdi",
    "SelectObject": "gdi", "DeleteObject": "gdi", "DeleteDC": "gdi",
    "CreatePen": "gdi", "CreateBrush": "gdi", "CreateFont": "gdi",
    "TextOut": "gdi", "SetTextColor": "gdi", "SetBkColor": "gdi",
    "GetDeviceCaps": "gdi", "CreateDIBSection": "gdi",
    # Networking
    "WSAStartup": "network", "WSACleanup": "network",
    "socket": "network", "bind": "network", "listen": "network",
    "accept": "network", "connect": "network", "send": "network",
    "recv": "network", "closesocket": "network", "select": "network",
    "getaddrinfo": "network", "freeaddrinfo": "network",
    "gethostbyname": "network", "inet_ntoa": "network",
    # COM
    "CoInitialize": "com", "CoInitializeEx": "com",
    "CoUninitialize": "com", "CoCreateInstance": "com",
    "CoGetClassObject": "com", "OleInitialize": "com",
    # D3D / Graphics
    "Direct3DCreate9": "d3d", "D3D11CreateDevice": "d3d",
    "CreateDXGIFactory": "d3d", "D3DCompile": "d3d",
    "D3D12CreateDevice": "d3d",
    # Audio
    "DirectSoundCreate": "audio", "waveOutOpen": "audio",
    "PlaySound": "audio",
    # Input
    "DirectInput8Create": "input", "XInputGetState": "input",
    "XInputSetState": "input", "GetKeyboardState": "input",
    "GetAsyncKeyState": "input", "GetCursorPos": "input",
}

# Functions that are commonly needed first -- prioritize these
_HIGH_PRIORITY_APIS = {
    "kernel32.dll": {
        "GetSystemInfo", "GlobalAlloc", "GlobalFree", "GlobalLock",
        "CreateEventA", "CreateEventW", "SetEvent", "ResetEvent",
        "WaitForSingleObject", "WaitForMultipleObjects",
        "CreateThread", "CreateFileA", "CreateFileW",
        "ReadFile", "WriteFile", "CloseHandle",
        "VirtualAlloc", "VirtualFree", "VirtualProtect",
        "GetModuleHandleA", "GetModuleHandleW",
        "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
        "GetLastError", "SetLastError",
        "InitializeCriticalSection", "EnterCriticalSection",
        "LeaveCriticalSection", "DeleteCriticalSection",
        "QueryPerformanceCounter", "QueryPerformanceFrequency",
        "GetTickCount64", "Sleep",
    },
    "user32.dll": {
        "CreateWindowExA", "CreateWindowExW",
        "ShowWindow", "UpdateWindow",
        "GetMessageA", "GetMessageW",
        "DispatchMessageA", "DispatchMessageW",
        "DefWindowProcA", "DefWindowProcW",
        "SetWindowPos", "RegisterClassExA", "RegisterClassExW",
        "MessageBoxA", "MessageBoxW",
        "GetDC", "ReleaseDC",
    },
    "gdi32.dll": {
        "CreateCompatibleDC", "BitBlt", "StretchBlt",
        "SelectObject", "DeleteObject", "DeleteDC",
        "CreateDIBSection", "GetDeviceCaps",
    },
    "advapi32.dll": {
        "RegOpenKeyExA", "RegOpenKeyExW",
        "RegQueryValueExA", "RegQueryValueExW",
        "RegCloseKey", "RegSetValueExA", "RegSetValueExW",
    },
    "ws2_32.dll": {
        "WSAStartup", "WSACleanup", "socket", "connect",
        "send", "recv", "closesocket", "select",
        "getaddrinfo", "freeaddrinfo",
    },
}


# ---------------------------------------------------------------------------
# DLL mapping table (mirrors pe_import.c g_dll_mappings)
# ---------------------------------------------------------------------------

# Map: windows DLL name -> .so stub name
_DLL_TO_SO: dict[str, str] = {
    "kernel32.dll": "libpe_kernel32.so",
    "ntdll.dll": "libpe_ntdll.so",
    "user32.dll": "libpe_user32.so",
    "gdi32.dll": "libpe_gdi32.so",
    "advapi32.dll": "libpe_advapi32.so",
    "ws2_32.dll": "libpe_ws2_32.so",
    "wsock32.dll": "libpe_ws2_32.so",
    "msvcrt.dll": "libpe_msvcrt.so",
    "ole32.dll": "libpe_ole32.so",
    "shell32.dll": "libpe_shell32.so",
    "ucrtbase.dll": "libpe_msvcrt.so",
    "vcruntime140.dll": "libpe_msvcrt.so",
    "version.dll": "libpe_version.so",
    "shlwapi.dll": "libpe_shlwapi.so",
    "crypt32.dll": "libpe_crypt32.so",
    "winmm.dll": "libpe_winmm.so",
    "iphlpapi.dll": "libpe_iphlpapi.so",
    "winhttp.dll": "libpe_winhttp.so",
    "wininet.dll": "libpe_winhttp.so",
    "setupapi.dll": "libpe_setupapi.so",
    "imm32.dll": "libpe_imm32.so",
    "comctl32.dll": "libpe_comctl32.so",
    "d3d9.dll": "libpe_d3d.so",
    "d3d11.dll": "libpe_d3d.so",
    "dxgi.dll": "libpe_d3d.so",
    "ddraw.dll": "libpe_d3d.so",
    "xinput1_3.dll": "libpe_d3d.so",
    "xinput1_4.dll": "libpe_d3d.so",
    "xinput9_1_0.dll": "libpe_d3d.so",
    "ntoskrnl.exe": "libpe_ntoskrnl.so",
    "hal.dll": "libpe_hal.so",
    "ndis.sys": "libpe_ndis.so",
    "oleaut32.dll": "libpe_oleaut32.so",
    "bcrypt.dll": "libpe_bcrypt.so",
    "psapi.dll": "libpe_psapi.so",
    "dbghelp.dll": "libpe_dbghelp.so",
    "userenv.dll": "libpe_userenv.so",
    "secur32.dll": "libpe_secur32.so",
    "dsound.dll": "libpe_dsound.so",
    "d3dcompiler_47.dll": "libpe_d3d.so",
    "d3d12.dll": "libpe_d3d.so",
    "mswsock.dll": "libpe_ws2_32.so",
    "wintrust.dll": "libpe_crypt32.so",
    "dwrite.dll": "libpe_gdi32.so",
    "d2d1.dll": "libpe_gdi32.so",
    "dwmapi.dll": "libpe_dwmapi.so",
    "opengl32.dll": "libpe_gdi32.so",
    "vulkan-1.dll": "libpe_d3d.so",
    "kernelbase.dll": "libpe_kernel32.so",
    "uxtheme.dll": "libpe_user32.so",
    "shcore.dll": "libpe_shcore.so",
    "comdlg32.dll": "libpe_comdlg32.so",
    "combase.dll": "libpe_combase.so",
    "dinput8.dll": "libpe_d3d.so",
    "steam_api64.dll": "libpe_steamclient.so",
}

# Reverse map: .so name -> canonical windows DLL
_SO_TO_DLL: dict[str, str] = {}
for _dll, _so in _DLL_TO_SO.items():
    if _so not in _SO_TO_DLL:
        _SO_TO_DLL[_so] = _dll


def _categorize_api(func_name: str) -> str:
    """Categorize a Windows API function by its base name (strip A/W suffix)."""
    base = func_name.rstrip("AW") if len(func_name) > 2 else func_name
    cat = _API_CATEGORIES.get(func_name) or _API_CATEGORIES.get(base)
    if cat:
        return cat
    # Heuristic categorization
    fn = func_name.lower()
    if "file" in fn or "path" in fn or "directory" in fn:
        return "file"
    if "thread" in fn:
        return "thread"
    if "heap" in fn or "virtual" in fn or "alloc" in fn:
        return "memory"
    if "window" in fn or "wnd" in fn or "message" in fn or "dialog" in fn:
        return "gui"
    if "reg" in fn and ("key" in fn or "value" in fn):
        return "registry"
    if "crypt" in fn or "hash" in fn or "cert" in fn:
        return "crypto"
    if "socket" in fn or "wsa" in fn or "net" in fn:
        return "network"
    if "d3d" in fn or "dx" in fn or "direct" in fn:
        return "d3d"
    if "console" in fn:
        return "console"
    return "misc"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class StubDiscoveryEngine:
    """Discovers unimplemented Windows API stubs via runtime + static analysis."""

    # Maximum number of cached profiles / event-stub entries (prevents OOM
    # when many PE processes are launched and never cleaned up).
    MAX_CACHED_PROFILES = 512

    def __init__(self):
        self._profiles: dict[int, ProcessProfile] = {}
        # Track all stub hits observed via the event bus (PID -> {dll!func -> count})
        self._event_stubs: dict[int, dict[str, int]] = {}

    # ------------------------------------------------------------------
    # Event bus integration
    # ------------------------------------------------------------------

    def on_unimplemented_event(self, event) -> None:
        """Handler for PE_EVT_UNIMPLEMENTED_API events from the cortex event bus.

        Register this with:
            event_bus.on(SourceLayer.RUNTIME, PeEventType.UNIMPLEMENTED_API,
                         engine.on_unimplemented_event)
        """
        pid = event.pid
        payload = event.payload if isinstance(event.payload, dict) else {}
        dll = payload.get("dll_name", "?")
        func = payload.get("func_name", "?")
        key = f"{dll}!{func}"

        if pid not in self._event_stubs:
            # Cap total tracked PIDs in event_stubs to prevent unbounded growth
            if len(self._event_stubs) >= self.MAX_CACHED_PROFILES:
                self._evict_stale_entries()
            self._event_stubs[pid] = {}
        self._event_stubs[pid][key] = self._event_stubs[pid].get(key, 0) + 1

    def on_pe_load_event(self, event) -> None:
        """Handler for PE_EVT_LOAD events -- triggers auto-analysis."""
        pid = event.pid
        payload = event.payload if isinstance(event.payload, dict) else {}
        exe_path = payload.get("exe_path", "")
        if exe_path:
            logger.info("PE loaded (pid=%d): %s -- queuing analysis", pid, exe_path)

    def _evict_stale_entries(self) -> None:
        """Evict stale profiles and event-stub entries for dead processes.

        Called after every analyze_process() to keep memory bounded.
        Removes entries for PIDs that no longer exist and, if still over
        the cap, evicts the oldest entries by scan_time.
        """
        import os as _os

        # Remove entries for dead processes
        dead_pids = [
            pid for pid in self._profiles
            if not _os.path.exists(f"/proc/{pid}") and pid != 0
        ]
        for pid in dead_pids:
            del self._profiles[pid]
            self._event_stubs.pop(pid, None)

        # If still over cap, evict oldest profiles
        if len(self._profiles) > self.MAX_CACHED_PROFILES:
            by_age = sorted(
                self._profiles.items(),
                key=lambda kv: kv[1].scan_time,
            )
            to_remove = len(self._profiles) - self.MAX_CACHED_PROFILES
            for pid, _ in by_age[:to_remove]:
                del self._profiles[pid]
                self._event_stubs.pop(pid, None)

        # Also prune event_stubs for PIDs that no longer have profiles
        stale_event_pids = [
            pid for pid in self._event_stubs
            if pid not in self._profiles and not _os.path.exists(f"/proc/{pid}")
        ]
        for pid in stale_event_pids:
            del self._event_stubs[pid]

    # ------------------------------------------------------------------
    # Analysis: full profile for a running PE process
    # ------------------------------------------------------------------

    async def analyze_process(self, pid: int) -> ProcessProfile:
        """Full analysis of a PE process's imports and stub status."""
        t0 = time.monotonic()
        profile = ProcessProfile(
            pid=pid,
            exe_path=self._get_exe_path(pid),
            exe_name="",
            scan_time=time.time(),
        )
        profile.exe_name = os.path.basename(profile.exe_path)

        # 1. Read /proc/PID/maps to find loaded DLL .so stubs
        loaded_dlls = self._get_loaded_dlls(pid)

        # 2. Parse stderr/log for stub call messages from pe_import.c
        stub_calls = await self._parse_stub_log(pid)

        # 3. Merge in event bus data (live PE_EVT_UNIMPLEMENTED_API events)
        event_stubs = self._event_stubs.get(pid, {})
        for key, count in event_stubs.items():
            stub_calls[key] = stub_calls.get(key, 0) + count

        # 4. Try static analysis of the PE binary's import table
        pe_imports = await self._read_pe_imports(profile.exe_path)

        # 5. Build per-DLL dependency profiles
        # Start with DLLs discovered from static PE import table analysis
        all_dll_names = set(pe_imports.keys())
        # Also add any DLLs we saw in maps or stub logs
        for dll_name in loaded_dlls:
            all_dll_names.add(dll_name)
        for key in stub_calls:
            dll_name = key.split("!", 1)[0] if "!" in key else key
            all_dll_names.add(dll_name.lower())

        for dll_name in sorted(all_dll_names):
            dll_lower = dll_name.lower()
            dep = DllDependency(
                name=dll_lower,
                so_stub=_DLL_TO_SO.get(dll_lower, ""),
                loaded=dll_lower in loaded_dlls,
            )

            # Collect function names from static analysis
            func_names = set()
            for imp in pe_imports.get(dll_lower, []):
                func_names.add(imp.get("name", ""))

            # Also add functions seen in stub logs for this DLL
            for key, count in stub_calls.items():
                parts = key.split("!", 1)
                if len(parts) == 2 and parts[0].lower() == dll_lower:
                    func_names.add(parts[1])

            for func_name in sorted(func_names):
                if not func_name or func_name.startswith("?"):
                    continue
                entry = ImportEntry(
                    dll_name=dll_lower,
                    function_name=func_name,
                    category=_categorize_api(func_name),
                )
                stub_key = f"{dll_lower}!{func_name}"
                if stub_key in stub_calls:
                    entry.resolved = False
                    entry.call_count = stub_calls[stub_key]
                    dep.stub_count += 1
                elif not dep.loaded and not dep.so_stub:
                    # DLL has no .so stub at all -- everything is missing
                    entry.resolved = False
                    dep.missing_count += 1
                else:
                    dep.resolved_count += 1

                dep.imports.append(entry)

            if dep.imports or dep.loaded:
                profile.dependencies[dll_lower] = dep

        # 6. Aggregate counts
        profile.total_imports = sum(len(d.imports) for d in profile.dependencies.values())
        profile.resolved_imports = sum(d.resolved_count for d in profile.dependencies.values())
        profile.stubbed_imports = sum(d.stub_count for d in profile.dependencies.values())
        profile.missing_imports = sum(d.missing_count for d in profile.dependencies.values())

        # 7. Generate prioritized recommendations
        profile.recommendations = self._generate_recommendations(profile)
        profile.scan_time = round(time.monotonic() - t0, 3)

        self._profiles[pid] = profile
        self._evict_stale_entries()
        return profile

    # ------------------------------------------------------------------
    # Static PE import table analysis
    # ------------------------------------------------------------------

    async def analyze_file(self, exe_path: str) -> ProcessProfile:
        """Analyze a PE file on disk (no running process needed).

        Performs static import table scanning to show what APIs the
        program will need.  No runtime stub-call data is available.
        """
        t0 = time.monotonic()
        profile = ProcessProfile(
            pid=0,
            exe_path=exe_path,
            exe_name=os.path.basename(exe_path),
            scan_time=time.time(),
        )

        pe_imports = await self._read_pe_imports(exe_path)
        if not pe_imports:
            profile.errors.append("Could not parse PE import table")
            return profile

        for dll_name, funcs in pe_imports.items():
            dll_lower = dll_name.lower()
            has_stub = dll_lower in _DLL_TO_SO
            dep = DllDependency(
                name=dll_lower,
                so_stub=_DLL_TO_SO.get(dll_lower, ""),
                loaded=False,
            )

            for imp in funcs:
                func_name = imp.get("name", "")
                if not func_name or func_name.startswith("?"):
                    continue
                entry = ImportEntry(
                    dll_name=dll_lower,
                    function_name=func_name,
                    ordinal=imp.get("ordinal", -1),
                    resolved=has_stub,  # Assume resolved if we have a .so stub
                    category=_categorize_api(func_name),
                )
                if has_stub:
                    dep.resolved_count += 1
                else:
                    dep.missing_count += 1
                dep.imports.append(entry)

            if dep.imports:
                profile.dependencies[dll_lower] = dep

        profile.total_imports = sum(len(d.imports) for d in profile.dependencies.values())
        profile.resolved_imports = sum(d.resolved_count for d in profile.dependencies.values())
        profile.missing_imports = sum(d.missing_count for d in profile.dependencies.values())
        profile.recommendations = self._generate_recommendations(profile)
        profile.scan_time = round(time.monotonic() - t0, 3)

        self._profiles[0] = profile
        return profile

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_exe_path(self, pid: int) -> str:
        """Read the executable path from /proc/PID/exe."""
        try:
            return os.readlink(f"/proc/{pid}/exe")
        except OSError:
            return f"<unknown:{pid}>"

    def _get_loaded_dlls(self, pid: int) -> dict[str, dict]:
        """Parse /proc/PID/maps for loaded PE DLL stub .so files."""
        dlls: dict[str, dict] = {}
        try:
            with open(f"/proc/{pid}/maps") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 6:
                        continue
                    mapped_path = parts[5].strip()
                    basename = os.path.basename(mapped_path)
                    if basename in _SO_TO_DLL:
                        dll_name = _SO_TO_DLL[basename]
                        addr_range = parts[0].split("-")
                        if dll_name not in dlls:
                            dlls[dll_name] = {
                                "so_path": mapped_path,
                                "so_name": basename,
                                "base": int(addr_range[0], 16),
                                "regions": [],
                            }
                        dlls[dll_name]["regions"].append({
                            "start": int(addr_range[0], 16),
                            "end": int(addr_range[1], 16),
                            "perms": parts[1],
                        })
        except (OSError, PermissionError) as e:
            logger.debug("Cannot read /proc/%d/maps: %s", pid, e)
        return dlls

    async def _parse_stub_log(self, pid: int) -> dict[str, int]:
        """Parse PE loader's stderr for STUB diagnostic messages.

        The PE loader outputs lines like:
            [pe_import] STUB: kernel32.dll!SomeFunc -> unimplemented (will return 0)

        We check multiple sources:
          1. /tmp/pe-stub-calls.jsonl (structured stub call log)
          2. /tmp/pe-loader-<PID>.log (explicit capture)
          3. journalctl for the PID's stderr
        """
        stub_calls: dict[str, int] = {}
        _stub_re = re.compile(r'STUB:\s+(\S+?)!(\S+)')

        # Source 1: structured JSONL stub call log (written by PE loader)
        jsonl_path = "/tmp/pe-stub-calls.jsonl"
        try:
            if os.path.exists(jsonl_path):
                with open(jsonl_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except (json.JSONDecodeError, ValueError):
                            continue
                        entry_pid = entry.get("pid", 0)
                        if entry_pid != pid:
                            continue
                        dll = entry.get("dll", "").lower()
                        func = entry.get("function", "") or entry.get("func", "")
                        if dll and func:
                            key = f"{dll}!{func}"
                            count = entry.get("count", 1)
                            stub_calls[key] = stub_calls.get(key, 0) + count
        except (OSError, PermissionError):
            pass

        # Source 2: direct log file
        log_path = f"/tmp/pe-loader-{pid}.log"
        try:
            if os.path.exists(log_path):
                with open(log_path) as f:
                    for line in f:
                        m = _stub_re.search(line)
                        if m:
                            key = f"{m.group(1).lower()}!{m.group(2)}"
                            stub_calls[key] = stub_calls.get(key, 0) + 1
        except (OSError, PermissionError):
            pass

        # Source 3: journalctl for this PID (async subprocess)
        try:
            proc = await asyncio.create_subprocess_exec(
                "journalctl", f"_PID={pid}", "--no-pager", "-o", "cat",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            for line in stdout.decode(errors="replace").splitlines():
                m = _stub_re.search(line)
                if m:
                    key = f"{m.group(1).lower()}!{m.group(2)}"
                    stub_calls[key] = stub_calls.get(key, 0) + 1
        except (FileNotFoundError, asyncio.TimeoutError, OSError):
            pass

        return stub_calls

    async def _read_pe_imports(self, exe_path: str) -> dict[str, list[dict]]:
        """Read PE import table from a file on disk.

        Uses pe_dump if available, otherwise falls back to a minimal
        Python PE parser that reads the import directory table.
        """
        imports: dict[str, list[dict]] = {}

        if not exe_path or exe_path.startswith("<"):
            return imports

        # Try pe_dump tool first (our own C tool, outputs JSON-parseable info)
        pe_dump_path = "/usr/bin/pe_dump"
        if not os.path.exists(pe_dump_path):
            pe_dump_path = "/usr/local/bin/pe_dump"

        # Fall back to our built-in minimal Python PE parser
        try:
            imports = await asyncio.get_event_loop().run_in_executor(
                None, self._parse_pe_imports_python, exe_path
            )
        except Exception as e:
            logger.debug("Python PE parser failed for %s: %s", exe_path, e)

        return imports

    def _parse_pe_imports_python(self, exe_path: str) -> dict[str, list[dict]]:
        """Minimal PE import directory parser in pure Python.

        Reads the PE optional header to find the import directory table RVA,
        then walks import descriptors to extract DLL names and function names.
        Handles both PE32 and PE32+ (64-bit) formats.
        """
        imports: dict[str, list[dict]] = {}

        try:
            with open(exe_path, "rb") as f:
                # Read MZ header
                mz = f.read(2)
                if mz != b"MZ":
                    return imports

                # PE header offset at 0x3C
                f.seek(0x3C)
                pe_offset = struct.unpack("<I", f.read(4))[0]

                # Verify PE signature
                f.seek(pe_offset)
                sig = f.read(4)
                if sig != b"PE\x00\x00":
                    return imports

                # COFF header (20 bytes)
                machine = struct.unpack("<H", f.read(2))[0]
                num_sections = struct.unpack("<H", f.read(2))[0]
                f.read(12)  # skip timestamp, symbol table ptr, symbol count
                opt_header_size = struct.unpack("<H", f.read(2))[0]
                f.read(2)  # characteristics

                if num_sections > 96:  # safety cap (matches pe_parser.c)
                    return imports

                # Optional header
                opt_start = f.tell()
                magic = struct.unpack("<H", f.read(2))[0]
                is_pe32plus = (magic == 0x20B)

                # Skip to data directories
                if is_pe32plus:
                    f.seek(opt_start + 112)  # 64-bit: import dir at offset 112
                else:
                    f.seek(opt_start + 96)   # 32-bit: import dir at offset 96

                # Read NumberOfRvaAndSizes
                f.seek(opt_start + (108 if is_pe32plus else 92))
                num_data_dirs = struct.unpack("<I", f.read(4))[0]
                if num_data_dirs < 2:
                    return imports

                # Import directory is data directory index 1
                # Each data directory entry is 8 bytes (RVA + Size)
                f.seek(opt_start + (112 if is_pe32plus else 96) + 8)  # skip export dir
                import_rva = struct.unpack("<I", f.read(4))[0]
                import_size = struct.unpack("<I", f.read(4))[0]

                if import_rva == 0:
                    return imports

                # Read section headers to build RVA -> file offset mapping
                section_header_start = opt_start + opt_header_size
                f.seek(section_header_start)
                sections = []
                for _ in range(num_sections):
                    sec_data = f.read(40)
                    if len(sec_data) < 40:
                        break
                    sec_name = sec_data[:8].rstrip(b"\x00").decode("ascii", errors="replace")
                    virtual_size = struct.unpack("<I", sec_data[8:12])[0]
                    virtual_addr = struct.unpack("<I", sec_data[12:16])[0]
                    raw_size = struct.unpack("<I", sec_data[16:20])[0]
                    raw_offset = struct.unpack("<I", sec_data[20:24])[0]
                    sections.append({
                        "name": sec_name,
                        "va": virtual_addr,
                        "vs": virtual_size,
                        "raw_offset": raw_offset,
                        "raw_size": raw_size,
                    })

                def rva_to_offset(rva: int) -> int:
                    """Convert RVA to file offset using section table."""
                    for sec in sections:
                        if sec["va"] <= rva < sec["va"] + sec["raw_size"]:
                            return rva - sec["va"] + sec["raw_offset"]
                    return -1

                # Walk import descriptors (20 bytes each)
                import_file_offset = rva_to_offset(import_rva)
                if import_file_offset < 0:
                    return imports

                max_descriptors = min(import_size // 20, 512)  # safety cap
                for desc_idx in range(max_descriptors):
                    f.seek(import_file_offset + desc_idx * 20)
                    desc = f.read(20)
                    if len(desc) < 20:
                        break

                    ilt_rva = struct.unpack("<I", desc[0:4])[0]     # OriginalFirstThunk
                    name_rva = struct.unpack("<I", desc[12:16])[0]  # Name RVA

                    # Null descriptor terminates
                    if name_rva == 0 and ilt_rva == 0:
                        break

                    # Read DLL name
                    name_offset = rva_to_offset(name_rva)
                    if name_offset < 0:
                        continue
                    f.seek(name_offset)
                    dll_name_bytes = b""
                    for _ in range(256):
                        ch = f.read(1)
                        if not ch or ch == b"\x00":
                            break
                        dll_name_bytes += ch
                    dll_name = dll_name_bytes.decode("ascii", errors="replace").lower()

                    if not dll_name:
                        continue

                    func_list = []

                    # Walk the Import Lookup Table (ILT)
                    if ilt_rva == 0:
                        # No ILT -- use IAT (FirstThunk) at desc[16:20]
                        ilt_rva = struct.unpack("<I", desc[16:20])[0]
                    if ilt_rva == 0:
                        imports[dll_name] = func_list
                        continue

                    ilt_offset = rva_to_offset(ilt_rva)
                    if ilt_offset < 0:
                        imports[dll_name] = func_list
                        continue

                    entry_size = 8 if is_pe32plus else 4
                    ordinal_flag = (1 << 63) if is_pe32plus else (1 << 31)

                    for i in range(65536):  # safety cap (matches pe_import.c)
                        f.seek(ilt_offset + i * entry_size)
                        entry_bytes = f.read(entry_size)
                        if len(entry_bytes) < entry_size:
                            break

                        if is_pe32plus:
                            entry_val = struct.unpack("<Q", entry_bytes)[0]
                        else:
                            entry_val = struct.unpack("<I", entry_bytes)[0]

                        if entry_val == 0:
                            break

                        if entry_val & ordinal_flag:
                            # Import by ordinal
                            ordinal = entry_val & 0xFFFF
                            func_list.append({
                                "name": f"Ordinal_{ordinal}",
                                "ordinal": ordinal,
                            })
                        else:
                            # Import by name -- RVA points to IMAGE_IMPORT_BY_NAME
                            hint_rva = entry_val & 0x7FFFFFFF
                            hint_offset = rva_to_offset(hint_rva)
                            if hint_offset < 0:
                                continue
                            f.seek(hint_offset)
                            hint = struct.unpack("<H", f.read(2))[0]
                            name_bytes = b""
                            for _ in range(256):
                                ch = f.read(1)
                                if not ch or ch == b"\x00":
                                    break
                                name_bytes += ch
                            func_name = name_bytes.decode("ascii", errors="replace")
                            if func_name:
                                func_list.append({
                                    "name": func_name,
                                    "ordinal": -1,
                                    "hint": hint,
                                })

                    imports[dll_name] = func_list

        except (OSError, struct.error) as e:
            logger.debug("PE import parse error for %s: %s", exe_path, e)

        return imports

    # ------------------------------------------------------------------
    # Recommendation generation
    # ------------------------------------------------------------------

    def _generate_recommendations(self, profile: ProcessProfile) -> list[dict]:
        """Generate prioritized implementation recommendations."""
        recs = []
        for dll_name, dep in profile.dependencies.items():
            for imp in dep.imports:
                if imp.resolved:
                    continue

                # Priority scoring:
                # - critical: high-priority API with call_count > 0
                # - high: any API with call_count > 10, or high-priority with call_count == 0
                # - medium: call_count > 0
                # - low: static import, no call observed yet
                priority = "low"
                is_high_priority = (
                    dll_name in _HIGH_PRIORITY_APIS
                    and imp.function_name in _HIGH_PRIORITY_APIS[dll_name]
                )

                if imp.call_count > 0:
                    priority = "medium"
                    if imp.call_count > 10:
                        priority = "high"
                    if is_high_priority:
                        priority = "critical"
                elif is_high_priority:
                    priority = "high"

                reason_parts = []
                if imp.call_count > 0:
                    reason_parts.append(f"called {imp.call_count}x at runtime")
                if not dep.so_stub:
                    reason_parts.append("no .so stub exists for this DLL")
                elif not dep.loaded:
                    reason_parts.append("DLL stub not loaded")
                else:
                    reason_parts.append("hitting diagnostic stub")
                if is_high_priority:
                    reason_parts.append("commonly needed by Windows programs")

                recs.append({
                    "dll": dll_name,
                    "function": imp.function_name,
                    "call_count": imp.call_count,
                    "priority": priority,
                    "category": imp.category,
                    "reason": "; ".join(reason_parts),
                })

        # Sort: critical > high > medium > low, then by call count desc
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        recs.sort(key=lambda r: (priority_order.get(r["priority"], 9), -r["call_count"]))
        return recs

    # ------------------------------------------------------------------
    # Public query methods (used by API routes)
    # ------------------------------------------------------------------

    def get_all_profiles(self) -> list[dict]:
        """Summary of all analyzed processes."""
        return [p.to_dict() for p in self._profiles.values()]

    def get_profile(self, pid: int) -> Optional[dict]:
        """Full profile for a specific PID."""
        p = self._profiles.get(pid)
        if p:
            return p.to_full_dict()
        return None

    def get_implementation_priority(self) -> list[dict]:
        """Cross-process priority list: what to implement next.

        Aggregates stub data from ALL analyzed processes to find
        the most impactful APIs to implement.
        """
        all_stubs: dict[str, dict] = {}
        for profile in self._profiles.values():
            for rec in profile.recommendations:
                key = f"{rec['dll']}!{rec['function']}"
                if key not in all_stubs:
                    all_stubs[key] = {
                        "dll": rec["dll"],
                        "function": rec["function"],
                        "category": rec["category"],
                        "priority": rec["priority"],
                        "call_count": 0,
                        "processes": [],
                        "reason": rec["reason"],
                    }
                existing = all_stubs[key]
                existing["call_count"] += rec["call_count"]
                if profile.exe_name and profile.exe_name not in existing["processes"]:
                    existing["processes"].append(profile.exe_name)
                # Promote priority if multiple processes need it
                priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                if priority_order.get(rec["priority"], 9) < priority_order.get(existing["priority"], 9):
                    existing["priority"] = rec["priority"]

        # Boost priority for functions needed by multiple processes
        for stub in all_stubs.values():
            if len(stub["processes"]) >= 3 and stub["priority"] == "medium":
                stub["priority"] = "high"
            if len(stub["processes"]) >= 5 and stub["priority"] == "high":
                stub["priority"] = "critical"

        result = sorted(
            all_stubs.values(),
            key=lambda r: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(r["priority"], 9),
                -len(r["processes"]),
                -r["call_count"],
            ),
        )
        return result[:100]  # Top 100 most-needed implementations

    def get_dll_coverage(self) -> list[dict]:
        """Summary of DLL stub coverage across all analyzed processes.

        Shows which DLLs have stubs, how many functions are implemented
        vs stubbed, helping the AI decide which DLL to work on next.
        """
        dll_stats: dict[str, dict] = {}
        for profile in self._profiles.values():
            for dll_name, dep in profile.dependencies.items():
                if dll_name not in dll_stats:
                    dll_stats[dll_name] = {
                        "dll": dll_name,
                        "so_stub": dep.so_stub,
                        "has_stub": bool(dep.so_stub),
                        "total_functions": 0,
                        "resolved": 0,
                        "stubbed": 0,
                        "missing": 0,
                        "processes": [],
                    }
                s = dll_stats[dll_name]
                s["total_functions"] += len(dep.imports)
                s["resolved"] += dep.resolved_count
                s["stubbed"] += dep.stub_count
                s["missing"] += dep.missing_count
                if profile.exe_name and profile.exe_name not in s["processes"]:
                    s["processes"].append(profile.exe_name)

        # Sort by most-needed (highest stub + missing count)
        result = sorted(
            dll_stats.values(),
            key=lambda d: -(d["stubbed"] + d["missing"]),
        )
        return result

    def get_category_summary(self) -> dict:
        """Summary of unimplemented APIs grouped by category.

        Helps the AI understand what functional areas are weakest
        (e.g., "file I/O is 80% covered but GUI is only 20%").
        """
        cats: dict[str, dict] = {}
        for profile in self._profiles.values():
            for dep in profile.dependencies.values():
                for imp in dep.imports:
                    cat = imp.category or "misc"
                    if cat not in cats:
                        cats[cat] = {"category": cat, "total": 0, "resolved": 0, "stubbed": 0}
                    cats[cat]["total"] += 1
                    if imp.resolved:
                        cats[cat]["resolved"] += 1
                    else:
                        cats[cat]["stubbed"] += 1

        # Add coverage percentage
        for cat in cats.values():
            total = cat["total"]
            cat["coverage_pct"] = round(100 * cat["resolved"] / total, 1) if total > 0 else 0.0

        return {
            "categories": sorted(cats.values(), key=lambda c: c["coverage_pct"]),
            "total_analyzed": len(self._profiles),
        }

    def clear_profile(self, pid: int) -> bool:
        """Remove a stored profile."""
        if pid in self._profiles:
            del self._profiles[pid]
            self._event_stubs.pop(pid, None)
            return True
        return False
