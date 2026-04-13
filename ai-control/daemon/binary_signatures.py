"""
Binary Signature Database -- Identifies known PE executables and provides
pre-computed dependency profiles for instant analysis.

Uses a combination of:
1. File hash (SHA-256 of first 64KB + file size) for exact match
2. Import table hash for fuzzy match (same imports = same requirements)
3. String signature for family detection ("UnrealEngine" -> UE game profile)

When a PE is loaded, instead of scanning from scratch, we check: "do we
already know this exe?"  If yes, we return its full profile instantly --
what DLLs it needs, what drivers, what anti-cheat, expected behavior,
known issues.
"""

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("ai-control.signatures")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class BinaryProfile:
    """Pre-computed profile for a known executable."""

    name: str                           # "Elden Ring"
    exe_names: list[str]                # ["eldenring.exe", "start_protected_game.exe"]
    file_hashes: list[str]              # SHA-256 hashes of known versions
    import_hash: str                    # Hash of import table (version-independent)

    # Dependencies
    required_dlls: list[str]            # ["d3d12.dll", "xinput1_4.dll", "kernel32.dll"]
    required_drivers: list[str]         # ["IOCTL_HID_*"]
    graphics_api: str                   # "d3d12", "d3d11", "vulkan", "opengl", "d3d9", "gdi", "none"

    # Features / requirements
    anti_cheat: str                     # "eac", "battleye", "vanguard", "none"
    drm: str                            # "denuvo", "steam", "epic", "gog", "none"
    net_required: bool                  # Needs internet
    controller_support: str             # "xinput", "dinput", "both", "none"

    # Known issues & workarounds
    known_issues: list[str]             # ["Needs CreateFileW for save files"]
    workarounds: list[str]              # ["Set DXVK_ASYNC=1"]
    critical_apis: list[str]            # APIs that MUST work for this exe

    # Behavioral hints
    category: str                       # "game", "installer", "tool", "service", "runtime"
    engine: str                         # "unreal", "unity", "godot", "custom", "electron", "qt", "dotnet", "java"
    estimated_compatibility: float      # 0.0-1.0 based on our stub coverage

    # Metadata
    added_date: str
    source: str                         # "community", "auto-scan", "manual", "builtin"
    version_notes: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serializable representation."""
        return {
            "name": self.name,
            "exe_names": self.exe_names,
            "file_hashes": self.file_hashes,
            "import_hash": self.import_hash,
            "required_dlls": self.required_dlls,
            "required_drivers": self.required_drivers,
            "graphics_api": self.graphics_api,
            "anti_cheat": self.anti_cheat,
            "drm": self.drm,
            "net_required": self.net_required,
            "controller_support": self.controller_support,
            "known_issues": self.known_issues,
            "workarounds": self.workarounds,
            "critical_apis": self.critical_apis,
            "category": self.category,
            "engine": self.engine,
            "estimated_compatibility": self.estimated_compatibility,
            "added_date": self.added_date,
            "source": self.source,
            "version_notes": self.version_notes,
        }

    @staticmethod
    def from_dict(d: dict) -> "BinaryProfile":
        """Reconstruct from a dict (e.g. loaded from JSON)."""
        return BinaryProfile(
            name=d["name"],
            exe_names=d.get("exe_names", []),
            file_hashes=d.get("file_hashes", []),
            import_hash=d.get("import_hash", ""),
            required_dlls=d.get("required_dlls", []),
            required_drivers=d.get("required_drivers", []),
            graphics_api=d.get("graphics_api", "none"),
            anti_cheat=d.get("anti_cheat", "none"),
            drm=d.get("drm", "none"),
            net_required=d.get("net_required", False),
            controller_support=d.get("controller_support", "none"),
            known_issues=d.get("known_issues", []),
            workarounds=d.get("workarounds", []),
            critical_apis=d.get("critical_apis", []),
            category=d.get("category", "unknown"),
            engine=d.get("engine", "custom"),
            estimated_compatibility=d.get("estimated_compatibility", 0.0),
            added_date=d.get("added_date", ""),
            source=d.get("source", "unknown"),
            version_notes=d.get("version_notes", {}),
        )


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

class BinarySignatureDB:
    """Manages the binary signature database."""

    DB_PATH = "/var/lib/ai-control/signatures"

    def __init__(self, db_path: str = ""):
        if db_path:
            self.DB_PATH = db_path
        self._profiles: dict[str, BinaryProfile] = {}
        self._hash_index: dict[str, str] = {}      # file_hash -> profile name
        self._import_index: dict[str, str] = {}     # import_hash -> profile name
        self._name_index: dict[str, str] = {}       # exe_name.lower() -> profile name
        self._string_sigs: list[tuple[bytes, str]] = []  # (needle, template_name)
        self._load_builtin_profiles()
        self._load_engine_templates()
        self._load_custom_profiles()

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _register(self, profile: BinaryProfile) -> None:
        """Register a profile and build all index entries."""
        self._profiles[profile.name] = profile
        for h in profile.file_hashes:
            self._hash_index[h] = profile.name
        if profile.import_hash:
            self._import_index[profile.import_hash] = profile.name
        for exe in profile.exe_names:
            self._name_index[exe.lower()] = profile.name

    def _get_template(self, template_name: str) -> Optional[BinaryProfile]:
        """Return a template profile by its registered name."""
        return self._profiles.get(template_name)

    # -----------------------------------------------------------------------
    # Builtin profiles -- 20+ entries for common executables
    # -----------------------------------------------------------------------

    def _load_builtin_profiles(self):
        """Built-in profiles for common games, tools, and applications."""
        builtins = [
            # ---- Common tools ----
            BinaryProfile(
                name="Notepad (Windows)",
                exe_names=["notepad.exe"],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "user32.dll", "gdi32.dll",
                    "comctl32.dll", "shell32.dll", "comdlg32.dll",
                    "msvcrt.dll", "advapi32.dll",
                ],
                required_drivers=[], graphics_api="gdi",
                anti_cheat="none", drm="none", net_required=False,
                controller_support="none",
                known_issues=[],
                workarounds=[],
                critical_apis=[
                    "CreateWindowExA", "GetMessageA", "DispatchMessageA",
                    "TextOutA", "CreateFileA", "ReadFile", "WriteFile",
                ],
                category="tool", engine="custom",
                estimated_compatibility=0.85,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="7-Zip File Manager",
                exe_names=["7zfm.exe", "7z.exe", "7zg.exe"],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "user32.dll", "gdi32.dll",
                    "shell32.dll", "ole32.dll", "oleaut32.dll",
                    "comctl32.dll", "advapi32.dll", "msvcrt.dll",
                ],
                required_drivers=[], graphics_api="gdi",
                anti_cheat="none", drm="none", net_required=False,
                controller_support="none",
                known_issues=["SHBrowseForFolder needs shell32 stub"],
                workarounds=[],
                critical_apis=[
                    "CreateFileA", "CreateFileW", "ReadFile", "WriteFile",
                    "FindFirstFileA", "FindNextFileA", "GetFileAttributesA",
                    "CreateDirectoryA", "SetFilePointer",
                ],
                category="tool", engine="custom",
                estimated_compatibility=0.70,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="WinRAR",
                exe_names=["winrar.exe", "rar.exe", "unrar.exe"],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "user32.dll", "gdi32.dll",
                    "shell32.dll", "comdlg32.dll", "comctl32.dll",
                    "advapi32.dll", "msvcrt.dll", "shlwapi.dll",
                    "ole32.dll", "version.dll",
                ],
                required_drivers=[], graphics_api="gdi",
                anti_cheat="none", drm="none", net_required=False,
                controller_support="none",
                known_issues=["Drag-and-drop requires OLE DnD stubs"],
                workarounds=[],
                critical_apis=[
                    "CreateFileW", "ReadFile", "WriteFile",
                    "FindFirstFileW", "FindNextFileW", "GetFileAttributesW",
                    "GetModuleHandleA", "LoadLibraryA",
                ],
                category="tool", engine="custom",
                estimated_compatibility=0.65,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="PuTTY",
                exe_names=["putty.exe", "plink.exe", "pscp.exe", "psftp.exe"],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "user32.dll", "gdi32.dll",
                    "ws2_32.dll", "advapi32.dll", "crypt32.dll",
                    "msvcrt.dll", "shell32.dll", "comdlg32.dll",
                ],
                required_drivers=[], graphics_api="gdi",
                anti_cheat="none", drm="none", net_required=True,
                controller_support="none",
                known_issues=["WSAStartup/socket/connect need Winsock stubs"],
                workarounds=["Use Linux native SSH instead for networking features"],
                critical_apis=[
                    "WSAStartup", "socket", "connect", "send", "recv",
                    "CreateWindowExA", "GetMessageA",
                ],
                category="tool", engine="custom",
                estimated_compatibility=0.50,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="Sysinternals Process Explorer",
                exe_names=["procexp.exe", "procexp64.exe"],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
                    "advapi32.dll", "psapi.dll", "shell32.dll", "comctl32.dll",
                    "ole32.dll", "oleaut32.dll", "version.dll", "dbghelp.dll",
                ],
                required_drivers=["IOCTL_PROCESS_*"],
                graphics_api="gdi",
                anti_cheat="none", drm="none", net_required=False,
                controller_support="none",
                known_issues=[
                    "NtQuerySystemInformation stubs needed for process enumeration",
                    "SeDebugPrivilege requires privilege escalation in trust",
                ],
                workarounds=["Map NtQuerySystemInformation to /proc parsing"],
                critical_apis=[
                    "NtQuerySystemInformation", "OpenProcess", "ReadProcessMemory",
                    "EnumProcessModules", "GetModuleFileNameExA",
                ],
                category="tool", engine="custom",
                estimated_compatibility=0.35,
                added_date="2026-04-12", source="builtin",
            ),

            # ---- D3D9 games (older titles) ----
            BinaryProfile(
                name="Generic D3D9 Game",
                exe_names=[],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "user32.dll", "gdi32.dll",
                    "d3d9.dll", "d3dx9_43.dll", "xinput1_3.dll",
                    "dinput8.dll", "dsound.dll", "winmm.dll",
                    "msvcrt.dll", "advapi32.dll", "shell32.dll",
                    "ole32.dll", "version.dll",
                ],
                required_drivers=["IOCTL_HID_*"],
                graphics_api="d3d9",
                anti_cheat="none", drm="none", net_required=False,
                controller_support="both",
                known_issues=[
                    "DXVK translates D3D9 to Vulkan",
                    "DirectInput needs evdev mapping",
                    "Window mode switching via ChangeDisplaySettings",
                ],
                workarounds=[
                    "Set DXVK_ASYNC=1 for shader compilation stutter",
                    "WINEDLLOVERRIDES='d3d9=n' to force native DXVK",
                ],
                critical_apis=[
                    "Direct3DCreate9", "CreateWindowExA",
                    "ShowWindow", "PeekMessageA",
                    "timeGetTime", "QueryPerformanceCounter",
                ],
                category="game", engine="custom",
                estimated_compatibility=0.55,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="Generic D3D11 Game",
                exe_names=[],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "user32.dll", "gdi32.dll",
                    "d3d11.dll", "dxgi.dll", "d3dcompiler_47.dll",
                    "xinput1_4.dll", "xinput9_1_0.dll",
                    "msvcrt.dll", "advapi32.dll", "shell32.dll",
                    "ole32.dll", "version.dll", "dwmapi.dll",
                    "winhttp.dll", "ws2_32.dll", "bcrypt.dll",
                ],
                required_drivers=["IOCTL_HID_*"],
                graphics_api="d3d11",
                anti_cheat="none", drm="none", net_required=False,
                controller_support="xinput",
                known_issues=[
                    "DXVK translates D3D11 to Vulkan",
                    "Fullscreen requires compositor bypass",
                    "Alt-Tab may not restore correctly",
                ],
                workarounds=[
                    "Set DXVK_ASYNC=1 for shader compilation stutter",
                    "Use gamescope for reliable fullscreen",
                ],
                critical_apis=[
                    "D3D11CreateDevice", "CreateDXGIFactory",
                    "CreateWindowExW", "ShowWindow",
                    "QueryPerformanceCounter", "QueryPerformanceFrequency",
                ],
                category="game", engine="custom",
                estimated_compatibility=0.55,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="Generic D3D12 Game",
                exe_names=[],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "user32.dll", "gdi32.dll",
                    "d3d12.dll", "dxgi.dll", "d3dcompiler_47.dll",
                    "xinput1_4.dll", "msvcrt.dll", "advapi32.dll",
                    "shell32.dll", "ole32.dll", "version.dll",
                    "dwmapi.dll", "winhttp.dll", "ws2_32.dll",
                    "bcrypt.dll", "shcore.dll",
                ],
                required_drivers=["IOCTL_HID_*"],
                graphics_api="d3d12",
                anti_cheat="none", drm="none", net_required=False,
                controller_support="xinput",
                known_issues=[
                    "VKD3D-Proton translates D3D12 to Vulkan",
                    "Shader compilation may cause heavy stutter on first run",
                    "HDR requires Wayland + HDR-capable compositor",
                ],
                workarounds=[
                    "Set VKD3D_CONFIG=dxr for raytracing titles",
                    "Use gamescope --hdr for HDR passthrough",
                    "Pre-cache shaders: fossilize-replay",
                ],
                critical_apis=[
                    "D3D12CreateDevice", "CreateDXGIFactory2",
                    "CreateWindowExW", "ShowWindow",
                    "QueryPerformanceCounter", "QueryPerformanceFrequency",
                    "WaitForSingleObject", "CreateEventA",
                ],
                category="game", engine="custom",
                estimated_compatibility=0.50,
                added_date="2026-04-12", source="builtin",
            ),

            # ---- Anti-cheat variants ----
            BinaryProfile(
                name="EAC Protected Game (D3D11)",
                exe_names=[],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
                    "d3d11.dll", "dxgi.dll", "xinput1_4.dll",
                    "msvcrt.dll", "advapi32.dll", "shell32.dll",
                    "ole32.dll", "version.dll", "psapi.dll",
                    "crypt32.dll", "winhttp.dll", "ws2_32.dll",
                    "bcrypt.dll", "iphlpapi.dll", "setupapi.dll",
                    "wer.dll",
                ],
                required_drivers=["IOCTL_HID_*", "IOCTL_STORAGE_*"],
                graphics_api="d3d11",
                anti_cheat="eac", drm="none", net_required=True,
                controller_support="xinput",
                known_issues=[
                    "EAC requires Blackshield anti-cheat shim",
                    "NtQuerySystemInformation must return convincing process list",
                    "DeviceIoControl for hardware fingerprint queries",
                    "GetAdaptersInfo must return real or fake network adapters",
                ],
                workarounds=[
                    "Enable Blackshield shim: systemctl start blackshield",
                    "Use pre-configured fake SMBIOS data for hardware queries",
                ],
                critical_apis=[
                    "NtQuerySystemInformation", "NtQueryInformationProcess",
                    "DeviceIoControl", "GetAdaptersInfo",
                    "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
                    "Module32First", "Module32Next",
                    "D3D11CreateDevice",
                ],
                category="game", engine="custom",
                estimated_compatibility=0.40,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="BattlEye Protected Game (D3D11)",
                exe_names=[],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
                    "d3d11.dll", "dxgi.dll", "xinput1_4.dll",
                    "msvcrt.dll", "advapi32.dll", "shell32.dll",
                    "ole32.dll", "version.dll", "psapi.dll",
                    "crypt32.dll", "winhttp.dll", "ws2_32.dll",
                    "bcrypt.dll", "iphlpapi.dll", "setupapi.dll",
                ],
                required_drivers=["IOCTL_HID_*", "IOCTL_STORAGE_*", "IOCTL_SCSI_*"],
                graphics_api="d3d11",
                anti_cheat="battleye", drm="none", net_required=True,
                controller_support="xinput",
                known_issues=[
                    "BattlEye requires Blackshield anti-cheat shim",
                    "BEService/BEDaisy kernel driver emulation needed",
                    "Thread enumeration and integrity checks on PE sections",
                ],
                workarounds=[
                    "Enable Blackshield shim: systemctl start blackshield",
                    "Ensure NtQueryVirtualMemory returns consistent PE layout",
                ],
                critical_apis=[
                    "NtQuerySystemInformation", "NtQueryVirtualMemory",
                    "NtQueryInformationThread", "DeviceIoControl",
                    "CreateToolhelp32Snapshot",
                    "D3D11CreateDevice",
                ],
                category="game", engine="custom",
                estimated_compatibility=0.35,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="Vanguard Protected Game (D3D11)",
                exe_names=["valorant.exe", "valorant-win64-shipping.exe"],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
                    "d3d11.dll", "dxgi.dll", "xinput1_4.dll",
                    "msvcrt.dll", "advapi32.dll", "shell32.dll",
                    "ole32.dll", "oleaut32.dll", "version.dll", "psapi.dll",
                    "crypt32.dll", "winhttp.dll", "ws2_32.dll",
                    "bcrypt.dll", "iphlpapi.dll", "setupapi.dll",
                    "secur32.dll", "wer.dll",
                ],
                required_drivers=[
                    "IOCTL_HID_*", "IOCTL_STORAGE_*",
                    "IOCTL_SMBIOS_*", "IOCTL_DISK_*",
                ],
                graphics_api="d3d11",
                anti_cheat="vanguard", drm="none", net_required=True,
                controller_support="xinput",
                known_issues=[
                    "Vanguard requires kernel-level Blackshield integration",
                    "Secure boot attestation via TPM stubs",
                    "Driver integrity checks on all loaded modules",
                    "Extremely invasive: ring-0 equivalent checks needed",
                ],
                workarounds=[
                    "Full Blackshield stack required: systemctl start blackshield-vanguard",
                    "TPM2 SMBIOS emulation must be enabled",
                ],
                critical_apis=[
                    "NtQuerySystemInformation", "NtQueryVirtualMemory",
                    "NtQueryInformationProcess", "NtQueryInformationThread",
                    "DeviceIoControl", "GetFirmwareEnvironmentVariableA",
                    "D3D11CreateDevice",
                ],
                category="game", engine="custom",
                estimated_compatibility=0.20,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="Denuvo Protected Game (D3D11)",
                exe_names=[],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
                    "d3d11.dll", "dxgi.dll", "xinput1_4.dll",
                    "msvcrt.dll", "advapi32.dll", "shell32.dll",
                    "ole32.dll", "version.dll", "bcrypt.dll",
                    "crypt32.dll", "winhttp.dll", "ws2_32.dll",
                    "iphlpapi.dll", "setupapi.dll", "wer.dll",
                ],
                required_drivers=[],
                graphics_api="d3d11",
                anti_cheat="none", drm="denuvo", net_required=True,
                controller_support="xinput",
                known_issues=[
                    "Denuvo requires online activation via winhttp",
                    "Hardware fingerprint via WMI/SMBIOS queries",
                    "Timing checks may trigger on slow emulation",
                    "Code virtualization makes static analysis difficult",
                ],
                workarounds=[
                    "Network access required for activation",
                    "Pre-cache hardware ID responses",
                ],
                critical_apis=[
                    "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
                    "BCryptOpenAlgorithmProvider", "BCryptGenRandom",
                    "GetSystemFirmwareTable",
                    "QueryPerformanceCounter",
                    "D3D11CreateDevice",
                ],
                category="game", engine="custom",
                estimated_compatibility=0.30,
                added_date="2026-04-12", source="builtin",
            ),

            # ---- Specific well-known games ----
            BinaryProfile(
                name="Elden Ring",
                exe_names=["eldenring.exe", "start_protected_game.exe"],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
                    "d3d12.dll", "dxgi.dll", "xinput1_4.dll",
                    "msvcrt.dll", "advapi32.dll", "shell32.dll",
                    "ole32.dll", "version.dll", "dwmapi.dll",
                    "winhttp.dll", "ws2_32.dll", "bcrypt.dll",
                    "shcore.dll", "setupapi.dll", "iphlpapi.dll",
                    "wer.dll",
                ],
                required_drivers=["IOCTL_HID_*"],
                graphics_api="d3d12",
                anti_cheat="eac", drm="steam", net_required=True,
                controller_support="xinput",
                known_issues=[
                    "EAC requires Blackshield shim",
                    "Save files use AppData with CreateDirectoryW",
                    "Mouse cursor hiding needs SetCursor/ClipCursor",
                    "VKD3D-Proton shader compilation stutter",
                ],
                workarounds=[
                    "VKD3D_CONFIG=dxr11 for raytracing",
                    "DXVK_ASYNC=1 for shader stutter",
                    "systemctl start blackshield for EAC",
                ],
                critical_apis=[
                    "D3D12CreateDevice", "CreateDXGIFactory2",
                    "XInputGetState", "XInputSetState",
                    "CreateFileW", "ReadFile", "WriteFile",
                    "CreateDirectoryW", "GetModuleFileNameW",
                    "QueryPerformanceCounter",
                ],
                category="game", engine="custom",
                estimated_compatibility=0.40,
                added_date="2026-04-12", source="builtin",
                version_notes={
                    "1.12": "Shadow of the Erdtree DLC - additional shader load",
                },
            ),
            BinaryProfile(
                name="Cyberpunk 2077",
                exe_names=["cyberpunk2077.exe"],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
                    "d3d12.dll", "dxgi.dll", "xinput1_4.dll",
                    "msvcrt.dll", "advapi32.dll", "shell32.dll",
                    "ole32.dll", "version.dll", "dwmapi.dll",
                    "winhttp.dll", "ws2_32.dll", "bcrypt.dll",
                    "shcore.dll", "dbghelp.dll",
                ],
                required_drivers=["IOCTL_HID_*"],
                graphics_api="d3d12",
                anti_cheat="none", drm="steam", net_required=False,
                controller_support="xinput",
                known_issues=[
                    "RED Engine uses custom memory allocator",
                    "Heavy shader compilation on first run",
                    "Ray-tracing requires VKD3D-Proton with DXR",
                    "AVX2 instruction set required",
                ],
                workarounds=[
                    "VKD3D_CONFIG=dxr11 for raytracing",
                    "Pre-cache shaders via fossilize-replay",
                ],
                critical_apis=[
                    "D3D12CreateDevice", "CreateDXGIFactory2",
                    "XInputGetState", "CreateFileW", "ReadFile",
                    "QueryPerformanceCounter", "QueryPerformanceFrequency",
                    "VirtualAlloc", "VirtualFree",
                ],
                category="game", engine="custom",
                estimated_compatibility=0.45,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="Baldur's Gate 3",
                exe_names=["bg3.exe", "bg3_dx11.exe"],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
                    "d3d11.dll", "dxgi.dll", "xinput1_4.dll",
                    "msvcrt.dll", "advapi32.dll", "shell32.dll",
                    "ole32.dll", "version.dll", "dwmapi.dll",
                    "winhttp.dll", "ws2_32.dll", "shcore.dll",
                ],
                required_drivers=["IOCTL_HID_*"],
                graphics_api="vulkan",
                anti_cheat="none", drm="steam", net_required=False,
                controller_support="xinput",
                known_issues=[
                    "Native Vulkan renderer - does not need DXVK",
                    "DX11 fallback mode does need DXVK",
                    "Large save files via CreateFileW",
                ],
                workarounds=[
                    "Use Vulkan renderer for best performance",
                    "Set --vulkan launch flag",
                ],
                critical_apis=[
                    "CreateWindowExW", "ShowWindow",
                    "XInputGetState", "CreateFileW", "ReadFile", "WriteFile",
                    "QueryPerformanceCounter",
                ],
                category="game", engine="custom",
                estimated_compatibility=0.60,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="Counter-Strike 2",
                exe_names=["cs2.exe"],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
                    "d3d11.dll", "dxgi.dll", "xinput1_4.dll",
                    "msvcrt.dll", "advapi32.dll", "shell32.dll",
                    "ole32.dll", "version.dll", "winhttp.dll",
                    "ws2_32.dll", "bcrypt.dll", "psapi.dll",
                    "steam_api64.dll", "steamclient64.dll",
                ],
                required_drivers=["IOCTL_HID_*"],
                graphics_api="d3d11",
                anti_cheat="none", drm="steam", net_required=True,
                controller_support="xinput",
                known_issues=[
                    "VAC anti-cheat (server-side, less invasive than EAC)",
                    "Steam networking required",
                    "Source 2 engine uses custom allocator",
                ],
                workarounds=[
                    "Ensure Steam client is running via SteamAPI stubs",
                ],
                critical_apis=[
                    "SteamAPI_Init", "D3D11CreateDevice",
                    "WSAStartup", "socket", "connect",
                    "QueryPerformanceCounter",
                ],
                category="game", engine="custom",
                estimated_compatibility=0.35,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="Minecraft Java Edition (Launcher)",
                exe_names=["minecraftlauncher.exe"],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "user32.dll", "gdi32.dll",
                    "shell32.dll", "advapi32.dll", "msvcrt.dll",
                    "ole32.dll", "version.dll", "winhttp.dll",
                    "ws2_32.dll",
                ],
                required_drivers=[], graphics_api="none",
                anti_cheat="none", drm="none", net_required=True,
                controller_support="none",
                known_issues=[
                    "Launcher is Electron-based",
                    "Downloads JRE and invokes javaw.exe",
                    "Main game is Java - not a PE concern",
                ],
                workarounds=[
                    "Use native Linux launcher instead for best experience",
                ],
                critical_apis=[
                    "CreateProcessA", "WinHttpOpen",
                    "CreateFileW", "ReadFile", "WriteFile",
                ],
                category="game", engine="electron",
                estimated_compatibility=0.45,
                added_date="2026-04-12", source="builtin",
            ),

            # ---- Installers / runtimes ----
            BinaryProfile(
                name="NSIS Installer",
                exe_names=[],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "user32.dll", "gdi32.dll",
                    "shell32.dll", "advapi32.dll", "comctl32.dll",
                    "ole32.dll", "msvcrt.dll", "version.dll",
                ],
                required_drivers=[], graphics_api="gdi",
                anti_cheat="none", drm="none", net_required=False,
                controller_support="none",
                known_issues=[
                    "Registry writes via RegCreateKeyExA/RegSetValueExA",
                    "Shell folder queries via SHGetFolderPathA",
                    "Service installation via CreateServiceA",
                ],
                workarounds=[
                    "Map registry writes to /var/lib/pe-compat/registry/",
                    "Map shell folders to XDG equivalents",
                ],
                critical_apis=[
                    "CreateFileA", "WriteFile", "CreateDirectoryA",
                    "RegCreateKeyExA", "RegSetValueExA",
                    "SHGetFolderPathA", "CreateWindowExA",
                    "ExtractIconA", "ShellExecuteA",
                ],
                category="installer", engine="custom",
                estimated_compatibility=0.55,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="InnoSetup Installer",
                exe_names=[],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "user32.dll", "gdi32.dll",
                    "shell32.dll", "advapi32.dll", "comctl32.dll",
                    "ole32.dll", "msvcrt.dll", "version.dll",
                    "oleaut32.dll",
                ],
                required_drivers=[], graphics_api="gdi",
                anti_cheat="none", drm="none", net_required=False,
                controller_support="none",
                known_issues=[
                    "Delphi runtime in newer versions",
                    "Registry writes for uninstall entries",
                    "Start menu shortcuts via COM IShellLink",
                ],
                workarounds=[
                    "Map registry to /var/lib/pe-compat/registry/",
                ],
                critical_apis=[
                    "CreateFileA", "WriteFile", "MoveFileA",
                    "RegCreateKeyExA", "RegSetValueExA",
                    "SHGetFolderPathA", "CreateDirectoryA",
                    "CoCreateInstance",
                ],
                category="installer", engine="custom",
                estimated_compatibility=0.50,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="MSI Installer",
                exe_names=["msiexec.exe"],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "user32.dll", "gdi32.dll",
                    "shell32.dll", "advapi32.dll", "msi.dll",
                    "ole32.dll", "oleaut32.dll", "msvcrt.dll",
                    "cabinet.dll", "version.dll",
                ],
                required_drivers=[], graphics_api="gdi",
                anti_cheat="none", drm="none", net_required=False,
                controller_support="none",
                known_issues=[
                    "Full MSI database engine not implemented",
                    "Custom actions may call arbitrary DLLs",
                    "Service installation during install phase",
                ],
                workarounds=[
                    "Extract MSI with cabextract/msitools on Linux side",
                ],
                critical_apis=[
                    "MsiOpenDatabaseA", "MsiInstallProductA",
                    "CreateFileA", "WriteFile",
                ],
                category="installer", engine="custom",
                estimated_compatibility=0.25,
                added_date="2026-04-12", source="builtin",
            ),

            # ---- Steam runtime ----
            BinaryProfile(
                name="Steam Client",
                exe_names=["steam.exe", "steamwebhelper.exe"],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
                    "shell32.dll", "advapi32.dll", "ole32.dll", "oleaut32.dll",
                    "msvcrt.dll", "version.dll", "winhttp.dll", "ws2_32.dll",
                    "crypt32.dll", "bcrypt.dll", "iphlpapi.dll",
                    "secur32.dll", "userenv.dll", "shcore.dll",
                    "imm32.dll", "dwmapi.dll",
                ],
                required_drivers=[], graphics_api="d3d11",
                anti_cheat="none", drm="steam", net_required=True,
                controller_support="xinput",
                known_issues=[
                    "Chromium Embedded Framework (CEF) for UI",
                    "steamwebhelper is a full Chromium process",
                    "Heavy COM usage for overlay",
                    "Use native Linux Steam instead",
                ],
                workarounds=[
                    "Install native Steam for Linux - no need for PE Steam",
                ],
                critical_apis=[
                    "CreateProcessA", "WinHttpOpen", "WSAStartup",
                    "CoInitializeEx", "CoCreateInstance",
                ],
                category="runtime", engine="custom",
                estimated_compatibility=0.20,
                added_date="2026-04-12", source="builtin",
            ),
        ]
        for p in builtins:
            self._register(p)

    # -----------------------------------------------------------------------
    # Engine / framework template profiles
    # -----------------------------------------------------------------------

    def _load_engine_templates(self):
        """Template profiles for detected engines/frameworks.

        These are returned by string-based family detection when no exact
        name or hash match exists.
        """
        templates = [
            BinaryProfile(
                name="unreal_game",
                exe_names=[],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
                    "d3d11.dll", "d3d12.dll", "dxgi.dll",
                    "xinput1_4.dll", "msvcrt.dll", "advapi32.dll",
                    "shell32.dll", "ole32.dll", "version.dll",
                    "winhttp.dll", "ws2_32.dll", "dbghelp.dll",
                    "dwmapi.dll", "shcore.dll", "bcrypt.dll",
                    "setupapi.dll",
                ],
                required_drivers=["IOCTL_HID_*"],
                graphics_api="d3d11",
                anti_cheat="none", drm="none", net_required=False,
                controller_support="xinput",
                known_issues=[
                    "UE uses D3D11 by default, D3D12 with -dx12 flag",
                    "Pak file system needs CreateFileW + SetFilePointer",
                    "Crash reporter phones home via winhttp",
                    "UE5 Nanite/Lumen need D3D12 + raytracing",
                ],
                workarounds=[
                    "Add -dx11 or -dx12 launch flag to control renderer",
                    "DXVK_ASYNC=1 for D3D11 path",
                    "VKD3D_CONFIG=dxr11 for D3D12/UE5 raytracing",
                ],
                critical_apis=[
                    "CreateWindowExW", "ShowWindow",
                    "PeekMessageW", "D3D11CreateDevice",
                    "CreateFileW", "ReadFile", "SetFilePointer",
                    "XInputGetState", "QueryPerformanceCounter",
                    "VirtualAlloc", "HeapCreate",
                ],
                category="game", engine="unreal",
                estimated_compatibility=0.50,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="unity_game",
                exe_names=[],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
                    "d3d11.dll", "dxgi.dll", "xinput1_4.dll",
                    "msvcrt.dll", "advapi32.dll", "shell32.dll",
                    "ole32.dll", "version.dll", "winhttp.dll",
                    "ws2_32.dll", "dwmapi.dll",
                ],
                required_drivers=["IOCTL_HID_*"],
                graphics_api="d3d11",
                anti_cheat="none", drm="none", net_required=False,
                controller_support="xinput",
                known_issues=[
                    "UnityPlayer.dll is the real engine, exe is just a launcher",
                    "Mono/.NET runtime embedded for C# scripts",
                    "Unity crash handler uses dbghelp.dll",
                    "IL2CPP builds have no managed code",
                ],
                workarounds=[
                    "Add -force-vulkan launch flag if available",
                    "DXVK handles D3D11 path automatically",
                ],
                critical_apis=[
                    "CreateWindowExW", "ShowWindow", "PeekMessageW",
                    "D3D11CreateDevice", "LoadLibraryA", "GetProcAddress",
                    "CreateFileW", "ReadFile", "XInputGetState",
                    "QueryPerformanceCounter",
                ],
                category="game", engine="unity",
                estimated_compatibility=0.55,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="godot_game",
                exe_names=[],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "user32.dll", "gdi32.dll",
                    "d3d11.dll", "dxgi.dll", "xinput1_4.dll",
                    "msvcrt.dll", "advapi32.dll", "shell32.dll",
                    "ole32.dll", "version.dll", "winmm.dll",
                    "ws2_32.dll", "dwmapi.dll",
                ],
                required_drivers=["IOCTL_HID_*"],
                graphics_api="vulkan",
                anti_cheat="none", drm="none", net_required=False,
                controller_support="xinput",
                known_issues=[
                    "Godot 4 uses Vulkan by default, D3D12 optional",
                    "Godot 3 uses OpenGL/D3D11",
                    "GDScript runtime in the exe, no external DLLs",
                ],
                workarounds=[
                    "Godot 4 Vulkan should work natively",
                    "Use --rendering-driver vulkan flag",
                ],
                critical_apis=[
                    "CreateWindowExW", "ShowWindow", "PeekMessageW",
                    "CreateFileW", "ReadFile",
                    "XInputGetState", "QueryPerformanceCounter",
                    "timeGetTime",
                ],
                category="game", engine="godot",
                estimated_compatibility=0.65,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="electron_app",
                exe_names=[],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
                    "shell32.dll", "advapi32.dll", "ole32.dll", "oleaut32.dll",
                    "msvcrt.dll", "version.dll", "winhttp.dll", "ws2_32.dll",
                    "crypt32.dll", "bcrypt.dll", "shcore.dll", "dwmapi.dll",
                    "imm32.dll", "userenv.dll", "secur32.dll",
                    "d3d11.dll", "dxgi.dll",
                ],
                required_drivers=[], graphics_api="d3d11",
                anti_cheat="none", drm="none", net_required=True,
                controller_support="none",
                known_issues=[
                    "Chromium-based: extremely heavy DLL requirements",
                    "Multi-process architecture (renderer, GPU, utility)",
                    "V8 JS engine needs VirtualAlloc JIT mapping",
                    "Sandbox uses restricted tokens/job objects",
                ],
                workarounds=[
                    "Run with --no-sandbox flag if available",
                    "Use native Linux version if one exists",
                ],
                critical_apis=[
                    "CreateProcessA", "CreateWindowExW",
                    "VirtualAlloc", "VirtualProtect",
                    "CreateFileMappingA", "MapViewOfFile",
                    "WSAStartup", "WinHttpOpen",
                    "CoInitializeEx",
                ],
                category="runtime", engine="electron",
                estimated_compatibility=0.25,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="dotnet_app",
                exe_names=[],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "ntdll.dll", "user32.dll",
                    "mscoree.dll", "msvcrt.dll", "advapi32.dll",
                    "shell32.dll", "ole32.dll", "oleaut32.dll",
                    "version.dll", "shlwapi.dll",
                ],
                required_drivers=[], graphics_api="gdi",
                anti_cheat="none", drm="none", net_required=False,
                controller_support="none",
                known_issues=[
                    "CLR bootstrap via mscoree.dll CorBindToRuntimeEx",
                    ".NET assemblies are IL bytecode, not native x86/x64",
                    "WinForms/WPF UI needs extensive GDI/user32 stubs",
                    "P/Invoke calls into native DLLs",
                ],
                workarounds=[
                    "Use Mono or .NET Core Linux runtime instead",
                    "Extract assemblies and run with dotnet CLI",
                ],
                critical_apis=[
                    "CorBindToRuntimeEx", "CLRCreateInstance",
                    "CoInitializeEx", "LoadLibraryA",
                    "GetProcAddress",
                ],
                category="runtime", engine="dotnet",
                estimated_compatibility=0.20,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="qt_app",
                exe_names=[],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "user32.dll", "gdi32.dll",
                    "shell32.dll", "advapi32.dll", "ole32.dll",
                    "oleaut32.dll", "msvcrt.dll", "version.dll",
                    "dwmapi.dll", "shcore.dll", "winmm.dll",
                    "imm32.dll", "ws2_32.dll",
                ],
                required_drivers=[], graphics_api="gdi",
                anti_cheat="none", drm="none", net_required=False,
                controller_support="none",
                known_issues=[
                    "Qt5/Qt6 DLLs (Qt5Core.dll etc.) need to be present",
                    "QPA platform plugin loading via LoadLibraryA",
                    "Clipboard via OLE or X11 backend",
                ],
                workarounds=[
                    "Use native Linux Qt build if available",
                    "Ship Qt DLLs alongside the exe",
                ],
                critical_apis=[
                    "CreateWindowExW", "ShowWindow", "GetMessageW",
                    "LoadLibraryA", "GetProcAddress",
                    "CreateFileW", "ReadFile",
                ],
                category="tool", engine="qt",
                estimated_compatibility=0.40,
                added_date="2026-04-12", source="builtin",
            ),
            BinaryProfile(
                name="java_app",
                exe_names=["javaw.exe", "java.exe"],
                file_hashes=[], import_hash="",
                required_dlls=[
                    "kernel32.dll", "user32.dll", "gdi32.dll",
                    "advapi32.dll", "msvcrt.dll", "shell32.dll",
                    "version.dll", "ws2_32.dll",
                ],
                required_drivers=[], graphics_api="gdi",
                anti_cheat="none", drm="none", net_required=False,
                controller_support="none",
                known_issues=[
                    "JVM is platform-specific native code",
                    "JNI calls LoadLibraryA for native methods",
                    "AWT/Swing uses GDI or Direct2D",
                ],
                workarounds=[
                    "Use native Linux JVM instead -- far better approach",
                    "java -jar app.jar on Linux JDK",
                ],
                critical_apis=[
                    "CreateProcessA", "LoadLibraryA", "GetProcAddress",
                    "VirtualAlloc", "VirtualProtect",
                ],
                category="runtime", engine="java",
                estimated_compatibility=0.15,
                added_date="2026-04-12", source="builtin",
            ),
        ]
        # Register templates and build string detection table
        for t in templates:
            self._register(t)

        # String signatures for family detection (needle -> template name)
        self._string_sigs = [
            (b"UnrealEngine", "unreal_game"),
            (b"UE4-", "unreal_game"),
            (b"UE5-", "unreal_game"),
            (b"Epic Games", "unreal_game"),
            (b"UnityPlayer", "unity_game"),
            (b"Unity Technologies", "unity_game"),
            (b"mono-2.0", "unity_game"),
            (b"Godot Engine", "godot_game"),
            (b"GodotProject", "godot_game"),
            (b"Electron", "electron_app"),
            (b"libcef.dll", "electron_app"),
            (b"nw.exe", "electron_app"),
            (b"libnode.dll", "electron_app"),
            (b"Qt5Core", "qt_app"),
            (b"Qt6Core", "qt_app"),
            (b"QApplication", "qt_app"),
            (b"mscoree.dll", "dotnet_app"),
            (b"CLRCreateInstance", "dotnet_app"),
            (b"_CorExeMain", "dotnet_app"),
            (b"v4.0.30319", "dotnet_app"),
            (b"jvm.dll", "java_app"),
            (b"java/lang/Object", "java_app"),
            (b"sun.java.command", "java_app"),
            # Installer detection (not templates, but useful for NSIS/Inno)
            (b"Nullsoft Install", "NSIS Installer"),
            (b"NSIS Error", "NSIS Installer"),
            (b"Inno Setup", "InnoSetup Installer"),
            (b"InnoSetupVersion", "InnoSetup Installer"),
        ]

    # -----------------------------------------------------------------------
    # Custom profiles (persisted to disk)
    # -----------------------------------------------------------------------

    def _load_custom_profiles(self):
        """Load user-contributed profiles from the signatures directory."""
        sigs_dir = Path(self.DB_PATH)
        if not sigs_dir.is_dir():
            return
        for json_file in sorted(sigs_dir.glob("*.json")):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for entry in data:
                        self._register(BinaryProfile.from_dict(entry))
                else:
                    self._register(BinaryProfile.from_dict(data))
                logger.info("Loaded custom signature file: %s", json_file.name)
            except Exception as e:
                logger.warning("Failed to load %s: %s", json_file.name, e)

    def save_profile(self, profile: BinaryProfile) -> str:
        """Persist a profile to the custom signatures directory.

        Returns the path of the saved file.
        """
        sigs_dir = Path(self.DB_PATH)
        sigs_dir.mkdir(parents=True, exist_ok=True)
        safe_name = "".join(
            c if c.isalnum() or c in "-_" else "_"
            for c in profile.name.lower()
        )
        out_path = sigs_dir / f"{safe_name}.json"
        with open(out_path, "w") as f:
            json.dump(profile.to_dict(), f, indent=2)
        logger.info("Saved profile %s to %s", profile.name, out_path)
        return str(out_path)

    # -----------------------------------------------------------------------
    # Identification pipeline
    # -----------------------------------------------------------------------

    def identify(self, exe_path: str) -> Optional[BinaryProfile]:
        """Identify an executable and return its profile.

        Resolution order:
          1. Exact exe name match (instant)
          2. File hash match (fast, reads first 64KB)
          3. Import table hash match (if available)
          4. String-based family detection (reads first 1MB)
        """
        start = time.monotonic()

        # 1. Exact name match
        basename = os.path.basename(exe_path).lower()
        if basename in self._name_index:
            name = self._name_index[basename]
            logger.info("Identified %s by name -> %s (%.1fms)",
                        basename, name, (time.monotonic() - start) * 1000)
            return self._profiles[name]

        # 2. File hash match
        file_hash = self._compute_file_hash(exe_path)
        if file_hash and file_hash in self._hash_index:
            name = self._hash_index[file_hash]
            logger.info("Identified %s by hash -> %s (%.1fms)",
                        basename, name, (time.monotonic() - start) * 1000)
            return self._profiles[name]

        # 3. Import table hash match
        import_hash = self._compute_import_hash(exe_path)
        if import_hash and import_hash in self._import_index:
            name = self._import_index[import_hash]
            logger.info("Identified %s by import hash -> %s (%.1fms)",
                        basename, name, (time.monotonic() - start) * 1000)
            return self._profiles[name]

        # 4. String-based family detection
        family = self._detect_family(exe_path)
        if family:
            logger.info("Identified %s by string sig -> %s (%.1fms)",
                        basename, family.name,
                        (time.monotonic() - start) * 1000)
            return family

        logger.info("No profile match for %s (%.1fms)",
                     basename, (time.monotonic() - start) * 1000)
        return None

    def _compute_file_hash(self, path: str) -> str:
        """Hash first 64KB + file size for fast identification."""
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                data = f.read(65536)
            return hashlib.sha256(data + str(size).encode()).hexdigest()
        except OSError:
            return ""

    def _compute_import_hash(self, path: str) -> str:
        """Compute a hash of the PE import table for version-independent matching.

        Reads the PE headers to locate the import directory, then hashes
        the sorted list of DLL names.  Falls back gracefully if the file
        is not a valid PE.
        """
        try:
            with open(path, "rb") as f:
                # Read MZ header
                mz = f.read(2)
                if mz != b"MZ":
                    return ""
                f.seek(0x3C)
                pe_off = int.from_bytes(f.read(4), "little")
                f.seek(pe_off)
                sig = f.read(4)
                if sig != b"PE\x00\x00":
                    return ""
                # COFF header
                f.read(2)  # machine
                num_sections = int.from_bytes(f.read(2), "little")
                f.read(12)  # skip timestamp, symbol table ptr, symbols
                opt_size = int.from_bytes(f.read(2), "little")
                f.read(2)  # characteristics
                opt_start = f.tell()
                magic = int.from_bytes(f.read(2), "little")
                if magic == 0x20B:  # PE32+
                    import_dir_off = opt_start + 120
                elif magic == 0x10B:  # PE32
                    import_dir_off = opt_start + 104
                else:
                    return ""
                f.seek(import_dir_off)
                import_rva = int.from_bytes(f.read(4), "little")
                import_size = int.from_bytes(f.read(4), "little")
                if import_rva == 0:
                    return ""

                # Find section containing import_rva
                f.seek(opt_start + opt_size)
                dll_names = []
                for _ in range(min(num_sections, 96)):
                    sec_name = f.read(8)
                    vsize = int.from_bytes(f.read(4), "little")
                    vrva = int.from_bytes(f.read(4), "little")
                    raw_size = int.from_bytes(f.read(4), "little")
                    raw_off = int.from_bytes(f.read(4), "little")
                    f.read(16)  # skip relocs, linenums, characteristics
                    if vrva <= import_rva < vrva + vsize:
                        # Read import descriptors
                        f.seek(raw_off + (import_rva - vrva))
                        for _ in range(256):  # cap
                            desc = f.read(20)
                            if len(desc) < 20:
                                break
                            name_rva = int.from_bytes(desc[12:16], "little")
                            if name_rva == 0:
                                break
                            # Resolve name_rva
                            if vrva <= name_rva < vrva + vsize:
                                name_off = raw_off + (name_rva - vrva)
                                pos = f.tell()
                                f.seek(name_off)
                                name_bytes = b""
                                for _ in range(256):
                                    ch = f.read(1)
                                    if not ch or ch == b"\x00":
                                        break
                                    name_bytes += ch
                                dll_names.append(name_bytes.decode("ascii", errors="replace").lower())
                                f.seek(pos)
                        break

                if dll_names:
                    dll_names.sort()
                    combined = "|".join(dll_names)
                    return hashlib.sha256(combined.encode()).hexdigest()
        except (OSError, ValueError):
            pass
        return ""

    def _detect_family(self, path: str) -> Optional[BinaryProfile]:
        """Detect the software family from strings in the binary."""
        try:
            with open(path, "rb") as f:
                data = f.read(1024 * 1024)  # First 1MB
        except OSError:
            return None

        for needle, template_name in self._string_sigs:
            if needle in data:
                return self._profiles.get(template_name)
        return None

    # -----------------------------------------------------------------------
    # Query helpers
    # -----------------------------------------------------------------------

    def get_all_profiles(self) -> list[dict]:
        """Return all registered profiles as dicts."""
        return [p.to_dict() for p in self._profiles.values()]

    def get_profile(self, name: str) -> Optional[dict]:
        """Get a specific profile by name."""
        p = self._profiles.get(name)
        return p.to_dict() if p else None

    def get_profiles_by_category(self, category: str) -> list[dict]:
        """Return profiles filtered by category."""
        return [
            p.to_dict() for p in self._profiles.values()
            if p.category == category
        ]

    def get_profiles_by_engine(self, engine: str) -> list[dict]:
        """Return profiles filtered by engine."""
        return [
            p.to_dict() for p in self._profiles.values()
            if p.engine == engine
        ]

    def get_stats(self) -> dict:
        """Return database statistics."""
        by_category: dict[str, int] = {}
        by_engine: dict[str, int] = {}
        by_anti_cheat: dict[str, int] = {}
        by_graphics: dict[str, int] = {}
        by_source: dict[str, int] = {}
        total_dlls: set[str] = set()
        total_apis: set[str] = set()

        for p in self._profiles.values():
            by_category[p.category] = by_category.get(p.category, 0) + 1
            by_engine[p.engine] = by_engine.get(p.engine, 0) + 1
            by_anti_cheat[p.anti_cheat] = by_anti_cheat.get(p.anti_cheat, 0) + 1
            by_graphics[p.graphics_api] = by_graphics.get(p.graphics_api, 0) + 1
            by_source[p.source] = by_source.get(p.source, 0) + 1
            total_dlls.update(p.required_dlls)
            total_apis.update(p.critical_apis)

        avg_compat = 0.0
        if self._profiles:
            avg_compat = sum(
                p.estimated_compatibility for p in self._profiles.values()
            ) / len(self._profiles)

        return {
            "total_profiles": len(self._profiles),
            "indexed_hashes": len(self._hash_index),
            "indexed_import_hashes": len(self._import_index),
            "indexed_exe_names": len(self._name_index),
            "string_signatures": len(self._string_sigs),
            "unique_dlls_referenced": len(total_dlls),
            "unique_critical_apis": len(total_apis),
            "average_compatibility": round(avg_compat, 3),
            "by_category": by_category,
            "by_engine": by_engine,
            "by_anti_cheat": by_anti_cheat,
            "by_graphics_api": by_graphics,
            "by_source": by_source,
        }
