"""
Pattern Scanner - Configurable memory pattern matching engine.

Scans PE process memory regions for known signatures to:
1. Auto-detect required Windows API calls
2. Identify driver dependencies (IOCTL codes)
3. Detect anti-tamper/anti-debug patterns
4. Find calls to unimplemented stubs
5. Build behavioral fingerprints for the AI cortex
"""

import re, struct, json, logging, os
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

logger = logging.getLogger("ai-control.scanner")


@dataclass
class Pattern:
    id: str                     # "IOCTL_SCSI_PASS_THROUGH"
    bytes_hex: str              # "4C8D05????????4889CE" (? = wildcard)
    category: str               # "ioctl", "api_call", "anti_debug", "drm", "driver"
    description: str
    severity: str = "info"      # "info", "warning", "critical"
    metadata: dict = field(default_factory=dict)  # extra context


@dataclass
class ScanMatch:
    pattern_id: str
    va: int
    region_label: str
    category: str
    description: str
    context_bytes: bytes        # surrounding bytes for analysis


class PatternDatabase:
    """Manages a library of scan patterns."""

    def __init__(self, db_path: str = "/var/lib/ai-control/patterns"):
        self.patterns: dict[str, Pattern] = {}
        self._db_path = Path(db_path)
        self._load_builtin_patterns()
        self._load_custom_patterns()

    def _load_builtin_patterns(self):
        """Built-in patterns for common Windows behaviors (30+ signatures)."""
        builtins = [
            # --- IOCTL codes (detect driver requirements) ---
            Pattern("IOCTL_STORAGE_QUERY", "B8002D0400", "ioctl",
                    "StorageQueryProperty IOCTL (storage driver)"),
            Pattern("IOCTL_DISK_GET_DRIVE_GEOMETRY", "B800700004", "ioctl",
                    "Disk geometry query (disk driver)"),
            Pattern("IOCTL_SCSI_PASS_THROUGH", "B804040D00", "ioctl",
                    "SCSI passthrough (SCSI driver)"),
            Pattern("IOCTL_HID_GET_COLLECTION", "B80100320B", "ioctl",
                    "HID collection (input device driver)"),
            Pattern("IOCTL_STORAGE_GET_DEVICE_NUMBER", "B82C2D0400", "ioctl",
                    "StorageGetDeviceNumber IOCTL (volume enumeration)"),
            Pattern("IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS", "B800560070", "ioctl",
                    "Volume disk extents query (volume manager)"),

            # --- Anti-debug detection ---
            Pattern("CHECK_REMOTE_DEBUGGER", "FF15????????85C075", "anti_debug",
                    "CheckRemoteDebuggerPresent call pattern"),
            Pattern("IS_DEBUGGER_PRESENT", "64A130000000", "anti_debug",
                    "PEB->BeingDebugged check via fs:[0x30]", severity="warning"),
            Pattern("IS_DEBUGGER_PRESENT_64", "65488B042560000000", "anti_debug",
                    "PEB->BeingDebugged check via gs:[0x60] (x64)", severity="warning"),
            Pattern("NT_QUERY_INFO_DEBUGPORT", "B807000000", "anti_debug",
                    "NtQueryInformationProcess DebugPort check"),
            Pattern("RDTSC_TIMING", "0F31", "anti_debug",
                    "RDTSC instruction (timing-based debug detection)"),
            Pattern("INT2D_DEBUG_TRAP", "CD2D90", "anti_debug",
                    "INT 2Dh debug service trap (anti-debug trick)",
                    severity="warning"),
            Pattern("NTQUERYOBJECT_DEBUGOBJECT", "B817000000", "anti_debug",
                    "NtQueryObject DebugObject type check"),

            # --- Anti-cheat signatures ---
            Pattern("VANGUARD_HEARTBEAT", "56616E67756172644865617274", "anti_cheat",
                    "Vanguard heartbeat string"),
            Pattern("EAC_INIT", "456173794172746943686561", "anti_cheat",
                    "EasyAntiCheat init string"),
            Pattern("BATTLEYE_INIT", "426174746C65457965", "anti_cheat",
                    "BattlEye init string"),
            Pattern("VANGUARD_DRIVER_LOAD", "76676B2E737973", "anti_cheat",
                    "vgk.sys driver reference (Vanguard kernel driver)"),
            Pattern("EAC_SERVICE_NAME", "45617379416E74694368656174", "anti_cheat",
                    "EasyAntiCheat service name string"),

            # --- DRM signatures ---
            Pattern("DENUVO_CHECK", "44656E75766F", "drm",
                    "Denuvo DRM string marker"),
            Pattern("STEAMDRM_STUB", "E8????????83C404", "drm",
                    "Steam DRM stub pattern"),
            Pattern("STEAMDRM_HEADER", "2E62696E64", "drm",
                    "Steam DRM .bind section marker"),

            # --- Common API call patterns (x64) ---
            Pattern("CALL_CREATEFILE", "FF15????????488BC8", "api_call",
                    "CreateFile[AW] indirect call pattern",
                    metadata={"api": "CreateFileA/W", "dll": "kernel32"}),
            Pattern("CALL_VIRTUALALLOC", "4489442420FF15", "api_call",
                    "VirtualAlloc indirect call pattern",
                    metadata={"api": "VirtualAlloc", "dll": "kernel32"}),
            Pattern("CALL_LOADLIBRARY", "488D0D????????FF15", "api_call",
                    "LoadLibrary[AW] lea+call pattern",
                    metadata={"api": "LoadLibraryA/W", "dll": "kernel32"}),
            Pattern("CALL_GETPROCADDRESS", "488D15????????FF15????????4885C0", "api_call",
                    "GetProcAddress lea+call+test pattern",
                    metadata={"api": "GetProcAddress", "dll": "kernel32"}),
            Pattern("CALL_REGOPENKEYEX", "4C8D05????????488D15????????FF15", "api_call",
                    "RegOpenKeyEx lea+lea+call pattern",
                    metadata={"api": "RegOpenKeyExA/W", "dll": "advapi32"}),
            Pattern("CALL_COCREATEINSTANCE", "488D0D????????488D15????????41B8", "api_call",
                    "CoCreateInstance CLSID+IID+context setup",
                    metadata={"api": "CoCreateInstance", "dll": "ole32"}),

            # --- DirectX initialization ---
            Pattern("D3D11_CREATE", "443D11000000", "dx_init",
                    "D3D11 feature level check",
                    metadata={"requires": "d3d11"}),
            Pattern("D3D12_CREATE", "443D0C000000", "dx_init",
                    "D3D12 feature level check",
                    metadata={"requires": "d3d12"}),
            Pattern("D3D9_CREATE", "443D09000000", "dx_init",
                    "D3D9 SDK version check",
                    metadata={"requires": "d3d9"}),
            Pattern("VULKAN_CREATE_INSTANCE", "766B437265617465496E7374616E6365", "dx_init",
                    "vkCreateInstance string",
                    metadata={"requires": "vulkan"}),
            Pattern("DXGI_CREATE_FACTORY", "4372656174654458474946616374", "dx_init",
                    "CreateDXGIFactory string reference",
                    metadata={"requires": "dxgi"}),

            # --- Unimplemented stub detection ---
            Pattern("STUB_DIAGNOSTIC", "5B70655F696D706F72745D2053545542", "stub_hit",
                    "[pe_import] STUB marker in memory (unimplemented function called)",
                    severity="warning"),
            Pattern("STUB_WILL_RETURN_ZERO", "77696C6C2072657475726E2030", "stub_hit",
                    "'will return 0' diagnostic (stub returning dummy value)",
                    severity="warning"),

            # --- Network ---
            Pattern("WINSOCK_INIT", "01020202", "network",
                    "WSAStartup version 2.2 request",
                    metadata={"api": "WSAStartup", "dll": "ws2_32"}),
            Pattern("HTTP_GET_REQUEST", "474554202F", "network",
                    "HTTP GET request in memory"),
            Pattern("HTTP_POST_REQUEST", "504F5354202F", "network",
                    "HTTP POST request in memory"),
            Pattern("HTTPS_TLS", "160301", "network",
                    "TLS ClientHello (HTTPS connection)"),
            Pattern("TLS_12_RECORD", "160303", "network",
                    "TLS 1.2 record header"),
        ]
        for p in builtins:
            self.patterns[p.id] = p

    def _load_custom_patterns(self):
        """Load user-defined patterns from disk."""
        custom_file = self._db_path / "custom_patterns.json"
        if custom_file.exists():
            try:
                data = json.loads(custom_file.read_text())
                for entry in data:
                    p = Pattern(**entry)
                    self.patterns[p.id] = p
                logger.info("Loaded %d custom patterns", len(data))
            except Exception as e:
                logger.error("Failed to load custom patterns: %s", e)

    def add_pattern(self, pattern: Pattern):
        self.patterns[pattern.id] = pattern

    def get_by_category(self, category: str) -> list[Pattern]:
        return [p for p in self.patterns.values() if p.category == category]

    def save_custom(self):
        """Persist custom patterns to disk."""
        self._db_path.mkdir(parents=True, exist_ok=True)
        # Identify builtin pattern prefixes to exclude from custom save
        _builtin_prefixes = (
            "IOCTL_", "CHECK_", "IS_", "NT", "RDTSC", "INT2D",
            "VANGUARD_", "EAC_", "BATTLEYE_", "DENUVO_",
            "STEAMDRM_", "CALL_", "D3D", "VULKAN_", "DXGI_",
            "STUB_", "WINSOCK_", "HTTP", "TLS_",
        )
        customs = [p.__dict__ for p in self.patterns.values()
                   if not p.id.startswith(_builtin_prefixes)]
        (self._db_path / "custom_patterns.json").write_text(
            json.dumps(customs, indent=2)
        )


class MemoryScanner:
    """Scans process memory against the pattern database."""

    def __init__(self, db: PatternDatabase = None):
        self.db = db or PatternDatabase()
        self._compiled: dict[str, tuple[bytes, bytes]] = {}
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile hex patterns into byte+mask pairs for fast matching."""
        for pid, pattern in self.db.patterns.items():
            raw = pattern.bytes_hex.upper()
            pat_bytes = []
            pat_mask = []
            i = 0
            while i < len(raw):
                if i + 1 < len(raw) and raw[i] == '?' and raw[i+1] == '?':
                    # Full wildcard byte
                    pat_bytes.append(0)
                    pat_mask.append(0)
                    i += 2
                elif raw[i] == '?':
                    # Single ? treated as nibble wildcard - skip paired handling
                    pat_bytes.append(0)
                    pat_mask.append(0)
                    i += 1
                    if i < len(raw) and raw[i] == '?':
                        i += 1  # Skip second ? if present
                elif i + 1 < len(raw):
                    try:
                        pat_bytes.append(int(raw[i:i+2], 16))
                    except ValueError:
                        pat_bytes.append(0)
                        pat_mask.append(0)
                        i += 2
                        continue
                    pat_mask.append(0xFF)
                    i += 2
                else:
                    # Odd trailing character - skip
                    i += 1
            self._compiled[pid] = (bytes(pat_bytes), bytes(pat_mask))

    def scan_bytes(self, data: bytes, region_label: str = "") -> list[ScanMatch]:
        """Scan a byte buffer against all patterns."""
        matches = []
        for pid, (pat, mask) in self._compiled.items():
            plen = len(pat)
            if plen == 0:
                continue
            for offset in range(len(data) - plen + 1):
                found = True
                for j in range(plen):
                    if mask[j] and (data[offset + j] & mask[j]) != pat[j]:
                        found = False
                        break
                if found:
                    pattern = self.db.patterns[pid]
                    ctx_start = max(0, offset - 16)
                    ctx_end = min(len(data), offset + plen + 16)
                    matches.append(ScanMatch(
                        pattern_id=pid,
                        va=offset,
                        region_label=region_label,
                        category=pattern.category,
                        description=pattern.description,
                        context_bytes=data[ctx_start:ctx_end],
                    ))
        return matches

    def scan_process(self, pid: int) -> list[ScanMatch]:
        """Scan a process's memory via /proc/PID/mem."""
        all_matches = []
        maps_path = f"/proc/{pid}/maps"
        mem_path = f"/proc/{pid}/mem"

        try:
            with open(maps_path) as f:
                regions = f.readlines()
        except (OSError, PermissionError):
            return []

        try:
            mem_fd = os.open(mem_path, os.O_RDONLY)
        except (OSError, PermissionError):
            return []

        try:
            for line in regions:
                parts = line.split()
                if len(parts) < 2:
                    continue
                addr_range = parts[0].split('-')
                start = int(addr_range[0], 16)
                end = int(addr_range[1], 16)
                perms = parts[1]
                size = end - start

                # Skip non-readable or very large regions
                if 'r' not in perms or size > 64 * 1024 * 1024:
                    continue

                label = parts[5].strip() if len(parts) > 5 else f"anon@{start:#x}"

                try:
                    os.lseek(mem_fd, start, os.SEEK_SET)
                    data = os.read(mem_fd, min(size, 4 * 1024 * 1024))
                    if data:
                        region_matches = self.scan_bytes(data, label)
                        for m in region_matches:
                            m.va += start  # Adjust to absolute VA
                        all_matches.extend(region_matches)
                except OSError:
                    continue
        finally:
            os.close(mem_fd)

        return all_matches

    def analyze_process(self, pid: int) -> dict:
        """High-level analysis: what does this process need?"""
        matches = self.scan_process(pid)

        analysis = {
            "pid": pid,
            "total_matches": len(matches),
            "required_dlls": set(),
            "required_drivers": [],
            "anti_debug_detected": [],
            "anti_cheat_detected": [],
            "drm_detected": [],
            "dx_requirements": [],
            "network_activity": [],
            "unimplemented_stubs": [],
            "api_calls": [],
        }

        for m in matches:
            pattern = self.db.patterns.get(m.pattern_id)
            if not pattern:
                continue

            if m.category == "ioctl":
                analysis["required_drivers"].append(m.description)
            elif m.category == "anti_debug":
                analysis["anti_debug_detected"].append(m.description)
            elif m.category == "anti_cheat":
                analysis["anti_cheat_detected"].append(m.description)
            elif m.category == "drm":
                analysis["drm_detected"].append(m.description)
            elif m.category == "dx_init":
                analysis["dx_requirements"].append(
                    pattern.metadata.get("requires", ""))
                analysis["required_dlls"].add(
                    pattern.metadata.get("requires", ""))
            elif m.category == "api_call":
                analysis["api_calls"].append(
                    pattern.metadata.get("api", ""))
                if "dll" in pattern.metadata:
                    analysis["required_dlls"].add(pattern.metadata["dll"])
            elif m.category == "stub_hit":
                analysis["unimplemented_stubs"].append(m.region_label)
            elif m.category == "network":
                analysis["network_activity"].append(m.description)

        analysis["required_dlls"] = sorted(analysis["required_dlls"])
        return analysis

    def get_stats(self) -> dict:
        return {
            "total_patterns": len(self.db.patterns),
            "categories": {cat: len(pats) for cat, pats in
                           self._group_by_category().items()},
        }

    def _group_by_category(self) -> dict:
        groups = {}
        for p in self.db.patterns.values():
            groups.setdefault(p.category, []).append(p)
        return groups
