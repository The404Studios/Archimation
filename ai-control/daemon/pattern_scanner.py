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

# io_uring batch reader (R32).  Optional -- daemon keeps working on
# kernels <5.1 and non-Linux hosts where the import returns the stub.
try:
    from iouring import IOUring, batch_read_proc_files
    _IOURING_IMPORT_OK = True
except Exception:
    try:
        from daemon.iouring import IOUring, batch_read_proc_files  # type: ignore
        _IOURING_IMPORT_OK = True
    except Exception:
        IOUring = None  # type: ignore[assignment]
        batch_read_proc_files = None  # type: ignore[assignment]
        _IOURING_IMPORT_OK = False

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

    def __init__(
        self,
        db: PatternDatabase = None,
        use_iouring: bool = False,
        iouring_sqpoll: bool = False,
        iouring_sq_cpu: Optional[int] = None,
        iouring_depth: int = 32,
    ):
        self.db = db or PatternDatabase()
        # (pat_bytes, pat_mask, literal_or_None) per pattern id.
        self._compiled: dict[str, tuple[bytes, bytes, bytes | None]] = {}
        self._compile_patterns()
        # io_uring params (R32).  When enabled, scan_process pipelines
        # region reads -- substring search overlaps kernel DMA/copy so
        # wall-clock scan time drops ~2x on large processes.
        self._use_iouring = bool(use_iouring and _IOURING_IMPORT_OK)
        self._iouring_sqpoll = bool(iouring_sqpoll)
        self._iouring_sq_cpu = iouring_sq_cpu
        self._iouring_depth = max(8, int(iouring_depth))
        self._iouring_disabled: bool = False

    def _compile_patterns(self):
        """Compile hex patterns into byte+mask pairs for fast matching.

        Also precomputes a "literal" bytes object (when the pattern has no
        wildcards) so scan_bytes can delegate to the C-implemented
        bytes.find(), which uses Boyer-Moore and is ~100× faster than the
        pure-Python mask loop on large memory regions.
        """
        # (pat_bytes, pat_mask, literal_or_None, has_wildcard)
        self._compiled = {}
        for pid, pattern in self.db.patterns.items():
            raw = "".join(pattern.bytes_hex.upper().split())
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
                    # Lone ? -- treat as wildcard byte to keep pat_bytes
                    # and pat_mask lengths in sync (previous code only appended
                    # to pat_bytes here, causing all subsequent byte/mask
                    # indices to desync and mis-match patterns).
                    pat_bytes.append(0)
                    pat_mask.append(0)
                    i += 1
                elif i + 1 < len(raw):
                    try:
                        pat_bytes.append(int(raw[i:i+2], 16))
                        pat_mask.append(0xFF)
                    except ValueError:
                        pat_bytes.append(0)
                        pat_mask.append(0)
                    i += 2
                else:
                    # Odd trailing character - skip
                    i += 1
            pat_b = bytes(pat_bytes)
            mask_b = bytes(pat_mask)
            has_wildcard = any(m != 0xFF for m in mask_b)
            literal = None if has_wildcard else pat_b
            self._compiled[pid] = (pat_b, mask_b, literal)

    def scan_bytes(self, data: bytes, region_label: str = "") -> list[ScanMatch]:
        """Scan a byte buffer against all patterns.

        Uses bytes.find() for wildcard-free patterns (which is most of the
        anti-cheat / DRM string and IOCTL patterns) — 100× faster than the
        Python loop for multi-MB memory regions. Falls back to mask-matching
        for patterns that contain `??`.
        """
        matches = []
        dlen = len(data)
        patterns = self.db.patterns
        for pid, compiled in self._compiled.items():
            pat, mask, literal = compiled
            plen = len(pat)
            if plen == 0:
                continue
            pattern = patterns[pid]

            if literal is not None:
                # Fast path: C-level substring search.
                start = 0
                while True:
                    idx = data.find(literal, start)
                    if idx < 0:
                        break
                    ctx_start = max(0, idx - 16)
                    ctx_end = min(dlen, idx + plen + 16)
                    matches.append(ScanMatch(
                        pattern_id=pid,
                        va=idx,
                        region_label=region_label,
                        category=pattern.category,
                        description=pattern.description,
                        context_bytes=data[ctx_start:ctx_end],
                    ))
                    start = idx + 1
                continue

            # Slow path: mask-based match for patterns with `??`.
            # Anchor on the first fully-specified byte when one exists so
            # we can still delegate the outer loop to C. Find the first
            # non-wildcard byte; bytes.find() on THAT is still much faster
            # than O(n) Python iteration and lets us validate the rest
            # only at hits.
            anchor = -1
            for j in range(plen):
                if mask[j] == 0xFF:
                    anchor = j
                    break
            if anchor >= 0:
                anchor_byte = bytes([pat[anchor]])
                search_start = 0
                while True:
                    idx = data.find(anchor_byte, search_start)
                    if idx < 0:
                        break
                    offset = idx - anchor
                    search_start = idx + 1
                    if offset < 0 or offset + plen > dlen:
                        continue
                    # Validate the masked bytes.
                    ok = True
                    for j in range(plen):
                        m = mask[j]
                        if m and (data[offset + j] & m) != pat[j]:
                            ok = False
                            break
                    if ok:
                        ctx_start = max(0, offset - 16)
                        ctx_end = min(dlen, offset + plen + 16)
                        matches.append(ScanMatch(
                            pattern_id=pid,
                            va=offset,
                            region_label=region_label,
                            category=pattern.category,
                            description=pattern.description,
                            context_bytes=data[ctx_start:ctx_end],
                        ))
                continue

            # Fully-wildcard pattern (pathological): fall back to original
            # slow loop. This basically never happens — included for safety.
            for offset in range(dlen - plen + 1):
                found = True
                for j in range(plen):
                    if mask[j] and (data[offset + j] & mask[j]) != pat[j]:
                        found = False
                        break
                if found:
                    ctx_start = max(0, offset - 16)
                    ctx_end = min(dlen, offset + plen + 16)
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
        """Scan a process's memory via /proc/PID/mem.

        With io_uring enabled (R32) region reads are pipelined: the
        substring scan on region N runs in parallel with the kernel
        fetching region N+1.  Falls back to the serial loop on kernels
        <5.1 or if any ring op errors out.
        """
        all_matches: list[ScanMatch] = []
        maps_path = f"/proc/{pid}/maps"
        mem_path = f"/proc/{pid}/mem"

        try:
            with open(maps_path) as f:
                regions = f.readlines()
        except (OSError, PermissionError):
            return []

        # Pre-parse region descriptors so both paths share the filter.
        scan_regions: list[tuple[int, int, str]] = []
        for line in regions:
            parts = line.split()
            if len(parts) < 2:
                continue
            addr_range = parts[0].split('-')
            try:
                start = int(addr_range[0], 16)
                end = int(addr_range[1], 16)
            except (ValueError, IndexError):
                continue
            perms = parts[1]
            size = end - start
            if 'r' not in perms or size > 64 * 1024 * 1024:
                continue
            label = parts[5].strip() if len(parts) > 5 else f"anon@{start:#x}"
            scan_regions.append((start, size, label))

        if not scan_regions:
            return []

        try:
            mem_fd = os.open(mem_path, os.O_RDONLY)
        except (OSError, PermissionError):
            return []

        try:
            if (
                self._use_iouring
                and not self._iouring_disabled
                and _IOURING_IMPORT_OK
                and IOUring is not None
                and IOUring.available()
                and len(scan_regions) > 1
            ):
                ok = self._scan_process_iouring(
                    mem_fd, scan_regions, all_matches,
                )
                if not ok:
                    all_matches.clear()
                    self._scan_process_sync(mem_fd, scan_regions, all_matches)
            else:
                self._scan_process_sync(mem_fd, scan_regions, all_matches)
        finally:
            os.close(mem_fd)

        return all_matches

    def _scan_process_sync(
        self,
        mem_fd: int,
        scan_regions: list[tuple[int, int, str]],
        all_matches: list[ScanMatch],
    ) -> None:
        """Synchronous per-region scan -- the portable fallback."""
        for start, size, label in scan_regions:
            try:
                os.lseek(mem_fd, start, os.SEEK_SET)
                data = os.read(mem_fd, min(size, 4 * 1024 * 1024))
            except OSError:
                continue
            if not data:
                continue
            region_matches = self.scan_bytes(data, label)
            for m in region_matches:
                m.va += start
            all_matches.extend(region_matches)

    def _scan_process_iouring(
        self,
        mem_fd: int,
        scan_regions: list[tuple[int, int, str]],
        all_matches: list[ScanMatch],
    ) -> bool:
        """Pipeline reads via io_uring so scan + I/O overlap.

        Returns False if a ring op failed -- the caller retries sync.
        """
        if IOUring is None:
            return False
        try:
            ring = IOUring(
                depth=self._iouring_depth,
                sqpoll=self._iouring_sqpoll,
                sq_cpu=self._iouring_sq_cpu,
            )
            ring._setup()
        except OSError as e:
            logger.debug("pattern_scanner: io_uring setup failed (%s)", e)
            self._iouring_disabled = True
            return False

        # Cap per-region buffer to the same 4 MiB budget the sync path uses.
        MAX_PER_REGION = 4 * 1024 * 1024
        depth = max(2, min(self._iouring_depth, 16))
        in_flight: dict[int, tuple[int, str, bytearray, int]] = {}
        idx = 0
        total = len(scan_regions)
        try:
            while idx < total or in_flight:
                # Fill the pipeline.
                while idx < total and len(in_flight) < depth:
                    start, size, label = scan_regions[idx]
                    to_read = min(size, MAX_PER_REGION)
                    buf = bytearray(to_read)
                    ud = ring.submit_read(mem_fd, buf, offset=start)
                    if ud is None:
                        break
                    in_flight[ud] = (start, label, buf, to_read)
                    idx += 1
                if not in_flight:
                    break
                completions = ring.drain(min_complete=1)
                for c in completions:
                    meta = in_flight.pop(c.user_data, None)
                    if meta is None:
                        continue
                    start, label, buf, reqlen = meta
                    if not c.ok:
                        # /proc/PID/mem returns EIO for unreadable pages --
                        # same as the sync path (lseek + read on a hole).
                        continue
                    n = c.res if c.res >= 0 else 0
                    if n == 0:
                        continue
                    data = bytes(buf[:n])
                    region_matches = self.scan_bytes(data, label)
                    for m in region_matches:
                        m.va += start
                    all_matches.extend(region_matches)
            return True
        except OSError as e:
            logger.warning(
                "pattern_scanner: io_uring drain failed (%s); disabling", e,
            )
            self._iouring_disabled = True
            return False
        finally:
            ring.close()

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
