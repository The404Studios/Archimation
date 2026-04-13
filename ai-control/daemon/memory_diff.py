"""
Memory Diff Engine -- Captures and compares process memory snapshots.

Use cases:
1. Detect lazy-loaded DLLs (not in import table, loaded at runtime via LoadLibrary)
2. Detect anti-tamper code decryption (encrypted .text section decrypted at runtime)
3. Track memory growth patterns (leak detection)
4. Compare pre-game vs in-game memory to find game-specific resources
5. Detect code injection by comparing snapshots
"""

import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("ai-control.memory_diff")

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class MemorySnapshot:
    """A point-in-time capture of a process's memory layout."""
    pid: int
    timestamp: float
    label: str                      # e.g. "load", "menu", "gameplay", "exit"
    regions: list[dict]             # Parsed from /proc/PID/maps
    total_mapped: int               # Sum of all region sizes in bytes
    total_regions: int              # Number of mapped regions
    dll_list: list[str]             # PE-compat DLL stubs loaded at this point
    region_hashes: dict[str, str]   # "start-end" -> SHA-256 prefix of first 4KB


@dataclass
class MemoryDiff:
    """The difference between two memory snapshots."""
    snapshot_a: str                 # label of first snapshot
    snapshot_b: str                 # label of second snapshot
    time_delta: float               # seconds between captures

    new_regions: list[dict]         # Regions present in B but absent in A
    removed_regions: list[dict]     # Regions present in A but absent in B
    modified_regions: list[dict]    # Same VA range but different content/perms

    new_dlls: list[str]             # DLLs loaded between snapshots
    removed_dlls: list[str]         # DLLs unloaded between snapshots

    memory_growth: int              # bytes (positive = growth, negative = shrink)
    region_count_delta: int         # change in region count

    anomalies: list[dict]           # Suspicious changes detected


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

# Max regions to hash per snapshot (avoids slow captures on large processes)
_MAX_HASH_REGIONS = 200

# Max bytes to read from the start of each region for hashing
_HASH_READ_SIZE = 4096

# Truncated SHA-256 prefix length (hex chars)
_HASH_PREFIX_LEN = 16


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class MemoryDiffEngine:
    """Captures and compares process memory snapshots over time."""

    def __init__(self, max_snapshots_per_pid: int = 20):
        self._snapshots: dict[int, list[MemorySnapshot]] = {}  # pid -> snapshots
        self._max_snapshots_per_pid = max(1, max_snapshots_per_pid)

    # ------------------------------------------------------------------
    # Capture
    # ------------------------------------------------------------------

    async def capture_snapshot(self, pid: int, label: str = "") -> MemorySnapshot:
        """Capture current memory state of a process.

        Reads /proc/PID/maps and optionally hashes the first 4 KB of each
        readable region via /proc/PID/mem so that content changes can be
        detected by later diffs.
        """
        if not label:
            label = f"snap_{int(time.time())}"

        regions: list[dict] = []
        dll_list: list[str] = []
        total_mapped = 0
        region_hashes: dict[str, str] = {}

        # -- Parse /proc/PID/maps ----------------------------------------
        try:
            with open(f"/proc/{pid}/maps") as f:
                for line in f:
                    parts = line.split(None, 5)
                    if len(parts) < 5:
                        continue
                    addr_range = parts[0].split("-")
                    if len(addr_range) != 2:
                        continue
                    try:
                        start = int(addr_range[0], 16)
                        end = int(addr_range[1], 16)
                    except ValueError:
                        continue
                    size = end - start
                    path = parts[5].strip() if len(parts) > 5 else ""

                    region = {
                        "start": start,
                        "end": end,
                        "size": size,
                        "perms": parts[1],
                        "path": path,
                    }
                    regions.append(region)
                    total_mapped += size

                    # Track PE-compat DLL stubs
                    basename = os.path.basename(path) if path else ""
                    if basename.startswith("libpe_") and basename.endswith(".so"):
                        if basename not in dll_list:
                            dll_list.append(basename)
        except (OSError, PermissionError) as exc:
            logger.error("Failed to read /proc/%d/maps: %s", pid, exc)

        # -- Hash first 4 KB of each readable region ---------------------
        try:
            with open(f"/proc/{pid}/mem", "rb") as mem:
                for region in regions[:_MAX_HASH_REGIONS]:
                    if "r" not in region["perms"]:
                        continue
                    key = f"{region['start']:#x}-{region['end']:#x}"
                    try:
                        mem.seek(region["start"])
                        data = mem.read(min(_HASH_READ_SIZE, region["size"]))
                        region_hashes[key] = hashlib.sha256(data).hexdigest()[:_HASH_PREFIX_LEN]
                    except (OSError, ValueError):
                        pass
        except (OSError, PermissionError):
            # Cannot read process memory (e.g. no ptrace access). Hashes
            # will be empty; diffs will still detect region/perm changes.
            pass

        snapshot = MemorySnapshot(
            pid=pid,
            timestamp=time.time(),
            label=label,
            regions=regions,
            total_mapped=total_mapped,
            total_regions=len(regions),
            dll_list=sorted(dll_list),
            region_hashes=region_hashes,
        )

        # Store (with eviction of oldest)
        self._snapshots.setdefault(pid, []).append(snapshot)
        if len(self._snapshots[pid]) > self._max_snapshots_per_pid:
            self._snapshots[pid] = self._snapshots[pid][-self._max_snapshots_per_pid:]

        logger.info(
            "Captured snapshot '%s' for PID %d: %d regions, %d bytes mapped, %d DLLs",
            label, pid, len(regions), total_mapped, len(dll_list),
        )
        return snapshot

    # ------------------------------------------------------------------
    # Diff
    # ------------------------------------------------------------------

    def diff_snapshots(self, pid: int, label_a: str, label_b: str) -> Optional[MemoryDiff]:
        """Compare two named snapshots for a given PID.

        Returns None if either snapshot label is not found.
        """
        snaps = self._snapshots.get(pid, [])
        snap_a = next((s for s in snaps if s.label == label_a), None)
        snap_b = next((s for s in snaps if s.label == label_b), None)
        if not snap_a or not snap_b:
            return None
        return self._compute_diff(snap_a, snap_b)

    def _compute_diff(self, a: MemorySnapshot, b: MemorySnapshot) -> MemoryDiff:
        """Compute the structural and content diff between two snapshots."""

        def _region_key(r: dict) -> str:
            return f"{r['start']:#x}-{r['end']:#x}"

        a_by_key = {_region_key(r): r for r in a.regions}
        b_by_key = {_region_key(r): r for r in b.regions}

        a_keys = set(a_by_key.keys())
        b_keys = set(b_by_key.keys())

        new_regions = [b_by_key[k] for k in sorted(b_keys - a_keys)]
        removed_regions = [a_by_key[k] for k in sorted(a_keys - b_keys)]

        # Shared regions: check for content changes and permission changes
        modified: list[dict] = []
        for key in sorted(a_keys & b_keys):
            r_a = a_by_key[key]
            r_b = b_by_key[key]
            hash_a = a.region_hashes.get(key, "")
            hash_b = b.region_hashes.get(key, "")

            if hash_a and hash_b and hash_a != hash_b:
                modified.append({**r_b, "change": "content_modified"})
            elif r_a["perms"] != r_b["perms"]:
                modified.append({
                    **r_b,
                    "change": "perms_changed",
                    "old_perms": r_a["perms"],
                })

        # DLL delta
        a_dlls = set(a.dll_list)
        b_dlls = set(b.dll_list)
        new_dlls = sorted(b_dlls - a_dlls)
        removed_dlls = sorted(a_dlls - b_dlls)

        # Anomaly detection
        anomalies = self._detect_anomalies(new_regions, modified)

        return MemoryDiff(
            snapshot_a=a.label,
            snapshot_b=b.label,
            time_delta=b.timestamp - a.timestamp,
            new_regions=new_regions,
            removed_regions=removed_regions,
            modified_regions=modified,
            new_dlls=new_dlls,
            removed_dlls=removed_dlls,
            memory_growth=b.total_mapped - a.total_mapped,
            region_count_delta=b.total_regions - a.total_regions,
            anomalies=anomalies,
        )

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_anomalies(
        new_regions: list[dict],
        modified_regions: list[dict],
    ) -> list[dict]:
        """Flag suspicious changes that may indicate injection or tampering."""
        anomalies: list[dict] = []

        # 1. New anonymous executable regions (possible code injection)
        for r in new_regions:
            perms = r.get("perms", "")
            path = r.get("path", "")
            if "x" in perms and not path:
                anomalies.append({
                    "type": "new_anon_executable",
                    "va": r["start"],
                    "size": r["size"],
                    "severity": "high",
                    "description": "New anonymous executable region appeared",
                })
            # New W+X region (should never happen with W^X policy)
            if "w" in perms and "x" in perms:
                anomalies.append({
                    "type": "new_wx_region",
                    "va": r["start"],
                    "size": r["size"],
                    "path": path,
                    "severity": "critical",
                    "description": "New writable+executable region (W^X violation)",
                })

        # 2. Code section content changed (decryption, self-modifying code)
        for r in modified_regions:
            if r.get("change") != "content_modified":
                continue
            path = r.get("path", "")
            perms = r.get("perms", "")
            if "x" in perms or ".text" in path:
                anomalies.append({
                    "type": "code_modified",
                    "va": r["start"],
                    "size": r["size"],
                    "path": path,
                    "severity": "critical",
                    "description": f"Code section content changed: {path or 'anonymous'}",
                })

        # 3. Permission escalation (e.g. r-- -> r-x)
        for r in modified_regions:
            if r.get("change") != "perms_changed":
                continue
            old_perms = r.get("old_perms", "")
            new_perms = r.get("perms", "")
            if "x" not in old_perms and "x" in new_perms:
                anomalies.append({
                    "type": "perm_escalation",
                    "va": r["start"],
                    "size": r["size"],
                    "old_perms": old_perms,
                    "new_perms": new_perms,
                    "severity": "medium",
                    "description": f"Region became executable: {old_perms} -> {new_perms}",
                })

        return anomalies

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_snapshots(self, pid: int) -> list[dict]:
        """List all snapshots for a PID (metadata only, no heavy region data)."""
        return [
            {
                "label": s.label,
                "timestamp": s.timestamp,
                "regions": s.total_regions,
                "mapped": s.total_mapped,
                "dlls": len(s.dll_list),
                "dll_list": s.dll_list,
                "hashed_regions": len(s.region_hashes),
            }
            for s in self._snapshots.get(pid, [])
        ]

    def get_timeline(self, pid: int) -> list[dict]:
        """Build a chronological timeline of all changes across snapshots.

        Returns a list of summary dicts, one per consecutive snapshot pair.
        """
        snaps = self._snapshots.get(pid, [])
        if len(snaps) < 2:
            return []

        timeline: list[dict] = []
        for i in range(1, len(snaps)):
            diff = self._compute_diff(snaps[i - 1], snaps[i])
            timeline.append({
                "from": diff.snapshot_a,
                "to": diff.snapshot_b,
                "time_delta": round(diff.time_delta, 3),
                "new_regions": len(diff.new_regions),
                "removed_regions": len(diff.removed_regions),
                "modified_regions": len(diff.modified_regions),
                "new_dlls": diff.new_dlls,
                "removed_dlls": diff.removed_dlls,
                "memory_growth": diff.memory_growth,
                "region_count_delta": diff.region_count_delta,
                "anomaly_count": len(diff.anomalies),
                "anomalies": diff.anomalies,
            })
        return timeline

    def clear_snapshots(self, pid: int) -> int:
        """Remove all snapshots for a PID. Returns the count removed."""
        removed = len(self._snapshots.pop(pid, []))
        return removed

    def get_stats(self) -> dict:
        """Return engine-wide statistics."""
        total_snaps = sum(len(v) for v in self._snapshots.values())
        return {
            "tracked_pids": len(self._snapshots),
            "total_snapshots": total_snaps,
            "max_snapshots_per_pid": self._max_snapshots_per_pid,
            "pids": sorted(self._snapshots.keys()),
        }
