"""
Trust History -- persistent per-executable trust records.

Remembers which executables behaved well across reboots.
The cortex uses this to fast-track trusted programs and be suspicious
of unknown ones.

Storage: /var/lib/pe-compat/trust-history/<sha256>.json
Key: SHA256 hash of the executable path (not content -- faster, good enough)
"""

import json
import os
import hashlib
import time
import logging
from collections import OrderedDict
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List

logger = logging.getLogger("cortex.trust_history")

HISTORY_DIR = "/var/lib/pe-compat/trust-history"


@dataclass
class ExecutionRecord:
    """One execution of a PE binary."""
    timestamp: float
    exit_code: int
    runtime_ms: int
    stubs_called: int = 0
    trust_denials: int = 0
    exceptions: int = 0
    quarantined: bool = False


@dataclass
class TrustRecord:
    """Persistent trust record for one executable."""
    exe_path: str
    first_seen: float
    last_seen: float
    total_runs: int = 0
    clean_exits: int = 0       # exit_code == 0
    crashes: int = 0           # exit_code != 0
    quarantines: int = 0
    total_trust_denials: int = 0
    avg_runtime_ms: float = 0.0
    trust_score: int = 50      # Accumulated score for this exe
    recent_runs: List[dict] = field(default_factory=list)  # Last 10 runs

    @property
    def reliability(self) -> float:
        """0.0 to 1.0 -- how reliable is this executable?"""
        if self.total_runs == 0:
            return 0.5  # Unknown
        clean_ratio = self.clean_exits / self.total_runs
        quarantine_penalty = min(self.quarantines * 0.1, 0.5)
        return max(0.0, min(1.0, clean_ratio - quarantine_penalty))

    @property
    def suggested_token_budget(self) -> int:
        """Suggest a token budget based on history."""
        base = 200
        if self.reliability >= 0.9:
            return base + 300  # Trusted: 500 tokens
        elif self.reliability >= 0.7:
            return base + 100  # Good: 300 tokens
        elif self.reliability >= 0.5:
            return base        # Neutral: 200 tokens
        else:
            return base - 100  # Suspicious: 100 tokens

    def to_api_dict(self) -> dict:
        """Serialize for the REST API, including computed properties."""
        d = asdict(self)
        d["reliability"] = round(self.reliability, 4)
        d["suggested_token_budget"] = self.suggested_token_budget
        return d


class TrustHistoryStore:
    """Persistent trust history storage."""

    # Maximum entries kept in the in-memory cache.  When exceeded, the
    # least-recently-used entries are evicted.  Disk files are never removed
    # by this limit -- only the in-memory mirror is bounded.
    MAX_CACHE_ENTRIES: int = 2000

    # Maximum number of on-disk trust record files.  When exceeded, the
    # oldest files (by mtime) are deleted during periodic maintenance.
    MAX_DISK_FILES: int = 10000

    def __init__(self, history_dir: str = HISTORY_DIR):
        self._dir = history_dir
        # OrderedDict gives O(1) move_to_end / popitem; the previous
        # list-based access tracking was O(N) per touch (list.remove) which
        # dominated record_start/record_exit on busy systems.
        self._cache: "OrderedDict[str, TrustRecord]" = OrderedDict()
        # Negative lookup cache -- remembers keys that weren't on disk so
        # repeated pe_load events for unknown binaries don't hit the disk
        # every time (open(ENOENT) is surprisingly expensive under load).
        # Invalidated when record_start/record_exit adds the key.
        self._miss_cache: set = set()
        self._all_cache: Optional[List[TrustRecord]] = None
        self._all_cache_time: float = 0.0
        self._save_count: int = 0  # Tracks saves for periodic disk pruning
        try:
            os.makedirs(self._dir, exist_ok=True)
        except OSError as e:
            logger.warning("Cannot create trust history dir %s: %s", self._dir, e)
        logger.info("Trust history store: %s", self._dir)

    def _touch_cache(self, key: str) -> None:
        """Mark a cache key as recently used and evict LRU entries if over limit."""
        # O(1) move to MRU end
        if key in self._cache:
            self._cache.move_to_end(key, last=True)

        # Evict oldest entries when cache exceeds limit (O(1) per eviction)
        while len(self._cache) > self.MAX_CACHE_ENTRIES:
            self._cache.popitem(last=False)

    def _prune_disk_files(self) -> None:
        """Remove oldest trust record files when disk count exceeds MAX_DISK_FILES.

        Called periodically (every 100 saves) to avoid excessive filesystem
        stat calls.  Only removes records for executables not currently cached
        (active executables are preserved).
        """
        try:
            files = [
                f for f in os.listdir(self._dir) if f.endswith(".json")
            ]
        except OSError:
            return

        if len(files) <= self.MAX_DISK_FILES:
            return

        # Sort by mtime (oldest first) and remove excess
        file_mtimes = []
        for fname in files:
            path = os.path.join(self._dir, fname)
            try:
                file_mtimes.append((os.path.getmtime(path), path, fname))
            except OSError:
                continue
        file_mtimes.sort()

        excess = len(file_mtimes) - self.MAX_DISK_FILES
        removed = 0
        for _, path, fname in file_mtimes:
            if removed >= excess:
                break
            # Don't remove files for currently cached (active) executables
            cache_key = fname.replace(".json", "")
            if cache_key in self._cache:
                continue
            try:
                os.unlink(path)
                removed += 1
            except OSError:
                pass

        if removed > 0:
            logger.info("Pruned %d old trust history files (had %d, limit %d)",
                        removed, len(file_mtimes), self.MAX_DISK_FILES)
            self._all_cache = None  # Invalidate get_all() cache

    def _key(self, exe_path: str) -> str:
        """Generate storage key from exe path (32 hex chars to reduce collision risk)."""
        return hashlib.sha256(exe_path.encode()).hexdigest()[:32]

    def _path(self, key: str) -> str:
        return os.path.join(self._dir, f"{key}.json")

    @staticmethod
    def _load_and_validate(path: str) -> Optional[TrustRecord]:
        """Load a trust record from disk and validate critical fields.

        Returns None (with a warning) if the file is corrupt or has bad types.
        Uses a single open() call and catches FileNotFoundError, eliminating
        the exists()+open() TOCTOU race from the previous implementation.
        """
        try:
            with open(path) as f:
                data = json.load(f)
            record = TrustRecord(**data)
            # Validate critical fields
            assert isinstance(record.total_runs, int)
            assert isinstance(record.trust_score, (int, float))
            return record
        except FileNotFoundError:
            # Expected negative lookup -- not a warning.
            return None
        except (json.JSONDecodeError, TypeError, KeyError, AssertionError) as e:
            logger.warning("Invalid trust record %s: %s", path, e)
            return None
        except OSError as e:
            logger.warning("Cannot read trust record %s: %s", path, e)
            return None

    def get(self, exe_path: str) -> Optional[TrustRecord]:
        """Get trust record for an executable. Returns None if never seen.

        Caches negative lookups (miss set) so a pe_load event for a new
        binary doesn't cost an open(ENOENT) syscall on every create_decision
        call.  The miss set is bounded to MAX_CACHE_ENTRIES.
        """
        key = self._key(exe_path)

        # Check cache
        cached = self._cache.get(key)
        if cached is not None:
            self._touch_cache(key)
            return cached

        # Negative cache: if we've recently confirmed this exe isn't on disk,
        # don't re-open().
        if key in self._miss_cache:
            return None

        # Check disk (no separate exists() call -- open() raises ENOENT)
        record = self._load_and_validate(self._path(key))
        if record is not None:
            self._cache[key] = record
            self._touch_cache(key)
            return record

        # Record the miss, bounded to prevent unbounded growth
        self._miss_cache.add(key)
        if len(self._miss_cache) > self.MAX_CACHE_ENTRIES:
            # Evict half; next call rebuilds as needed
            self._miss_cache = set()
        return None

    def record_start(self, exe_path: str) -> TrustRecord:
        """Record that an executable is starting. Creates record if new."""
        key = self._key(exe_path)
        record = self.get(exe_path)

        if record is None:
            record = TrustRecord(
                exe_path=exe_path,
                first_seen=time.time(),
                last_seen=time.time(),
            )
            logger.info("New executable: %s", exe_path)

        record.total_runs += 1
        record.last_seen = time.time()

        self._cache[key] = record
        # A newly-created record invalidates any negative-cache entry.
        self._miss_cache.discard(key)
        self._touch_cache(key)
        self._save(key, record)
        return record

    def record_exit(
        self,
        exe_path: str,
        exit_code: int,
        runtime_ms: int,
        stubs_called: int = 0,
        trust_denials: int = 0,
        exceptions: int = 0,
    ) -> None:
        """Record execution completion."""
        key = self._key(exe_path)
        record = self.get(exe_path)
        if record is None:
            # Create a new record without incrementing total_runs -- record_start
            # already did that when the process launched.  If somehow record_exit
            # is called without a prior record_start (e.g. daemon restart),
            # we create the record with total_runs=1 to avoid losing the run.
            record = TrustRecord(
                exe_path=exe_path,
                first_seen=time.time(),
                last_seen=time.time(),
                total_runs=1,
            )
            self._cache[key] = record
            self._miss_cache.discard(key)
            self._touch_cache(key)
            self._save(key, record)

        if exit_code == 0:
            record.clean_exits += 1
            record.trust_score = min(100, record.trust_score + 1)
        else:
            record.crashes += 1
            record.trust_score = max(0, record.trust_score - 3)

        record.total_trust_denials += trust_denials

        # Update average runtime
        if record.total_runs > 1:
            record.avg_runtime_ms = (
                record.avg_runtime_ms * (record.total_runs - 1) + runtime_ms
            ) / record.total_runs
        else:
            record.avg_runtime_ms = float(runtime_ms)

        # Keep last 10 runs
        run = ExecutionRecord(
            timestamp=time.time(),
            exit_code=exit_code,
            runtime_ms=runtime_ms,
            stubs_called=stubs_called,
            trust_denials=trust_denials,
            exceptions=exceptions,
        )
        record.recent_runs.append(asdict(run))
        if len(record.recent_runs) > 10:
            record.recent_runs = record.recent_runs[-10:]

        self._cache[key] = record
        self._touch_cache(key)
        self._save(key, record)

    def record_quarantine(self, exe_path: str) -> None:
        """Record that an executable was quarantined."""
        key = self._key(exe_path)
        record = self.get(exe_path)
        if record is not None:
            record.quarantines += 1
            record.trust_score = max(0, record.trust_score - 10)
            self._cache[key] = record
            self._touch_cache(key)
            self._save(key, record)
            logger.info(
                "Quarantine recorded for %s (total=%d, score=%d)",
                exe_path, record.quarantines, record.trust_score,
            )

    def _save(self, key: str, record: TrustRecord) -> None:
        """Persist record to disk atomically (write-to-temp-then-rename)."""
        path = self._path(key)
        tmp_path = path + ".tmp"
        try:
            data = asdict(record)
            with open(tmp_path, 'w') as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, path)  # Atomic on POSIX
            # Mark the get_all() aggregate as stale without forcing a
            # full rescan -- the 5s TTL check in get_all() still governs
            # when we actually re-read the directory.  Patching the
            # existing list in place (when present) keeps the common-case
            # dashboard poll O(1) during bursts of save activity.
            if self._all_cache is not None:
                replaced = False
                for i, r in enumerate(self._all_cache):
                    if r.exe_path == record.exe_path:
                        self._all_cache[i] = record
                        replaced = True
                        break
                if not replaced:
                    self._all_cache.append(record)
        except OSError as e:
            logger.error("Failed to save trust record %s: %s", path, e)
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        # Periodically prune old disk files to prevent unbounded growth
        self._save_count += 1
        if self._save_count % 100 == 0:
            self._prune_disk_files()

    def get_all(self) -> List[TrustRecord]:
        """Get all trust records (for dashboard). Cached with 5-second TTL.

        Uses os.scandir() for ~2x faster directory enumeration than
        os.listdir() and skips non-.json entries without a stat() call.
        """
        now = time.time()
        if self._all_cache is not None and now - self._all_cache_time < 5.0:
            return self._all_cache

        records: List[TrustRecord] = []
        try:
            with os.scandir(self._dir) as it:
                for entry in it:
                    name = entry.name
                    if not name.endswith(".json") or name.endswith(".tmp"):
                        continue
                    # Prefer the cache: identical record and saves a file read.
                    key = name[:-5]  # strip .json
                    cached = self._cache.get(key)
                    if cached is not None:
                        records.append(cached)
                        continue
                    record = self._load_and_validate(entry.path)
                    if record is not None:
                        records.append(record)
        except OSError:
            pass
        records = sorted(records, key=lambda r: r.last_seen, reverse=True)
        self._all_cache = records
        self._all_cache_time = now
        return records

    def clear(self, exe_path: str) -> bool:
        """Remove the trust record for a specific executable. Returns True if removed."""
        key = self._key(exe_path)
        path = self._path(key)
        removed = False

        if key in self._cache:
            del self._cache[key]
            removed = True
        # Drop any stale negative-cache entry so the next get() re-checks disk.
        self._miss_cache.discard(key)

        # Attempt unlink directly; ENOENT is fine (file already gone).
        try:
            os.unlink(path)
            removed = True
        except FileNotFoundError:
            pass
        except OSError as e:
            logger.error("Failed to remove trust record %s: %s", path, e)

        # Invalidate get_all aggregate so the dashboard reflects the deletion.
        if removed:
            self._all_cache = None

        return removed

    @property
    def stats(self) -> dict:
        """Summary statistics for the trust history store."""
        records = self.get_all()
        return {
            "total_executables": len(records),
            "cached": len(self._cache),
            "trusted": sum(1 for r in records if r.reliability >= 0.9),
            "suspicious": sum(1 for r in records if r.reliability < 0.5),
            "total_runs": sum(r.total_runs for r in records),
            "total_quarantines": sum(r.quarantines for r in records),
        }
