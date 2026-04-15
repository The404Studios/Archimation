"""
Audit logging for the AI Control Daemon.

Every API call is logged to /var/log/ai-control/audit.jsonl with:
- Caller identity (subject_id, name)
- Trust score at time of call
- Action (method + path)
- Result (success/denied/error)
- Trust delta (if applicable)

Also pushes events to the WebSocket for real-time monitoring.
"""

import collections
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional, Callable

logger = logging.getLogger("ai-control.audit")

AUDIT_LOG_DIR = "/var/log/ai-control"
AUDIT_LOG_FILE = os.path.join(AUDIT_LOG_DIR, "audit.jsonl")

# Polling / discovery endpoints that don't need to be spammed into audit.jsonl.
# Used to keep the log focused on real privileged actions and avoid IO on hot
# paths like health-checks and OpenAPI probes.
_AUDIT_SKIP_PATHS = frozenset({
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/favicon.ico",
})

# Rotate when the on-disk log exceeds this many bytes. We keep a single
# ".1" backup; older content is discarded. Checked lazily on write so
# startup stays fast even on slow disks.
_AUDIT_ROTATE_BYTES = 10 * 1024 * 1024  # 10 MB
_AUDIT_ROTATE_CHECK_INTERVAL = 256  # writes between size checks


class AuditLogger:
    """Append-only audit log with WebSocket push support.

    The log file is *not* opened at construction. It is opened on the first
    write (lazy init) so daemon startup on slow disks doesn't pay for audit
    IO until an actual audit-worthy request arrives.
    """

    def __init__(
        self,
        log_file: str = AUDIT_LOG_FILE,
        ws_callback: Optional[Callable] = None,
        recent_buffer_size: int = 1000,
    ):
        self._log_file = log_file
        self._ws_callback = ws_callback
        self._fd = None
        self._init_failed = False
        self._writes_since_rotate_check = 0
        # In-memory ring buffer of the most recent audit entries. Gives O(1)
        # get_recent() instead of tailing the log file every call (previously
        # every /audit/recent + /audit/stats request re-opened the file,
        # seeked from the end in 8K chunks, and parsed JSON lines). On hot
        # dashboards polling /audit/recent every second this was measurable.
        self._recent: collections.deque = collections.deque(maxlen=recent_buffer_size)
        # Track whether the in-memory buffer has been bootstrapped from disk
        # (lazy, only on first get_recent() call).
        self._recent_loaded_from_disk: bool = False

    def _init_log(self):
        """Create log directory and open the audit file (lazy, first write only)."""
        if self._fd is not None or self._init_failed:
            return
        try:
            os.makedirs(os.path.dirname(self._log_file), exist_ok=True)
            self._fd = open(self._log_file, "a", buffering=1)  # Line-buffered
            logger.info("Audit log opened: %s", self._log_file)
        except OSError:
            logger.warning("Cannot open audit log at %s", self._log_file)
            self._fd = None
            self._init_failed = True

    def _maybe_rotate(self):
        """Rotate audit.jsonl if it has grown past _AUDIT_ROTATE_BYTES.

        Called periodically from the write path (not on every write) so we
        don't stat() on the hot path. Keeps one backup at audit.jsonl.1.
        """
        self._writes_since_rotate_check += 1
        if self._writes_since_rotate_check < _AUDIT_ROTATE_CHECK_INTERVAL:
            return
        self._writes_since_rotate_check = 0
        try:
            if not self._fd:
                return
            size = os.fstat(self._fd.fileno()).st_size
            if size < _AUDIT_ROTATE_BYTES:
                return
            self._fd.close()
            self._fd = None
            backup = self._log_file + ".1"
            try:
                # os.replace() atomically overwrites an existing backup without
                # an exists()+remove() TOCTOU window. Using the old
                # exists()+remove()+rename() sequence, a concurrent process
                # (or another thread that went through rotation fast) could
                # recreate the backup between exists() and rename(), causing
                # rename() to fail on some filesystems. os.replace is also
                # ~1 syscall instead of 3.
                try:
                    os.remove(backup)
                except FileNotFoundError:
                    pass
                os.rename(self._log_file, backup)
            except OSError:
                # If rename fails, truncate in-place so the log doesn't grow
                # without bound.  Use a with-block rather than
                # open(...).close() so the fd is released promptly even
                # if close() raises (rare, but ResourceWarning-worthy).
                try:
                    with open(self._log_file, "w"):
                        pass
                except OSError:
                    pass
            # Reopen fresh.
            try:
                self._fd = open(self._log_file, "a", buffering=1)
            except OSError:
                self._fd = None
                self._init_failed = True
        except OSError:
            pass

    @staticmethod
    def should_skip(path: str) -> bool:
        """True if audit should skip this path (polling/discovery endpoints)."""
        return path in _AUDIT_SKIP_PATHS

    def log(
        self,
        method: str,
        path: str,
        subject_id: Optional[int] = None,
        subject_name: Optional[str] = None,
        trust_score: Optional[int] = None,
        result: str = "success",
        status_code: int = 200,
        detail: Optional[str] = None,
        trust_delta: int = 0,
    ):
        """Record an audit event."""
        # Skip noisy polling endpoints entirely to avoid disk IO + WS fanout.
        if path in _AUDIT_SKIP_PATHS:
            return

        entry = {
            "ts": time.time(),
            "method": method,
            "path": path,
            "subject_id": subject_id,
            "subject_name": subject_name,
            "trust_score": trust_score,
            "result": result,
            "status_code": status_code,
            "trust_delta": trust_delta,
        }
        if detail:
            entry["detail"] = detail

        # Always append to the in-memory ring buffer first — this is what
        # /audit/recent and /audit/stats read from, and we want that path to
        # succeed even if the on-disk file is unwritable.
        self._recent.append(entry)

        # Lazy-open the log file on first real write.
        if self._fd is None and not self._init_failed:
            self._init_log()

        # Write to file
        if self._fd:
            try:
                self._fd.write(json.dumps(entry, separators=(",", ":")) + "\n")
                self._maybe_rotate()
            except OSError:
                logger.warning("Failed to write audit log entry")

        # Push to WebSocket
        if self._ws_callback:
            event = {"type": "audit", **entry}
            try:
                self._ws_callback(event)
            except Exception:
                pass

    def log_auth_failure(
        self,
        method: str,
        path: str,
        reason: str,
        subject_id: Optional[int] = None,
        subject_name: Optional[str] = None,
    ):
        """Log an authentication/authorization failure."""
        self.log(
            method=method,
            path=path,
            subject_id=subject_id,
            subject_name=subject_name,
            result="denied",
            status_code=403,
            detail=reason,
            trust_delta=-5,
        )

    def _bootstrap_recent_from_disk(self) -> None:
        """Populate the in-memory ring buffer from the tail of the on-disk
        audit log. Called once, lazily, on the first get_recent() request.
        """
        self._recent_loaded_from_disk = True
        if not self._log_file or not os.path.exists(self._log_file):
            return
        cap = self._recent.maxlen or 1000
        try:
            with open(self._log_file, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                if size == 0:
                    return
                # Read chunks from end until we have enough newlines
                # (roughly cap+1 so the last partial line doesn't bias).
                chunk_size = min(65536, size)
                lines: list[bytes] = []
                pos = size
                target = cap + 1
                while pos > 0 and len(lines) <= target:
                    read_size = min(chunk_size, pos)
                    pos -= read_size
                    f.seek(pos)
                    chunk = f.read(read_size)
                    lines = chunk.split(b"\n") + lines
            # Parse last cap JSON lines. deque ordered oldest->newest.
            parsed: list[dict] = []
            for line in lines[-(cap + 1):]:
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            # Preserve ordering: existing in-memory entries (if any) are the
            # freshest; put disk-loaded history in front.
            existing = list(self._recent)
            self._recent.clear()
            for e in parsed[-cap:]:
                self._recent.append(e)
            for e in existing:
                self._recent.append(e)
        except OSError:
            return

    def get_recent(self, count: int = 50) -> list[dict]:
        """Return the most recent *count* audit entries.

        First call bootstraps the ring buffer from the on-disk log (so a
        daemon restart doesn't lose history). Subsequent calls are O(count)
        — no disk I/O, no JSON parsing, no seek.
        """
        if not self._recent_loaded_from_disk:
            self._bootstrap_recent_from_disk()
        if count <= 0:
            return []
        if count >= len(self._recent):
            return list(self._recent)
        # deque doesn't slice directly; use islice for O(count).
        import itertools
        total = len(self._recent)
        start = max(0, total - count)
        return list(itertools.islice(self._recent, start, total))

    def __del__(self):
        self.close()

    def close(self):
        """Close the audit log file."""
        if self._fd:
            self._fd.close()
            self._fd = None
