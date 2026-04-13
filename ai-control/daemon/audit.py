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

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional, Callable

logger = logging.getLogger("ai-control.audit")

AUDIT_LOG_DIR = "/var/log/ai-control"
AUDIT_LOG_FILE = os.path.join(AUDIT_LOG_DIR, "audit.jsonl")


class AuditLogger:
    """Append-only audit log with WebSocket push support."""

    def __init__(
        self,
        log_file: str = AUDIT_LOG_FILE,
        ws_callback: Optional[Callable] = None,
    ):
        self._log_file = log_file
        self._ws_callback = ws_callback
        self._fd = None
        self._init_log()

    def _init_log(self):
        """Create log directory and open the audit file."""
        try:
            os.makedirs(os.path.dirname(self._log_file), exist_ok=True)
            self._fd = open(self._log_file, "a", buffering=1)  # Line-buffered
            logger.info("Audit log opened: %s", self._log_file)
        except OSError:
            logger.warning("Cannot open audit log at %s", self._log_file)
            self._fd = None

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

        # Write to file
        if self._fd:
            try:
                self._fd.write(json.dumps(entry, separators=(",", ":")) + "\n")
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

    def get_recent(self, count: int = 50) -> list[dict]:
        """Return the most recent audit entries (reads from end of file)."""
        if not self._log_file or not os.path.exists(self._log_file):
            return []
        try:
            entries = []
            with open(self._log_file, "rb") as f:
                # Seek from end to find last N newlines
                f.seek(0, 2)  # end of file
                size = f.tell()
                if size == 0:
                    return []
                # Read chunks from end until we have enough lines
                chunk_size = min(8192, size)
                lines = []
                pos = size
                while pos > 0 and len(lines) <= count:
                    read_size = min(chunk_size, pos)
                    pos -= read_size
                    f.seek(pos)
                    chunk = f.read(read_size)
                    lines = chunk.split(b"\n") + lines
                # Take last count non-empty lines
                for line in lines[-(count+1):]:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            return entries[-count:]
        except Exception:
            return []

    def __del__(self):
        self.close()

    def close(self):
        """Close the audit log file."""
        if self._fd:
            self._fd.close()
            self._fd = None
