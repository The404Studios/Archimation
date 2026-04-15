"""
Orchestrator -- executes cortex decisions by commanding lower layers.

Commands flow DOWN:
  - trust.ko via /dev/trust ioctl
  - PE processes via kill signals
  - Object broker via /run/pe-compat/objects.sock
  - SCM via /run/pe-compat/scm.sock
  - systemd via subprocess (systemctl)
  - Desktop via notify-send / xdotool
"""

import asyncio
import fcntl
import json
import logging
import os
import signal
import socket
import struct
import time
from typing import Dict, Optional

from .autonomy import AutonomyController, Decision, AutonomyLevel, Domain

logger = logging.getLogger("cortex.orchestrator")


# ---------------------------------------------------------------------------
# Trust ioctl constants -- must match trust_uapi.h
# ---------------------------------------------------------------------------

TRUST_IOC_MAGIC = 0x54  # 'T'

# ---------------------------------------------------------------------------
# Linux ioctl encoding: (direction << 30) | (size << 16) | (type << 8) | nr
#   _IOW  = direction 1 (write)
#   _IOR  = direction 2 (read)
#   _IOWR = direction 3 (read+write)
#   type  = 'T' = 0x54
#
# Computed from trust_ioctl.h definitions.
# ---------------------------------------------------------------------------

# TRUST_IOC_GET_SCORE = _IOWR('T', 2, trust_ioc_get_score_t)
#   trust_ioc_get_score_t: uint32_t subject_id + int32_t score = 8 bytes
#   (3 << 30) | (8 << 16) | (0x54 << 8) | 2 = 0xC008_5402
TRUST_IOC_GET_SCORE = 0xC0085402

# TRUST_IOC_REGISTER = _IOW('T', 10, trust_ioc_register_t)
#   trust_ioc_register_t: uint32_t subject_id + uint16_t domain + uint16_t _pad
#                         + uint32_t authority + int32_t initial_score = 16 bytes
#   (1 << 30) | (16 << 16) | (0x54 << 8) | 10 = 0x4010_540A
TRUST_IOC_REGISTER = 0x4010540A

# TRUST_IOC_TOKEN_BALANCE = _IOWR('T', 70, trust_ioc_token_balance_t)
#   trust_ioc_token_balance_t: uint32_t subject_id + int32_t balance
#                              + int32_t max_balance = 12 bytes
#   (3 << 30) | (12 << 16) | (0x54 << 8) | 70 = 0xC00C_5446
TRUST_IOC_TOKEN_BALANCE = 0xC00C5446

# TRUST_IOC_QUARANTINE = _IOWR('T', 96, trust_ioc_quarantine_t)
#   trust_ioc_quarantine_t: uint32_t subject_id + uint32_t reason
#                           + int32_t result = 12 bytes
#   (3 << 30) | (12 << 16) | (0x54 << 8) | 96 = 0xC00C_5460
TRUST_IOC_QUARANTINE = 0xC00C5460

# TRUST_IOC_RELEASE_QUARANTINE = _IOWR('T', 97, trust_ioc_release_quarantine_t)
#   trust_ioc_release_quarantine_t: uint32_t subject_id + int32_t result = 8 bytes
#   (3 << 30) | (8 << 16) | (0x54 << 8) | 97 = 0xC008_5461
TRUST_IOC_RELEASE_QUARANTINE = 0xC0085461

# Struct layouts (must match trust_ioctl.h)
#   get_score:     uint32_t subject_id (in), int32_t score (out)
SCORE_FORMAT = "<Ii"           # 8 bytes

#   register:      uint32_t subject_id, uint16_t domain, uint16_t _pad,
#                  uint32_t authority, int32_t initial_score
REGISTER_FORMAT = "<IHHIi"     # 16 bytes

#   token_balance: uint32_t subject_id (in), int32_t balance (out),
#                  int32_t max_balance (out)
BALANCE_FORMAT = "<Iii"        # 12 bytes

#   quarantine:    uint32_t subject_id, uint32_t reason, int32_t result (out)
QUARANTINE_FORMAT = "<IIi"     # 12 bytes

#   release_quarantine: uint32_t subject_id, int32_t result (out)
RELEASE_FORMAT = "<Ii"         # 8 bytes

# Trust domains (from trust_types.h)
TRUST_DOMAIN_AI = 2       # TRUST_DOMAIN_AI in trust_types.h
TRUST_AUTH_ADMIN = 3      # TRUST_AUTH_ADMIN in trust_types.h (highest non-kernel level)


# ---------------------------------------------------------------------------
# SCM command protocol
# ---------------------------------------------------------------------------

SCM_CMD_START = 1
SCM_CMD_STOP  = 2
SCM_CMD_QUERY = 3

# SCM command frame: uint8 cmd, uint8 name_len, char name[name_len]


# ---------------------------------------------------------------------------
# Result helpers
# ---------------------------------------------------------------------------

def _ok(msg: str = "ok", **extra) -> dict:
    result = {"success": True, "message": msg}
    result.update(extra)
    return result


def _fail(msg: str, **extra) -> dict:
    result = {"success": False, "error": msg}
    result.update(extra)
    return result


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class Orchestrator:
    """
    Executes cortex decisions by commanding lower layers.

    Every public method:
      1. Checks autonomy before executing
      2. Logs the action
      3. Handles errors gracefully
      4. Returns a success/failure dict
    """

    def __init__(
        self,
        autonomy: AutonomyController,
        trust_device: str = "/dev/trust",
        scm_socket: str = "/run/pe-compat/scm.sock",
        broker_socket: str = "/run/pe-compat/objects.sock",
    ):
        self._autonomy = autonomy
        self._trust_device = trust_device
        self._scm_socket = scm_socket
        self._broker_socket = broker_socket
        self._trust_fd: Optional[int] = None
        self._action_count: int = 0
        self._error_count: int = 0
        self._last_action_time: float = 0.0
        # Score-query cache: pid -> (score, expires_at_monotonic).  The
        # handle_pe_* paths call trust_get_score() on every event (thousands
        # per second under load); each call is a syscall.  A 500ms cache is
        # short enough that quarantine decisions stay responsive but long
        # enough to collapse bursts.
        self._score_cache: Dict[int, tuple] = {}
        self._SCORE_CACHE_TTL: float = 0.5

    # -- Trust device ---------------------------------------------------------

    def _open_trust_device(self) -> None:
        """Open /dev/trust for ioctl. Graceful degradation if absent."""
        if not os.path.exists(self._trust_device):
            logger.warning(
                "Trust device %s not found -- trust commands will be no-ops",
                self._trust_device,
            )
            return
        try:
            self._trust_fd = os.open(self._trust_device, os.O_RDWR)
            logger.info("Trust device opened: %s (fd=%d)", self._trust_device, self._trust_fd)
        except OSError as exc:
            logger.warning("Cannot open %s: %s -- trust commands will be no-ops",
                           self._trust_device, exc)
            self._trust_fd = None

    @property
    def trust_available(self) -> bool:
        return self._trust_fd is not None

    def _trust_ioctl(self, request: int, data: bytes) -> Optional[bytes]:
        """Issue an ioctl to /dev/trust. Returns response bytes or None on error."""
        if self._trust_fd is None:
            return None
        try:
            # Create a mutable buffer for ioctl
            buf = bytearray(data)
            fcntl.ioctl(self._trust_fd, request, buf)
            return bytes(buf)
        except OSError as exc:
            logger.error("Trust ioctl 0x%04x failed: %s", request, exc)
            self._error_count += 1
            return None

    # -- Autonomy check -------------------------------------------------------

    def _check_autonomy(self, domain: str, action: str, desc: str) -> Decision:
        """Create a decision and log the autonomy check."""
        decision = self._autonomy.create_decision(domain, action, desc)
        level = self._autonomy.effective_level(domain)
        try:
            level_name = AutonomyLevel(level).name
        except ValueError:
            level_name = f"LEVEL_{level}"

        if decision.approved is True:
            logger.info("ACT [%s] %s (level=%s, auto-approved)", domain, desc, level_name)
        elif decision.approved is None:
            logger.info("PENDING [%s] %s (level=%s, awaiting human)", domain, desc, level_name)
        else:
            logger.info("OBSERVE [%s] %s (level=%s, no action)", domain, desc, level_name)

        return decision

    def _record_action(self) -> None:
        """Record that an action was taken."""
        self._action_count += 1
        self._last_action_time = time.time()

    # =========================================================================
    # Process management
    # =========================================================================

    def kill_process(self, pid: int) -> dict:
        """Send SIGKILL to a process."""
        decision = self._check_autonomy(
            Domain.PROCESS, "kill", f"Kill process pid={pid}",
        )
        if not decision.approved:
            return _fail("not approved", decision_approved=decision.approved)

        try:
            os.kill(pid, signal.SIGKILL)
            self._record_action()
            logger.info("Killed pid=%d", pid)
            return _ok(f"SIGKILL sent to pid={pid}")
        except ProcessLookupError:
            return _fail(f"Process {pid} not found")
        except PermissionError:
            self._error_count += 1
            return _fail(f"Permission denied killing pid={pid}")

    def freeze_process(self, pid: int, force: bool = False) -> dict:
        """Send SIGSTOP to freeze (pause) a process.

        Args:
            pid: Process ID to freeze.
            force: If True, skip autonomy check (for security-critical freezes
                   such as immune alerts that must work even in OBSERVE mode).
        """
        if not force:
            decision = self._check_autonomy(
                Domain.PROCESS, "freeze", f"Freeze process pid={pid}",
            )
            if not decision.approved:
                return _fail("not approved", decision_approved=decision.approved)

        try:
            os.kill(pid, signal.SIGSTOP)
            self._record_action()
            logger.info("Froze pid=%d (SIGSTOP)", pid)
            return _ok(f"SIGSTOP sent to pid={pid}")
        except ProcessLookupError:
            return _fail(f"Process {pid} not found")
        except PermissionError:
            self._error_count += 1
            return _fail(f"Permission denied freezing pid={pid}")

    def unfreeze_process(self, pid: int) -> dict:
        """Send SIGCONT to resume a frozen process."""
        decision = self._check_autonomy(
            Domain.PROCESS, "unfreeze", f"Unfreeze process pid={pid}",
        )
        if not decision.approved:
            return _fail("not approved", decision_approved=decision.approved)

        try:
            os.kill(pid, signal.SIGCONT)
            self._record_action()
            logger.info("Unfroze pid=%d (SIGCONT)", pid)
            return _ok(f"SIGCONT sent to pid={pid}")
        except ProcessLookupError:
            return _fail(f"Process {pid} not found")
        except PermissionError:
            self._error_count += 1
            return _fail(f"Permission denied unfreezing pid={pid}")

    # -- Ungated signal helpers (approval follow-through) --------------------
    #
    # These bypass the autonomy gate because the human has ALREADY approved
    # (or denied) the underlying action via /decisions/{index}/approve|deny
    # -- running them through _check_autonomy would re-gate the very thing
    # the human just decided, and at OBSERVE level would leave the PE
    # process frozen forever.  See Session 25 follow-through wiring.

    def resume_after_approval(self, pid: int) -> dict:
        """SIGCONT a pid whose freeze was already approved by a human.

        Uses kill(pid, 0) first to check the process still exists -- it may
        have died while waiting.  Never raises: all errors are returned as
        failure dicts so a registered callback can be called without
        try/except at the call site.
        """
        if pid <= 0:
            return _fail(f"invalid pid={pid}")
        try:
            os.kill(pid, 0)  # existence probe
        except ProcessLookupError:
            logger.info("resume_after_approval: pid=%d already gone", pid)
            return _fail(f"Process {pid} not found", pid=pid)
        except PermissionError:
            logger.warning("resume_after_approval: permission denied probing pid=%d", pid)
            return _fail(f"Permission denied probing pid={pid}")

        try:
            os.kill(pid, signal.SIGCONT)
            self._record_action()
            logger.info("resume_after_approval: SIGCONT -> pid=%d", pid)
            return _ok(f"SIGCONT sent to pid={pid}", pid=pid)
        except ProcessLookupError:
            return _fail(f"Process {pid} vanished between probe and SIGCONT")
        except PermissionError:
            self._error_count += 1
            return _fail(f"Permission denied resuming pid={pid}")

    def kill_after_rejection(self, pid: int) -> dict:
        """SIGKILL a pid whose freeze was rejected by a human (or auto-expired).

        Sends SIGKILL directly.  (SIGCONT is NOT sent first because the
        kernel delivers SIGKILL to stopped processes -- the stop doesn't
        mask termination.)  Never raises.
        """
        if pid <= 0:
            return _fail(f"invalid pid={pid}")
        try:
            os.kill(pid, 0)  # existence probe
        except ProcessLookupError:
            logger.info("kill_after_rejection: pid=%d already gone", pid)
            return _ok(f"Process {pid} already gone", pid=pid, note="already-gone")
        except PermissionError:
            logger.warning("kill_after_rejection: permission denied probing pid=%d", pid)
            return _fail(f"Permission denied probing pid={pid}")

        try:
            os.kill(pid, signal.SIGKILL)
            self._record_action()
            logger.warning("kill_after_rejection: SIGKILL -> pid=%d", pid)
            return _ok(f"SIGKILL sent to pid={pid}", pid=pid)
        except ProcessLookupError:
            return _ok(f"Process {pid} exited before SIGKILL", pid=pid, note="already-gone")
        except PermissionError:
            self._error_count += 1
            return _fail(f"Permission denied killing pid={pid}")

    def set_priority(self, pid: int, nice: int) -> dict:
        """Set process scheduling priority (nice value)."""
        decision = self._check_autonomy(
            Domain.PROCESS, "priority", f"Set priority pid={pid} nice={nice}",
        )
        if not decision.approved:
            return _fail("not approved", decision_approved=decision.approved)

        nice = max(-20, min(19, nice))  # Clamp to valid range
        try:
            os.setpriority(os.PRIO_PROCESS, pid, nice)
            self._record_action()
            logger.info("Set priority pid=%d nice=%d", pid, nice)
            return _ok(f"Priority set: pid={pid} nice={nice}")
        except ProcessLookupError:
            return _fail(f"Process {pid} not found")
        except PermissionError:
            self._error_count += 1
            return _fail(f"Permission denied setting priority for pid={pid}")

    # =========================================================================
    # Trust commands (via /dev/trust ioctl)
    # =========================================================================

    def trust_quarantine(self, pid: int) -> dict:
        """Quarantine a process via trust.ko."""
        decision = self._check_autonomy(
            Domain.SECURITY, "quarantine", f"Trust quarantine pid={pid}",
        )
        if not decision.approved:
            return _fail("not approved", decision_approved=decision.approved)

        if not self.trust_available:
            logger.warning("Trust device unavailable -- quarantine is a no-op for pid=%d", pid)
            return _fail("trust device unavailable")

        data = struct.pack(QUARANTINE_FORMAT, pid, 0, 0)  # subject_id, reason=0, result=0
        result = self._trust_ioctl(TRUST_IOC_QUARANTINE, data)
        if result is not None:
            _, _, res = struct.unpack(QUARANTINE_FORMAT, result)
            if res < 0:
                return _fail(f"Quarantine denied for pid={pid} (result={res})")
            self._record_action()
            logger.info("Quarantined pid=%d via trust.ko", pid)
            return _ok(f"Quarantined pid={pid}")
        return _fail(f"Quarantine ioctl failed for pid={pid}")

    def trust_release(self, pid: int) -> dict:
        """Release a quarantined process via trust.ko."""
        decision = self._check_autonomy(
            Domain.SECURITY, "release", f"Trust release pid={pid}",
        )
        if not decision.approved:
            return _fail("not approved", decision_approved=decision.approved)

        if not self.trust_available:
            logger.warning("Trust device unavailable -- release is a no-op for pid=%d", pid)
            return _fail("trust device unavailable")

        data = struct.pack(RELEASE_FORMAT, pid, 0)  # subject_id, result=0
        result = self._trust_ioctl(TRUST_IOC_RELEASE_QUARANTINE, data)
        if result is not None:
            _, res = struct.unpack(RELEASE_FORMAT, result)
            if res < 0:
                return _fail(f"Release denied for pid={pid} (result={res})")
            self._record_action()
            logger.info("Released pid=%d via trust.ko", pid)
            return _ok(f"Released pid={pid}")
        return _fail(f"Release ioctl failed for pid={pid}")

    def trust_get_balance(self, pid: int) -> dict:
        """Query token balance for a process via trust.ko."""
        decision = self._check_autonomy(
            Domain.TRUST, "get_balance", f"Get balance pid={pid}",
        )
        if not decision.approved:
            return _fail("not approved", decision_approved=decision.approved)

        if not self.trust_available:
            return _fail("trust device unavailable")

        # TOKEN_BALANCE is a query ioctl; we use it to read balance/max.
        # There is no dedicated "set budget" ioctl in trust_ioctl.h --
        # the token economy is managed via TOKEN_BURN / TOKEN_XFER.
        # We query the current balance instead.
        data = struct.pack(BALANCE_FORMAT, pid, 0, 0)  # subject_id, balance=0, max=0
        result = self._trust_ioctl(TRUST_IOC_TOKEN_BALANCE, data)
        if result is not None:
            _, balance, max_balance = struct.unpack(BALANCE_FORMAT, result)
            self._record_action()
            logger.info("Token balance pid=%d: %d/%d", pid, balance, max_balance)
            return _ok(
                f"Token balance for pid={pid}: {balance}/{max_balance}",
                balance=balance, max_balance=max_balance,
            )
        return _fail(f"Token balance ioctl failed for pid={pid}")

    def trust_get_score(self, pid: int) -> dict:
        """Query trust score for a process via trust.ko.

        Results are cached for `_SCORE_CACHE_TTL` seconds per-pid so a burst
        of handlers (pe_load + trust_deny + memory_anomaly) all touching the
        same process don't each issue a separate ioctl syscall.
        """
        # Score queries are read-only, no autonomy check needed
        if not self.trust_available:
            return _fail("trust device unavailable")

        # Cache lookup -- cache hits skip the syscall entirely.
        now = time.monotonic()
        cached = self._score_cache.get(pid)
        if cached is not None:
            score, expires = cached
            if now < expires:
                return _ok(f"Score for pid={pid}: {score}", pid=pid, score=score)

        data = struct.pack(SCORE_FORMAT, pid, 0)  # subject_id, score=0 (output)
        result = self._trust_ioctl(TRUST_IOC_GET_SCORE, data)
        if result is not None:
            _, score = struct.unpack(SCORE_FORMAT, result)
            self._score_cache[pid] = (score, now + self._SCORE_CACHE_TTL)
            # Bound cache size to prevent growth with many short-lived pids.
            if len(self._score_cache) > 4096:
                # Evict expired/oldest entries.  Simple sweep -- amortised O(1).
                self._score_cache = {
                    p: (s, exp)
                    for p, (s, exp) in self._score_cache.items()
                    if exp > now
                }
            return _ok(f"Score for pid={pid}: {score}", pid=pid, score=score)
        return _fail(f"Get score ioctl failed for pid={pid}")

    def invalidate_score_cache(self, pid: Optional[int] = None) -> None:
        """Drop cached trust scores. Called by score-change handlers.

        Pass pid=None to drop all cached entries (e.g. after quarantine,
        which changes trust scores in a way we can't predict).
        """
        if pid is None:
            self._score_cache.clear()
        else:
            self._score_cache.pop(pid, None)

    def trust_register_cortex(
        self,
        subject_id: int = 0,
        initial_score: int = 50,
    ) -> dict:
        """Register the cortex itself as trust subject 0."""
        if not self.trust_available:
            logger.info("Trust device unavailable -- skipping cortex registration")
            return _fail("trust device unavailable")

        # trust_ioc_register_t: subject_id, domain (u16), _pad (u16),
        #                       authority, initial_score
        data = struct.pack(
            REGISTER_FORMAT,
            subject_id,
            TRUST_DOMAIN_AI,   # uint16_t domain
            0,                 # uint16_t _padding
            TRUST_AUTH_ADMIN, # uint32_t authority
            initial_score,     # int32_t initial_score
        )
        result = self._trust_ioctl(TRUST_IOC_REGISTER, data)
        if result is not None:
            logger.info(
                "Cortex registered as trust subject %d (domain=AI, auth=SYSTEM, "
                "initial_score=%d)",
                subject_id, initial_score,
            )
            return _ok("Cortex registered with trust system")
        return _fail("Failed to register cortex with trust system")

    # =========================================================================
    # Service management (via SCM Unix socket)
    # =========================================================================

    def _scm_command(self, cmd: int, name: str) -> dict:
        """Send a command to the SCM daemon via Unix socket."""
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)
                sock.connect(self._scm_socket)

                name_bytes = name.encode("utf-8")[:255]
                frame = struct.pack("BB", cmd, len(name_bytes)) + name_bytes
                sock.sendall(frame)

                # Read response: uint8 status, uint16 msg_len, char msg[msg_len]
                resp_header = sock.recv(3)
                if len(resp_header) < 3:
                    return _fail("SCM: incomplete response")

                status, msg_len = struct.unpack("<BH", resp_header)
                if msg_len > 65000:  # Reasonable max response size
                    logger.error("SCM response too large: %d bytes", msg_len)
                    return _fail("SCM response too large")
                msg_data = b""
                while len(msg_data) < msg_len:
                    chunk = sock.recv(msg_len - len(msg_data))
                    if not chunk:
                        raise ConnectionError("SCM connection closed")
                    msg_data += chunk

                msg_str = msg_data.decode("utf-8", errors="replace")
                if status == 0:
                    return _ok(msg_str)
                return _fail(msg_str)

        except FileNotFoundError:
            return _fail(f"SCM socket not found: {self._scm_socket}")
        except ConnectionRefusedError:
            return _fail("SCM daemon not running")
        except socket.timeout:
            return _fail("SCM command timed out")
        except OSError as exc:
            self._error_count += 1
            return _fail(f"SCM socket error: {exc}")

    async def scm_start_service(self, name: str) -> dict:
        """Start a service via the SCM daemon."""
        decision = self._check_autonomy(
            Domain.SERVICE, "svc_start", f"Start service: {name}",
        )
        if not decision.approved:
            return _fail("not approved", decision_approved=decision.approved)

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, self._scm_command, SCM_CMD_START, name)
        if result["success"]:
            self._record_action()
            logger.info("Started service: %s", name)
        else:
            logger.error("Failed to start service %s: %s", name, result.get("error"))
        return result

    async def scm_stop_service(self, name: str) -> dict:
        """Stop a service via the SCM daemon."""
        decision = self._check_autonomy(
            Domain.SERVICE, "svc_stop", f"Stop service: {name}",
        )
        if not decision.approved:
            return _fail("not approved", decision_approved=decision.approved)

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, self._scm_command, SCM_CMD_STOP, name)
        if result["success"]:
            self._record_action()
            logger.info("Stopped service: %s", name)
        else:
            logger.error("Failed to stop service %s: %s", name, result.get("error"))
        return result

    async def scm_query_service(self, name: str) -> dict:
        """Query service status via the SCM daemon."""
        # Queries are read-only, no autonomy gate
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._scm_command, SCM_CMD_QUERY, name)

    # =========================================================================
    # Desktop notifications
    # =========================================================================

    async def notify(
        self,
        title: str,
        message: str,
        urgency: str = "normal",
    ) -> dict:
        """Send a desktop notification via notify-send."""
        if urgency not in ("low", "normal", "critical"):
            urgency = "normal"

        proc = None
        try:
            env = os.environ.copy()
            env.setdefault("DISPLAY", ":0")
            proc = await asyncio.create_subprocess_exec(
                "notify-send",
                "--urgency", urgency,
                "--app-name", "AI Cortex",
                "--icon", "dialog-information",
                title,
                message,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            if proc.returncode == 0:
                return _ok("Notification sent")
            err_msg = stderr.decode(errors="replace").strip()
            logger.debug("notify-send failed: %s", err_msg)
            return _fail(f"notify-send failed: {err_msg}")
        except FileNotFoundError:
            return _fail("notify-send not installed")
        except asyncio.TimeoutError:
            if proc is not None:
                proc.kill()
                await proc.wait()
            return _fail("notify-send timed out")

    async def notify_decision(self, decision: Decision) -> dict:
        """Format a decision as a user-friendly notification."""
        try:
            level_name = AutonomyLevel(decision.autonomy_level).name
        except ValueError:
            level_name = f"LEVEL_{decision.autonomy_level}"

        if decision.approved is None:
            title = "Approval Needed"
            urgency = "critical"
            body = (
                f"Action: {decision.action}\n"
                f"Domain: {decision.domain}\n"
                f"Level: {level_name}\n"
                f"{decision.description}\n\n"
                "Use 'ai-cortex --pending' to approve/deny."
            )
        elif decision.approved:
            title = "Action Taken"
            urgency = "normal"
            body = (
                f"Action: {decision.action}\n"
                f"Domain: {decision.domain}\n"
                f"{decision.description}"
            )
        else:
            title = "Action Blocked"
            urgency = "low"
            body = (
                f"Action: {decision.action}\n"
                f"Domain: {decision.domain}\n"
                f"{decision.description}\n"
                "Autonomy level too low to act."
            )

        return await self.notify(title, body, urgency)

    # =========================================================================
    # System commands
    # =========================================================================

    # Commands that are NEVER allowed autonomously.  These require human
    # approval regardless of autonomy level (checked before autonomy gate).
    BLOCKED_COMMANDS = frozenset({
        "rm", "mkfs", "dd", "shred", "wipefs",          # destructive filesystem
        "iptables", "ip6tables", "nft", "nftables",      # firewall manipulation
        "shutdown", "reboot", "poweroff", "halt", "init", # power state
        "passwd", "usermod", "useradd", "userdel",        # identity changes
        "chmod", "chown",                                 # permission changes
        "mount", "umount",                                # mount operations
        "modprobe", "rmmod", "insmod",                    # kernel module loading
        "sysctl",                                         # kernel parameter changes
    })

    async def run_command(self, cmd: list[str], timeout: int = 30) -> dict:
        """
        Run a command as a subprocess. Uses exec, NOT shell.

        Dangerous commands (rm, mkfs, dd, iptables, shutdown, etc.) are
        blocked outright.  See BLOCKED_COMMANDS.

        Args:
            cmd: Command as a list of strings (e.g. ["ls", "-la"]).
            timeout: Maximum seconds to wait.

        Returns:
            Dict with success, returncode, stdout, stderr.
        """
        if not cmd:
            return _fail("empty command")

        # Extract the base command name (strip path prefix)
        base_cmd = os.path.basename(cmd[0])

        if base_cmd in self.BLOCKED_COMMANDS:
            logger.warning(
                "BLOCKED dangerous command: %s (base=%s)", cmd, base_cmd,
            )
            return _fail(
                f"Command '{base_cmd}' is on the blocked list and cannot "
                f"be run autonomously. Use the system shell directly.",
                blocked=True,
            )

        # Block kill on PID 0 or 1
        if base_cmd == "kill" and any(a in ("0", "1") for a in cmd[1:]):
            logger.warning("BLOCKED kill on critical PID: %s", cmd)
            return _fail("Cannot kill PID 0 or 1", blocked=True)

        decision = self._check_autonomy(
            Domain.SYSTEM_CONFIG, "run_command",
            f"Run command: {' '.join(cmd[:3])}{'...' if len(cmd) > 3 else ''}",
        )
        if not decision.approved:
            return _fail("not approved", decision_approved=decision.approved)

        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout,
            )
            self._record_action()
            return {
                "success": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": stdout.decode(errors="replace"),
                "stderr": stderr.decode(errors="replace"),
            }
        except FileNotFoundError:
            return _fail(f"Command not found: {cmd[0]}")
        except asyncio.TimeoutError:
            if proc is not None:
                proc.kill()
                await proc.wait()
            self._error_count += 1
            return _fail(f"Command timed out after {timeout}s")

    async def systemctl(self, action: str, unit: str) -> dict:
        """Manage a systemd unit (start, stop, restart, enable, disable, status)."""
        valid_actions = {"start", "stop", "restart", "enable", "disable", "status",
                         "reload", "is-active", "is-enabled"}
        if action not in valid_actions:
            return _fail(f"Invalid systemctl action: {action}")

        # Read-only actions skip autonomy check
        read_only = action in {"status", "is-active", "is-enabled"}

        if not read_only:
            decision = self._check_autonomy(
                Domain.SERVICE, f"systemctl_{action}",
                f"systemctl {action} {unit}",
            )
            if not decision.approved:
                return _fail("not approved", decision_approved=decision.approved)

        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "systemctl", action, unit,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)

            if not read_only:
                self._record_action()

            return {
                "success": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": stdout.decode(errors="replace"),
                "stderr": stderr.decode(errors="replace"),
            }
        except FileNotFoundError:
            return _fail("systemctl not found")
        except asyncio.TimeoutError:
            if proc is not None:
                proc.kill()
                await proc.wait()
            self._error_count += 1
            return _fail(f"systemctl {action} {unit} timed out")

    # =========================================================================
    # Cleanup
    # =========================================================================

    def close(self) -> None:
        """Release resources."""
        if self._trust_fd is not None:
            try:
                os.close(self._trust_fd)
            except OSError:
                pass
            self._trust_fd = None
            logger.info("Trust device closed")

    # =========================================================================
    # Introspection
    # =========================================================================

    @property
    def stats(self) -> dict:
        """Return orchestrator statistics."""
        return {
            "trust_available": self.trust_available,
            "trust_device": self._trust_device,
            "scm_socket": self._scm_socket,
            "actions_executed": self._action_count,
            "errors": self._error_count,
            "last_action_time": self._last_action_time,
        }
