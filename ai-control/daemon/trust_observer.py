"""
Trust Observer - AI-driven trust monitoring and adaptive control.

Implements the "AI Observer & Adaptive Threshold Control" component from
the Root of Trust architecture. Monitors trust state changes, detects
anomalies (oscillation / "shaking objects"), classifies risk tiers,
and dynamically adjusts trust thresholds.

Communicates with the kernel trust module via /dev/trust ioctl or
falls back to polling /proc/trust/* if available.
"""

import asyncio
import ctypes
import ctypes.util
import fcntl
import logging
import os
import struct
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional, Callable

logger = logging.getLogger("ai-control.trust")

# ── Trust constants (must match trust_types.h) ──

TRUST_DOMAIN_LINUX = 0
TRUST_DOMAIN_WIN32 = 1
TRUST_DOMAIN_AI = 2
TRUST_DOMAIN_SERVICE = 3

TRUST_AUTH_NONE = 0
TRUST_AUTH_USER = 1
TRUST_AUTH_SERVICE = 2
TRUST_AUTH_ADMIN = 3
TRUST_AUTH_KERNEL = 4

TRUST_SCORE_MIN = -1000
TRUST_SCORE_MAX = 1000
TRUST_SCORE_DEFAULT = 200

TRUST_RESULT_ALLOW = 0
TRUST_RESULT_DENY = 1
TRUST_RESULT_ESCALATE = 2

TRUST_FLAG_FROZEN = 1 << 0
TRUST_FLAG_OBSERVED = 1 << 1
TRUST_FLAG_ESCALATING = 1 << 2
TRUST_FLAG_DECAYING = 1 << 3
TRUST_FLAG_NEW = 1 << 4
TRUST_FLAG_APOPTOTIC = 1 << 5
TRUST_FLAG_CANCEROUS = 1 << 6
TRUST_FLAG_MEIOTIC = 1 << 7

# Root of Authority: Immune status constants
TRUST_IMMUNE_HEALTHY = 0
TRUST_IMMUNE_SUSPICIOUS = 1
TRUST_IMMUNE_CANCEROUS = 2
TRUST_IMMUNE_APOPTOSIS = 3
TRUST_IMMUNE_QUARANTINED = 4

# Root of Authority: XY Sex Determination
CHROMO_SEX_XX = 0  # Conformant: maintain
CHROMO_SEX_XY = 1  # Behavioral divergence: demote
CHROMO_SEX_YX = 2  # Construction divergence: promote
CHROMO_SEX_YY = 3  # Strongly divergent: apoptosis candidate

# Root of Authority: Lifecycle states
TRUST_LIFECYCLE_EMBRYONIC = 0
TRUST_LIFECYCLE_ACTIVE = 1
TRUST_LIFECYCLE_DIVIDING = 2
TRUST_LIFECYCLE_COMBINING = 3
TRUST_LIFECYCLE_SENESCENT = 4
TRUST_LIFECYCLE_APOPTOTIC = 5
TRUST_LIFECYCLE_NECROTIC = 6

# Root of Authority: TRC states
TRUST_TRC_NORMAL = 0
TRUST_TRC_ELEVATED = 1
TRUST_TRC_LOCKDOWN = 2
TRUST_TRC_PERMISSIVE = 3


# ── ioctl numbers (must match trust_ioctl.h, magic 'T') ──

def _IOC(direction, magic, nr, size):
    return (direction << 30) | (size << 16) | (ord(magic) << 8) | nr

_IOC_WRITE = 1
_IOC_READ = 2
_IOC_READWRITE = 3

TRUST_IOC_CHECK_CAP = _IOC(_IOC_READWRITE, 'T', 1, 16)  # sizeof(trust_ioc_check_cap_t) = 16 (includes _padding)
TRUST_IOC_GET_SCORE = _IOC(_IOC_READWRITE, 'T', 2, 8)
TRUST_IOC_RECORD_ACTION = _IOC(_IOC_READWRITE, 'T', 3, 16)
TRUST_IOC_GET_SUBJECT = _IOC(_IOC_READWRITE, 'T', 20, 504)  # sizeof trust_ioc_get_subject_t (4 + 4pad + 496)

# Escalation queue ioctls
# trust_ioc_escalation_poll_t: u32 subject_id, u32 auth, char[128] just,
#   u64 ts, i32 score, u32 seq, i32 has_pending, 4 bytes trailing padding
# = 4+4+128+8+4+4+4+4(pad) = 160 bytes (alignment to uint64_t)
TRUST_IOC_ESCALATION_POLL = _IOC(_IOC_READ, 'T', 50, 160)
# trust_ioc_escalation_respond_t: u32 seq, u32 approved = 8 bytes
TRUST_IOC_ESCALATION_RESPOND = _IOC(_IOC_WRITE, 'T', 51, 8)

# Root of Authority ioctls
# Token balance: u32 subject_id, i32 balance, i32 max_balance = 12 bytes
TRUST_IOC_TOKEN_BALANCE = _IOC(_IOC_READWRITE, 'T', 70, 12)
# Immune status: u32 subject_id, u8 status, u8[3] pad, u32 suspicious, i32 result = 16 bytes
TRUST_IOC_IMMUNE_STATUS = _IOC(_IOC_READWRITE, 'T', 95, 16)
# Quarantine: u32 subject_id, u32 reason, i32 result = 12 bytes
TRUST_IOC_QUARANTINE = _IOC(_IOC_READWRITE, 'T', 96, 12)
# Release quarantine: u32 subject_id, i32 result = 8 bytes
TRUST_IOC_RELEASE_QUARANTINE = _IOC(_IOC_READWRITE, 'T', 97, 8)
# Apoptosis: u32 subject_id, i32 result = 8 bytes
TRUST_IOC_APOPTOSIS = _IOC(_IOC_READWRITE, 'T', 83, 8)
# Get sex: u32 subject_id, u8 sex, u8[3] pad, i32 result = 12 bytes
TRUST_IOC_GET_SEX = _IOC(_IOC_READWRITE, 'T', 91, 12)


class RiskTier(IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class TrustSnapshot:
    """A point-in-time capture of a subject's trust state."""
    subject_id: int
    score: int
    timestamp: float
    direction: int = 0  # +1 rising, -1 falling, 0 stable


@dataclass
class SubjectProfile:
    """Accumulated trust profile for a monitored subject."""
    subject_id: int
    domain: int = TRUST_DOMAIN_LINUX
    risk_tier: RiskTier = RiskTier.LOW
    history: deque = field(default_factory=lambda: deque(maxlen=100))
    direction_changes: deque = field(default_factory=lambda: deque(maxlen=20))
    last_score: int = TRUST_SCORE_DEFAULT
    frozen: bool = False
    anomaly_count: int = 0
    score_sum: float = 0.0
    score_count: int = 0

    # Root of Authority fields
    immune_status: int = TRUST_IMMUNE_HEALTHY
    sex: int = CHROMO_SEX_XX
    lifecycle_state: int = TRUST_LIFECYCLE_ACTIVE
    token_balance: int = 1000
    token_max: int = 1000
    generation: int = 0
    parent_id: int = 0
    trc_state: int = TRUST_TRC_NORMAL

    @property
    def avg_score(self) -> float:
        return self.score_sum / self.score_count if self.score_count else TRUST_SCORE_DEFAULT


class TrustObserver:
    """
    Watches trust score changes and applies adaptive control.

    Three main responsibilities:
    1. Shaking Object Detection — rapid trust oscillation triggers freeze
    2. Risk Classification — assigns LOW/MEDIUM/HIGH/CRITICAL tiers
    3. Adaptive Thresholds — adjusts per-subject thresholds based on behavior
    """

    def __init__(
        self,
        dev_path: str = "/dev/trust",
        poll_interval: float = 1.0,
        oscillation_window: float = 10.0,
        oscillation_threshold: int = 4,
        freeze_duration: float = 30.0,
    ):
        self._dev_path = dev_path
        self._fd: Optional[int] = None
        self._poll_interval = poll_interval
        self._oscillation_window = oscillation_window
        self._oscillation_threshold = oscillation_threshold
        self._freeze_duration = freeze_duration

        self._profiles: dict[int, SubjectProfile] = {}
        self._event_callbacks: list[Callable] = []
        self._running = False
        self._task: Optional[asyncio.Task] = None

        # Freeze timers: subject_id -> unfreeze_at timestamp
        self._freeze_timers: dict[int, float] = {}

    # ── Lifecycle ──

    def start(self):
        """Open /dev/trust and start the monitoring loop."""
        try:
            self._fd = os.open(self._dev_path, os.O_RDWR)
            logger.info("Trust observer connected to %s", self._dev_path)
        except OSError:
            self._fd = None
            logger.warning(
                "Cannot open %s — trust observer running in passive mode",
                self._dev_path,
            )

    async def start_async(self):
        """Start the async monitoring loop."""
        self.start()
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())
        logger.info("Trust observer monitoring started (interval=%.1fs)", self._poll_interval)

    async def stop(self):
        """Stop monitoring and close /dev/trust."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        logger.info("Trust observer stopped")

    def add_event_callback(self, cb: Callable):
        """Register a callback for trust events (score changes, freezes, etc.)."""
        self._event_callbacks.append(cb)

    # ── Core monitoring loop ──

    async def _monitor_loop(self):
        """Periodically poll known subjects, check for anomalies, and process escalation requests."""
        loop = asyncio.get_running_loop()
        while self._running:
            try:
                # Run blocking ioctl calls in executor to avoid blocking the event loop
                await loop.run_in_executor(None, self._poll_subjects_sync)
                self._check_unfreeze()
                await loop.run_in_executor(None, self._process_escalation_queue)
                await asyncio.sleep(self._poll_interval)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in trust monitor loop")
                await asyncio.sleep(self._poll_interval)

    def _poll_subjects_sync(self):
        """Read current scores and RoA state for all tracked subjects (blocking ioctl)."""
        for sid in list(self._profiles.keys()):
            score = self._read_score(sid)
            if score is not None:
                self._update_subject(sid, score)

            # Update Root of Authority state (immune, tokens, sex)
            profile = self._profiles.get(sid)
            if profile:
                self._update_roa_state(profile)

    def _read_score(self, subject_id: int) -> Optional[int]:
        """Read a subject's trust score via ioctl."""
        if self._fd is None:
            return None

        # struct trust_ioc_get_score_t { uint32_t subject_id; int32_t score; }
        buf = struct.pack("=Ii", subject_id, 0)
        try:
            result = fcntl.ioctl(self._fd, TRUST_IOC_GET_SCORE, buf)
            _, score = struct.unpack("=Ii", result)
            return score
        except OSError:
            return None

    # ── Subject tracking ──

    # Cap tracked subjects to prevent unbounded growth when short-lived
    # PE processes repeatedly register without matching unregister.
    MAX_TRACKED_SUBJECTS = 4096

    def register_subject(self, subject_id: int, domain: int = TRUST_DOMAIN_LINUX):
        """Start tracking a subject.

        Uses dict-insertion-order as an implicit LRU: the first key in
        self._profiles is the oldest tracked subject. Evicting that is O(1)
        via iter(dict), avoiding the previous O(n) min() scan over all
        subjects every time a new one registers (noticeable when thousands
        of short-lived PE processes spin up).
        """
        if subject_id not in self._profiles:
            # Evict the oldest-registered profile if we'd exceed the cap.
            # dict iteration order == insertion order (guaranteed 3.7+),
            # so next(iter(...)) is the oldest.
            if len(self._profiles) >= self.MAX_TRACKED_SUBJECTS:
                try:
                    oldest_sid = next(iter(self._profiles))
                    self._profiles.pop(oldest_sid, None)
                    self._freeze_timers.pop(oldest_sid, None)
                except StopIteration:
                    pass
            self._profiles[subject_id] = SubjectProfile(
                subject_id=subject_id,
                domain=domain,
            )
            logger.debug("Now tracking subject %u (domain=%d)", subject_id, domain)

    def unregister_subject(self, subject_id: int):
        """Stop tracking a subject."""
        self._profiles.pop(subject_id, None)
        self._freeze_timers.pop(subject_id, None)

    def _update_subject(self, subject_id: int, new_score: int):
        """Process a new score reading for a subject."""
        profile = self._profiles.get(subject_id)
        if not profile:
            return

        now = time.monotonic()
        old_score = profile.last_score

        # Determine direction
        if new_score > old_score:
            direction = 1
        elif new_score < old_score:
            direction = -1
        else:
            direction = 0

        snapshot = TrustSnapshot(
            subject_id=subject_id,
            score=new_score,
            timestamp=now,
            direction=direction,
        )
        profile.history.append(snapshot)
        profile.score_sum += new_score
        profile.score_count += 1

        # Check for direction change (oscillation detection)
        if direction != 0 and len(profile.history) >= 2:
            prev = profile.history[-2]
            if prev.direction != 0 and prev.direction != direction:
                profile.direction_changes.append(now)

        profile.last_score = new_score

        # Run detectors
        if not profile.frozen:
            self._detect_oscillation(profile)
        self._classify_risk(profile)

        # Emit event if score changed
        if old_score != new_score:
            self._emit_event({
                "type": "score_change",
                "subject_id": subject_id,
                "old_score": old_score,
                "new_score": new_score,
                "risk_tier": profile.risk_tier.name,
                "frozen": profile.frozen,
            })

    # ── Shaking Object Detection ──

    def _detect_oscillation(self, profile: SubjectProfile):
        """
        Detect rapid trust oscillation ("shaking object").

        If a subject's trust score changes direction >= threshold times
        within the oscillation window, freeze the subject.
        """
        now = time.monotonic()
        cutoff = now - self._oscillation_window

        # Count recent direction changes
        recent = sum(1 for t in profile.direction_changes if t >= cutoff)

        if recent >= self._oscillation_threshold:
            self._freeze_subject(profile)
            profile.anomaly_count += 1
            logger.warning(
                "OSCILLATION DETECTED: Subject %u had %d direction changes in %.0fs — FROZEN",
                profile.subject_id, recent, self._oscillation_window,
            )
            self._emit_event({
                "type": "oscillation_freeze",
                "subject_id": profile.subject_id,
                "direction_changes": recent,
                "window_seconds": self._oscillation_window,
                "freeze_duration": self._freeze_duration,
            })

    def _freeze_subject(self, profile: SubjectProfile):
        """Freeze a subject — prevent all trust-modifying actions."""
        profile.frozen = True
        self._freeze_timers[profile.subject_id] = (
            time.monotonic() + self._freeze_duration
        )

        # Tell kernel to set FROZEN flag (if /dev/trust available)
        # This is done via recording a trust action that triggers kernel freeze
        if self._fd is not None:
            # Record a TRUST_CHANGE action with failure to penalize
            buf = struct.pack("=IIIi", profile.subject_id, 13, 1, 0)  # action=13 (TRUST_CHANGE), result=1 (failure)
            try:
                fcntl.ioctl(self._fd, TRUST_IOC_RECORD_ACTION, buf)
            except OSError:
                pass

    def _check_unfreeze(self):
        """Unfreeze subjects whose freeze duration has elapsed."""
        now = time.monotonic()
        to_unfreeze = [
            sid for sid, unfreeze_at in self._freeze_timers.items()
            if now >= unfreeze_at
        ]
        for sid in to_unfreeze:
            del self._freeze_timers[sid]
            profile = self._profiles.get(sid)
            if profile:
                profile.frozen = False
                profile.direction_changes.clear()
                logger.info("Subject %u unfrozen after %.0fs cooldown", sid, self._freeze_duration)
                self._emit_event({
                    "type": "unfreeze",
                    "subject_id": sid,
                })

    # ── Risk Classification ──

    def _classify_risk(self, profile: SubjectProfile):
        """
        Classify subject into risk tiers based on behavior.

        Factors:
        - Current trust score
        - Anomaly history (oscillation count)
        - Domain (Win32 processes start higher risk)
        - Average score trend
        """
        score = profile.last_score
        old_tier = profile.risk_tier

        if profile.frozen or profile.anomaly_count >= 3:
            tier = RiskTier.CRITICAL
        elif score < -200 or profile.anomaly_count >= 2:
            tier = RiskTier.HIGH
        elif score < 100 or profile.domain == TRUST_DOMAIN_WIN32:
            tier = RiskTier.MEDIUM
        else:
            tier = RiskTier.LOW

        profile.risk_tier = tier

        if tier != old_tier:
            logger.info(
                "Subject %u risk tier: %s -> %s (score=%d, anomalies=%d)",
                profile.subject_id, old_tier.name, tier.name,
                score, profile.anomaly_count,
            )
            self._emit_event({
                "type": "risk_change",
                "subject_id": profile.subject_id,
                "old_tier": old_tier.name,
                "new_tier": tier.name,
                "score": score,
            })

    # ── Escalation Queue Processing ──

    def _process_escalation_queue(self):
        """
        Poll the kernel's escalation queue and auto-approve/deny based on
        AI observer risk assessment.

        Approval criteria:
        - Subject must not be frozen
        - Subject must not be CRITICAL risk tier
        - Subject's average score must justify the requested authority
        - HIGH risk subjects can only escalate to SERVICE, not ADMIN/KERNEL
        """
        if self._fd is None:
            return

        # Poll up to 4 escalation requests per tick
        for _ in range(4):
            # struct: u32 sid, u32 auth, char[128] just, u64 ts, i32 score, u32 seq, i32 pending, 4pad
            buf = bytearray(160)
            try:
                result = fcntl.ioctl(self._fd, TRUST_IOC_ESCALATION_POLL, bytes(buf))
                # Parse result (160 bytes with trailing padding)
                fields = struct.unpack_from("=II128sQiIi4x", result)
                subject_id = fields[0]
                requested_auth = fields[1]
                justification = fields[2].split(b'\x00', 1)[0].decode('utf-8', errors='replace')
                timestamp = fields[3]
                current_score = fields[4]
                seq = fields[5]
                has_pending = fields[6]
            except OSError:
                return

            if not has_pending:
                return

            # Make approval decision
            approved = self._evaluate_escalation(
                subject_id, requested_auth, current_score, justification
            )

            # Send response back to kernel
            resp_buf = struct.pack("=II", seq, 1 if approved else 0)
            try:
                fcntl.ioctl(self._fd, TRUST_IOC_ESCALATION_RESPOND, resp_buf)
            except OSError:
                logger.error("Failed to respond to escalation seq=%u", seq)
                continue

            auth_names = {0: "NONE", 1: "USER", 2: "SERVICE", 3: "ADMIN", 4: "KERNEL"}
            decision = "APPROVED" if approved else "DENIED"
            logger.info(
                "Escalation %s: subject %u -> %s (score=%d, reason='%s')",
                decision, subject_id, auth_names.get(requested_auth, "?"),
                current_score, justification,
            )

            self._emit_event({
                "type": "escalation_decision",
                "subject_id": subject_id,
                "requested_authority": requested_auth,
                "authority_name": auth_names.get(requested_auth, "UNKNOWN"),
                "current_score": current_score,
                "justification": justification,
                "approved": approved,
                "seq": seq,
            })

    def _evaluate_escalation(
        self, subject_id: int, requested_auth: int, current_score: int,
        justification: str,
    ) -> bool:
        """
        AI observer's escalation approval logic.

        This is the core decision function — it can be extended with
        ML-based anomaly detection, but the baseline uses risk tiers
        and score thresholds.
        """
        profile = self._profiles.get(subject_id)

        # Unknown subjects: deny ADMIN+, allow USER/SERVICE
        if not profile:
            return requested_auth <= TRUST_AUTH_SERVICE

        # Frozen subjects: always deny
        if profile.frozen:
            return False

        # CRITICAL risk: deny all escalation
        if profile.risk_tier == RiskTier.CRITICAL:
            return False

        # HIGH risk: only allow up to SERVICE
        if profile.risk_tier == RiskTier.HIGH:
            return requested_auth <= TRUST_AUTH_SERVICE

        # MEDIUM risk: allow up to ADMIN if score is sufficient
        if profile.risk_tier == RiskTier.MEDIUM:
            if requested_auth >= TRUST_AUTH_KERNEL:
                return False
            # Require higher score for ADMIN with MEDIUM risk
            return current_score >= 700

        # LOW risk: approve if score thresholds are met
        score_requirements = {
            TRUST_AUTH_USER: 100,
            TRUST_AUTH_SERVICE: 300,
            TRUST_AUTH_ADMIN: 600,
            TRUST_AUTH_KERNEL: 900,
        }
        required = score_requirements.get(requested_auth, 1000)
        return current_score >= required

    # ── Adaptive Thresholds ──

    def get_adaptive_threshold(self, subject_id: int, base_threshold: int) -> int:
        """
        Adjust a trust threshold based on subject risk tier.

        Higher-risk subjects need higher scores to pass checks.
        Lower-risk subjects get relaxed thresholds.
        """
        profile = self._profiles.get(subject_id)
        if not profile:
            return base_threshold

        adjustments = {
            RiskTier.LOW: -50,       # Trusted: slightly lower bar
            RiskTier.MEDIUM: 0,      # Normal: no adjustment
            RiskTier.HIGH: 100,      # Risky: raise the bar
            RiskTier.CRITICAL: 300,  # Dangerous: very high bar
        }

        return base_threshold + adjustments.get(profile.risk_tier, 0)

    # ── Event emission ──

    def _emit_event(self, event: dict):
        """Send event to all registered callbacks."""
        event["timestamp"] = time.time()
        for cb in self._event_callbacks:
            try:
                cb(event)
            except Exception:
                logger.exception("Error in trust event callback")

    # ── Query interface (for API endpoints) ──

    def get_all_subjects(self) -> list[dict]:
        """Return summary of all tracked subjects."""
        return [
            {
                "subject_id": p.subject_id,
                "domain": p.domain,
                "score": p.last_score,
                "risk_tier": p.risk_tier.name,
                "frozen": p.frozen,
                "anomaly_count": p.anomaly_count,
                "avg_score": round(p.avg_score, 1),
                "history_len": len(p.history),
            }
            for p in self._profiles.values()
        ]

    def get_subject(self, subject_id: int) -> Optional[dict]:
        """Return detailed info for a single subject."""
        p = self._profiles.get(subject_id)
        if not p:
            return None

        # Grab last 20 snapshots without materializing the whole deque.
        import itertools
        hist_len = len(p.history)
        hist_start = max(0, hist_len - 20)
        history_slice = itertools.islice(p.history, hist_start, hist_len)

        return {
            "subject_id": p.subject_id,
            "domain": p.domain,
            "score": p.last_score,
            "risk_tier": p.risk_tier.name,
            "frozen": p.frozen,
            "anomaly_count": p.anomaly_count,
            "avg_score": round(p.avg_score, 1),
            "history": [
                {"score": s.score, "timestamp": s.timestamp, "direction": s.direction}
                for s in history_slice
            ],
        }

    # ── Root of Authority: Immune Response Monitoring ──

    def _read_immune_status(self, subject_id: int) -> Optional[int]:
        """Read immune status for a subject via ioctl."""
        if self._fd is None:
            return None
        try:
            buf = bytearray(16)
            struct.pack_into("=I", buf, 0, subject_id)
            fcntl.ioctl(self._fd, TRUST_IOC_IMMUNE_STATUS, buf)
            status, _, suspicious, result = struct.unpack_from("=BxxxIi", buf, 4)
            if result < 0:
                return None
            return status
        except OSError:
            return None

    def _read_token_balance(self, subject_id: int) -> tuple:
        """Read token balance and max for a subject."""
        if self._fd is None:
            return (1000, 1000)
        try:
            buf = bytearray(12)
            struct.pack_into("=I", buf, 0, subject_id)
            fcntl.ioctl(self._fd, TRUST_IOC_TOKEN_BALANCE, buf)
            _, balance, max_balance = struct.unpack_from("=Iii", buf, 0)
            return (balance, max_balance)
        except OSError:
            return (1000, 1000)

    def _read_sex(self, subject_id: int) -> Optional[int]:
        """Read XY sex determination for a subject."""
        if self._fd is None:
            return None
        try:
            buf = bytearray(12)
            struct.pack_into("=I", buf, 0, subject_id)
            fcntl.ioctl(self._fd, TRUST_IOC_GET_SEX, buf)
            _, sex, _, _, _, result = struct.unpack_from("=IBBBBi", buf, 0)
            if result < 0:
                return None
            return sex
        except OSError:
            return None

    def _trigger_quarantine(self, subject_id: int, reason: int) -> bool:
        """Quarantine a subject via kernel ioctl."""
        if self._fd is None:
            return False
        try:
            buf = bytearray(12)
            struct.pack_into("=IIi", buf, 0, subject_id, reason, 0)
            fcntl.ioctl(self._fd, TRUST_IOC_QUARANTINE, buf)
            _, _, result = struct.unpack_from("=IIi", buf, 0)
            return result == 0
        except OSError:
            return False

    def _trigger_apoptosis(self, subject_id: int) -> bool:
        """Initiate apoptosis for a subject via kernel ioctl."""
        if self._fd is None:
            return False
        try:
            buf = bytearray(8)
            struct.pack_into("=Ii", buf, 0, subject_id, 0)
            fcntl.ioctl(self._fd, TRUST_IOC_APOPTOSIS, buf)
            _, result = struct.unpack_from("=Ii", buf, 0)
            return result == 0
        except OSError:
            return False

    def _update_roa_state(self, profile: SubjectProfile):
        """Update Root of Authority state for a profile."""
        # Read immune status
        immune = self._read_immune_status(profile.subject_id)
        if immune is not None:
            old_immune = profile.immune_status
            profile.immune_status = immune

            if immune != old_immune:
                self._emit_event({
                    "type": "immune_change",
                    "subject_id": profile.subject_id,
                    "old_status": old_immune,
                    "new_status": immune,
                })

            # If cancerous, trigger apoptosis automatically
            if immune == TRUST_IMMUNE_CANCEROUS:
                logger.warning("Subject %d detected as CANCEROUS, triggering apoptosis",
                             profile.subject_id)
                self._trigger_apoptosis(profile.subject_id)

        # Read token balance
        balance, max_balance = self._read_token_balance(profile.subject_id)
        profile.token_balance = balance
        profile.token_max = max_balance

        # Token starvation → escalate risk tier
        if balance <= 0 and profile.risk_tier < RiskTier.HIGH:
            logger.warning("Subject %d token-starved (balance=%d)",
                         profile.subject_id, balance)
            self._emit_event({
                "type": "token_starved",
                "subject_id": profile.subject_id,
                "balance": balance,
            })

        # Read sex determination
        sex = self._read_sex(profile.subject_id)
        if sex is not None:
            old_sex = profile.sex
            profile.sex = sex

            if sex != old_sex:
                self._emit_event({
                    "type": "sex_change",
                    "subject_id": profile.subject_id,
                    "old_sex": old_sex,
                    "new_sex": sex,
                    "interpretation": {
                        CHROMO_SEX_XX: "conformant (maintain)",
                        CHROMO_SEX_XY: "behavioral divergence (demote)",
                        CHROMO_SEX_YX: "construction divergence (promote)",
                        CHROMO_SEX_YY: "strongly divergent (apoptosis candidate)",
                    }.get(sex, "unknown"),
                })

                # YY subjects should be quarantined
                if sex == CHROMO_SEX_YY:
                    logger.warning("Subject %d classified YY (strongly divergent), "
                                 "quarantining", profile.subject_id)
                    self._trigger_quarantine(profile.subject_id, 0)

    # ── Enhanced anomaly status with RoA fields ──

    def get_anomaly_status(self) -> dict:
        """Return anomaly detection state for monitoring/debugging."""
        frozen_subjects = [
            {
                "subject_id": sid,
                "unfreeze_at": unfreeze_at,
                "remaining_seconds": max(0, round(unfreeze_at - time.monotonic(), 1)),
            }
            for sid, unfreeze_at in self._freeze_timers.items()
        ]

        risk_distribution = {tier.name: 0 for tier in RiskTier}
        immune_distribution = {
            "HEALTHY": 0, "SUSPICIOUS": 0, "CANCEROUS": 0,
            "APOPTOSIS": 0, "QUARANTINED": 0
        }
        sex_distribution = {"XX": 0, "XY": 0, "YX": 0, "YY": 0}
        total_anomalies = 0
        oscillating_subjects = []
        token_starved_subjects = []

        for p in self._profiles.values():
            risk_distribution[p.risk_tier.name] += 1
            total_anomalies += p.anomaly_count

            # Immune distribution
            immune_names = ["HEALTHY", "SUSPICIOUS", "CANCEROUS",
                          "APOPTOSIS", "QUARANTINED"]
            if 0 <= p.immune_status < len(immune_names):
                immune_distribution[immune_names[p.immune_status]] += 1

            # Sex distribution
            sex_names = ["XX", "XY", "YX", "YY"]
            if 0 <= p.sex < len(sex_names):
                sex_distribution[sex_names[p.sex]] += 1

            # Token starvation
            if p.token_balance <= 0:
                token_starved_subjects.append({
                    "subject_id": p.subject_id,
                    "balance": p.token_balance,
                    "max": p.token_max,
                })

            # Check for recent oscillation (not yet frozen)
            now = time.monotonic()
            cutoff = now - self._oscillation_window
            recent_changes = sum(1 for t in p.direction_changes if t >= cutoff)
            if recent_changes >= 2:  # Approaching threshold
                oscillating_subjects.append({
                    "subject_id": p.subject_id,
                    "direction_changes": recent_changes,
                    "threshold": self._oscillation_threshold,
                    "frozen": p.frozen,
                })

        return {
            "frozen_subjects": frozen_subjects,
            "frozen_count": len(frozen_subjects),
            "total_tracked": len(self._profiles),
            "total_anomalies": total_anomalies,
            "risk_distribution": risk_distribution,
            "oscillating_subjects": oscillating_subjects,
            # Root of Authority fields
            "immune_distribution": immune_distribution,
            "sex_distribution": sex_distribution,
            "token_starved_subjects": token_starved_subjects,
            "architecture": "Root of Authority (Dynamic Hyperlation)",
            "config": {
                "poll_interval": self._poll_interval,
                "oscillation_window": self._oscillation_window,
                "oscillation_threshold": self._oscillation_threshold,
                "freeze_duration": self._freeze_duration,
            },
        }
