"""
algedonic_reader.py -- Userspace drain for the kernel algedonic channel.

Beer's VSM algedonic ("pain/pleasure") bypass is a sub-millisecond kernel->
cortex signalling path that short-circuits the normal perception->decision
pipeline during emergencies. The kernel half lives in
``trust/kernel/trust_algedonic.c`` and emits 40-byte
``trust_algedonic_packet`` structures to ``/dev/trust_algedonic``.

Without a reader in place, those packets pile up in a 64-slot ring and
the oldest are evicted on overflow -- meaning every emergency from the
kernel that we fail to drain is *lost*. The wire format matches
``trust/include/trust_algedonic.h``:

    struct trust_algedonic_packet {     // 40 bytes, __attribute__((packed))
        __u64 ts_ns;
        __u32 subject_pid;
        __u16 severity;
        __u16 reason;
        __u64 data[3];
    };

This module implements the userspace half: a ``/dev/trust_algedonic``
reader running inside the ai-control daemon's asyncio loop that decodes
each packet and dispatches it to the cortex event bus with topic

    trust.algedonic.<reason_name>

where ``reason_name`` is a short string derived from the
``TRUST_ALG_*`` enum in the kernel header.

Graceful fallback: if the device node does not exist (WSL test host,
QEMU without the trust.ko module loaded) the reader logs a single
warning and becomes a no-op. The rest of the daemon is unaffected.

S74 Integration / Research Finding #1 (Beer + Levin convergence).
"""

from __future__ import annotations

import asyncio
import errno
import logging
import os
import struct
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# -------- Wire format -------------------------------------------------------

# Matches <trust_algedonic.h> struct trust_algedonic_packet.
# Little-endian on all supported Linux/x86_64 + aarch64 platforms.
_PACKET_FMT = "<QIHHQQQ"
_PACKET_SIZE = struct.calcsize(_PACKET_FMT)  # 40

if _PACKET_SIZE != 40:  # pragma: no cover - platform sanity check
    raise RuntimeError(
        "algedonic_reader: wire format size mismatch "
        f"({_PACKET_SIZE} != 40); kernel ABI changed?"
    )

# Reason code names -- KEEP IN SYNC with enum trust_alg_reason in
# trust/include/trust_algedonic.h. Drift is caught by
# tests/unit/test_algedonic_reader.py.
_REASON_NAMES = {
    0: "unknown",
    1: "pool_exhaustion",
    2: "ape_exhaustion",
    3: "cascade_apoptosis",
    4: "quorum_disputed_repeatedly",
    5: "morphogen_hot_spot",
    6: "cancer_detected",
    7: "tpm_drift",
    8: "proof_chain_break",
    9: "token_starvation_storm",
}

# Severity thresholds -- match trust_algedonic.h.
TRUST_ALG_SEVERITY_INFO = 1024
TRUST_ALG_SEVERITY_WARN = 16384
TRUST_ALG_SEVERITY_CRITICAL = 32768
TRUST_ALG_SEVERITY_MAX = 65535


def _reason_name(code: int) -> str:
    return _REASON_NAMES.get(code, f"unknown({code})")


def decode_packet(raw: bytes) -> dict:
    """Decode one 40-byte algedonic packet into a dict event.

    Returns the event dict suitable for event_bus dispatch. Raises
    ``ValueError`` on short buffer.
    """
    if len(raw) != _PACKET_SIZE:
        raise ValueError(
            f"algedonic packet wrong size: {len(raw)} (want {_PACKET_SIZE})"
        )
    ts_ns, pid, sev, reason, d0, d1, d2 = struct.unpack(_PACKET_FMT, raw)
    name = _reason_name(reason)
    return {
        "source": "trust.algedonic",
        "topic": f"trust.algedonic.{name}",
        "ts_ns": ts_ns,
        "subject_pid": pid,
        "severity": sev,
        "reason_code": reason,
        "reason_name": name,
        "payload": [d0, d1, d2],
        "critical": sev > TRUST_ALG_SEVERITY_CRITICAL,
    }


# -------- Reader -----------------------------------------------------------


class AlgedonicReader:
    """Drain ``/dev/trust_algedonic`` on an asyncio task.

    The reader publishes each decoded packet to ``event_bus`` via whichever
    of ``publish`` / ``emit`` / direct-call attribute exists on it. If the
    device node is absent, ``start()`` logs one warning and returns; the
    reader becomes a no-op for the rest of the process lifetime.
    """

    def __init__(
        self,
        dev_path: str = "/dev/trust_algedonic",
        event_bus: Any = None,
        cortex: Any = None,
    ) -> None:
        self._dev_path = dev_path
        self._event_bus = event_bus
        self._cortex = cortex
        self._task: Optional[asyncio.Task] = None
        self._fd: int = -1
        self._running = False
        self._stats = {
            "packets_read": 0,
            "packets_dispatched": 0,
            "decode_errors": 0,
            "read_errors": 0,
            "critical_bypasses": 0,
        }

    # -- Lifecycle ----------------------------------------------------------

    async def start(self) -> None:
        """Open the device (if present) and spawn the drain task."""
        if self._running:
            return
        try:
            # Blocking mode; run_in_executor handles the read.
            self._fd = os.open(self._dev_path, os.O_RDONLY)
        except FileNotFoundError:
            logger.warning(
                "algedonic_reader: %s not present; trust.ko not loaded? "
                "algedonic bypass disabled",
                self._dev_path,
            )
            self._fd = -1
            return
        except PermissionError as e:
            logger.error(
                "algedonic_reader: permission denied on %s (%s); "
                "daemon should be in the 'trust' group",
                self._dev_path,
                e,
            )
            self._fd = -1
            return
        except OSError as e:
            logger.error(
                "algedonic_reader: open failed on %s: %s",
                self._dev_path,
                e,
            )
            self._fd = -1
            return
        self._running = True
        self._task = asyncio.create_task(
            self._run(), name="algedonic_reader"
        )
        logger.info(
            "algedonic_reader: draining %s (packet=%d B)",
            self._dev_path,
            _PACKET_SIZE,
        )

    async def stop(self) -> None:
        """Stop the drain task and close the device fd."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1

    # -- Introspection ------------------------------------------------------

    def stats(self) -> dict:
        return dict(self._stats)

    # -- Drain loop ---------------------------------------------------------

    async def _run(self) -> None:
        assert self._fd >= 0
        loop = asyncio.get_running_loop()
        while self._running:
            try:
                raw = await loop.run_in_executor(
                    None, os.read, self._fd, _PACKET_SIZE
                )
            except asyncio.CancelledError:
                raise
            except OSError as e:
                # EINTR is benign -- a signal interrupted read(). ENODEV
                # means the module was unloaded; stop cleanly.
                self._stats["read_errors"] += 1
                if e.errno == errno.ENODEV:
                    logger.info(
                        "algedonic_reader: %s vanished (trust.ko unloaded?)",
                        self._dev_path,
                    )
                    self._running = False
                    return
                logger.debug(
                    "algedonic_reader: read error %s; continuing", e
                )
                await asyncio.sleep(0.1)
                continue
            if not raw:
                await asyncio.sleep(0.01)
                continue
            try:
                event = decode_packet(raw)
            except ValueError as e:
                self._stats["decode_errors"] += 1
                logger.debug("algedonic_reader: decode error %s", e)
                continue
            self._stats["packets_read"] += 1
            self._dispatch(event)

    # -- Dispatch -----------------------------------------------------------

    def _dispatch(self, event: dict) -> None:
        """Publish to event bus + fast-path critical to cortex."""
        if self._event_bus is not None:
            for name in ("publish", "emit"):
                fn = getattr(self._event_bus, name, None)
                if callable(fn):
                    try:
                        fn(event)
                        self._stats["packets_dispatched"] += 1
                        break
                    except Exception as e:  # pragma: no cover - log only
                        logger.debug(
                            "algedonic_reader: bus.%s failed: %s", name, e
                        )
        if event.get("critical") and self._cortex is not None:
            try:
                bypass_fn = getattr(self._cortex, "on_algedonic", None)
                if callable(bypass_fn):
                    bypass_fn(event)
                    self._stats["critical_bypasses"] += 1
                else:
                    # Older ActiveInferenceAgent signature: select_action(bypass=)
                    select = getattr(self._cortex, "select_action", None)
                    if callable(select):
                        try:
                            select(bypass=event)
                            self._stats["critical_bypasses"] += 1
                        except TypeError:
                            pass
            except Exception as e:  # pragma: no cover - defensive
                logger.debug(
                    "algedonic_reader: cortex bypass failed: %s", e
                )


# -------- Wire-up helper ---------------------------------------------------


def register_with_daemon(app: Any, event_bus: Any, cortex: Any = None,
                         dev_path: str = "/dev/trust_algedonic"
                         ) -> AlgedonicReader:
    """Construct the reader and register its stats endpoint on *app*.

    Call-site owns ``start()`` / ``stop()`` lifecycle.
    """
    reader = AlgedonicReader(
        dev_path=dev_path, event_bus=event_bus, cortex=cortex
    )

    if app is not None:
        try:
            @app.get("/metrics/algedonic")  # type: ignore[misc]
            async def _alg_metrics() -> dict:
                return reader.stats()
        except Exception:
            logger.debug(
                "algedonic_reader: FastAPI route registration skipped"
            )

    return reader


__all__ = [
    "AlgedonicReader",
    "decode_packet",
    "register_with_daemon",
    "TRUST_ALG_SEVERITY_INFO",
    "TRUST_ALG_SEVERITY_WARN",
    "TRUST_ALG_SEVERITY_CRITICAL",
    "TRUST_ALG_SEVERITY_MAX",
]
