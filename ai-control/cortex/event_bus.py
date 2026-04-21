"""
AI Cortex Event Bus -- SENSE component.

Listens on /run/pe-compat/events.sock for events from all layers.
Parses 64-byte event headers, dispatches to registered handlers.
Non-blocking, asyncio-based.
"""

import asyncio
import logging
import os
import socket as sock_mod
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Union

logger = logging.getLogger("cortex.eventbus")

# ---------------------------------------------------------------------------
# Wire-format constants -- must match pe_event.h exactly
# ---------------------------------------------------------------------------

EVENT_MAGIC = 0x45564E54  # "EVNT"
EVENT_VERSION = 1
HEADER_SIZE = 64

# Packed little-endian layout of pe_event_header_t (64 bytes):
#   uint32_t  magic          I   (4)
#   uint16_t  version        H   (2)
#   uint8_t   source_layer   B   (1)
#   uint8_t   event_type     B   (1)
#   uint64_t  timestamp_ns   Q   (8)
#   uint32_t  pid            I   (4)
#   uint32_t  tid            I   (4)
#   uint32_t  subject_id     I   (4)
#   uint64_t  sequence       Q   (8)
#   uint16_t  payload_len    H   (2)
#   uint16_t  flags          H   (2)
#   uint8_t   reserved[24]  24x  (24)
#                                ----
#                                 64
HEADER_FORMAT = "<IHBBQIIIQHH24x"

# Maximum datagram size (header + payload) -- matches PE_EVENT_MAX_SIZE
MAX_DGRAM = 4096

# ---------------------------------------------------------------------------
# Source layers (PE_EVENT_SRC_*)
# ---------------------------------------------------------------------------

class SourceLayer(IntEnum):
    KERNEL = 0
    BROKER = 1
    RUNTIME = 2
    SCM = 3
    CORTEX = 4


# ---------------------------------------------------------------------------
# Per-source event type enums
# ---------------------------------------------------------------------------

class PeEventType(IntEnum):
    """PE Runtime events (source=RUNTIME)."""
    LOAD = 0x01
    DLL_LOAD = 0x02
    UNIMPLEMENTED_API = 0x03
    EXCEPTION = 0x04
    EXIT = 0x05
    TRUST_DENY = 0x06
    TRUST_ESCALATE = 0x07
    DRIVER_LOAD = 0x08
    DEVICE_CREATE = 0x09
    # Memory subsystem events (from TMS / memory scanner)
    MEMORY_MAP = 0x10           # New memory region mapped
    MEMORY_UNMAP = 0x11         # Memory region unmapped
    MEMORY_PROTECT = 0x12       # Memory protection changed
    MEMORY_PATTERN = 0x13       # Pattern match detected
    MEMORY_ANOMALY = 0x14       # Memory anomaly (RWX heap, IAT hook, etc.)
    STUB_CALLED = 0x15          # Unimplemented stub function was called


class TrustEventType(IntEnum):
    """Trust kernel module events (source=KERNEL)."""
    SCORE_CHANGE = 0x01
    TOKEN_STARVE = 0x02
    IMMUNE_ALERT = 0x03
    QUARANTINE = 0x04
    APOPTOSIS = 0x05
    TRC_CHANGE = 0x06


class BrokerEventType(IntEnum):
    """Object broker events (source=BROKER)."""
    CREATE = 0x01
    DESTROY = 0x02
    CONTENTION = 0x03
    REGISTRY_WRITE = 0x04
    REGISTRY_DELETE = 0x05
    DEVICE_ARRIVE = 0x06
    DEVICE_REMOVE = 0x07


class SvcEventType(IntEnum):
    """Service fabric events (source=SCM)."""
    INSTALL = 0x01
    START = 0x02
    STOP = 0x03
    CRASH = 0x04
    RESTART = 0x05
    DEPENDENCY_FAIL = 0x06


class CortexEventType(IntEnum):
    """Cortex-originated events (source=CORTEX)."""
    DECISION = 0x01
    AUTONOMY = 0x02
    OVERRIDE = 0x03
    POLICY = 0x04


# ---------------------------------------------------------------------------
# Flags (PE_EVENT_FLAG_*)
# ---------------------------------------------------------------------------

EVENT_FLAG_URGENT = 0x0001
EVENT_FLAG_AUDIT = 0x0002
EVENT_FLAG_REPLY_REQUESTED = 0x0004


# ---------------------------------------------------------------------------
# Parsed event dataclass
# ---------------------------------------------------------------------------

@dataclass
class Event:
    """Parsed event from the bus."""
    magic: int
    version: int
    source_layer: int
    event_type: int
    timestamp_ns: int
    pid: int
    tid: int
    subject_id: int
    sequence: int
    payload_len: int
    flags: int
    payload: Union[bytes, dict] = field(default_factory=lambda: b"")
    raw_payload: bytes = b""

    @property
    def is_urgent(self) -> bool:
        """True if PE_EVENT_FLAG_URGENT is set."""
        return bool(self.flags & EVENT_FLAG_URGENT)

    @property
    def is_audit(self) -> bool:
        """True if PE_EVENT_FLAG_AUDIT is set."""
        return bool(self.flags & EVENT_FLAG_AUDIT)

    @property
    def reply_requested(self) -> bool:
        """True if PE_EVENT_FLAG_REPLY_REQUESTED is set."""
        return bool(self.flags & EVENT_FLAG_REPLY_REQUESTED)

    @property
    def source_name(self) -> str:
        """Human-readable source layer name."""
        try:
            return SourceLayer(self.source_layer).name
        except ValueError:
            return f"UNKNOWN({self.source_layer})"

    def type_name(self) -> str:
        """Human-readable event type name (source-dependent)."""
        _type_maps: Dict[int, type] = {
            SourceLayer.KERNEL: TrustEventType,
            SourceLayer.BROKER: BrokerEventType,
            SourceLayer.RUNTIME: PeEventType,
            SourceLayer.SCM: SvcEventType,
            SourceLayer.CORTEX: CortexEventType,
        }
        enum_cls = _type_maps.get(self.source_layer)
        if enum_cls is not None:
            try:
                return enum_cls(self.event_type).name
            except ValueError:
                pass
        return f"0x{self.event_type:02x}"


# ---------------------------------------------------------------------------
# Payload parsers -- convert raw bytes to dicts matching pe_event.h structs
# ---------------------------------------------------------------------------

def _decode_cstr(data: bytes) -> str:
    """Decode a null-terminated C string from a fixed-size byte buffer."""
    return data.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def parse_pe_load_payload(data: bytes) -> dict:
    """Parse pe_evt_load_t: char[256] exe_path, uint32 imports_resolved,
    uint32 imports_unresolved, int32 trust_score, uint32 token_budget."""
    if len(data) < 272:  # 256 + 4 + 4 + 4 + 4
        return {}
    rest = struct.unpack_from("<IIiI", data, 256)
    return {
        "exe_path": _decode_cstr(data[:256]),
        "imports_resolved": rest[0],
        "imports_unresolved": rest[1],
        "trust_score": rest[2],
        "token_budget": rest[3],
    }


def parse_pe_dll_load_payload(data: bytes) -> dict:
    """Parse pe_evt_dll_load_t: char[64] dll_name, uint32 resolved,
    uint32 unresolved."""
    if len(data) < 72:  # 64 + 4 + 4
        return {}
    rest = struct.unpack_from("<II", data, 64)
    return {
        "dll_name": _decode_cstr(data[:64]),
        "resolved": rest[0],
        "unresolved": rest[1],
    }


def parse_pe_unimplemented_payload(data: bytes) -> dict:
    """Parse pe_evt_unimplemented_t: char[64] dll_name, char[128] func_name."""
    if len(data) < 192:  # 64 + 128
        return {}
    return {
        "dll_name": _decode_cstr(data[:64]),
        "func_name": _decode_cstr(data[64:192]),
    }


def parse_pe_exit_payload(data: bytes) -> dict:
    """Parse pe_evt_exit_t: uint32 exit_code, uint32 stubs_called,
    uint32 runtime_ms."""
    if len(data) < 12:  # 4 + 4 + 4
        return {}
    ec, stubs, rt = struct.unpack_from("<III", data, 0)
    return {
        "exit_code": ec,
        "stubs_called": stubs,
        "runtime_ms": rt,
    }


def parse_pe_trust_deny_payload(data: bytes) -> dict:
    """Parse pe_evt_trust_deny_t: char[128] api_name, uint8 category,
    int32 score, uint32 tokens."""
    # Minimum size is the packed layout: 128 (api_name) + 1 (category)
    # + 4 (int32 score) + 4 (uint32 tokens) = 137 bytes. The padded layout
    # (with 3 bytes of struct alignment between category and score) is 140.
    if len(data) < 137:
        return {}
    api_name = _decode_cstr(data[:128])
    category = data[128]
    # Use exact payload length to determine layout
    if len(data) == 137:
        # Packed layout (no padding)
        score, tokens = struct.unpack_from("<iI", data, 129)
    elif len(data) >= 140:
        # Padded layout (3 bytes padding after path)
        score, tokens = struct.unpack_from("<iI", data, 132)
    else:
        return {"raw_len": len(data)}
    return {
        "api_name": api_name,
        "category": category,
        "score": score,
        "tokens": tokens,
    }


# PE_EVT_TRUST_ESCALATE reason codes (S78 Dev C). Mirror of the
# PE_TRUST_ESCALATE_REASON_* constants in
# pe-loader/include/eventbus/pe_event.h. If you add a new code, add it
# in BOTH places in the same commit; the _Static_assert in pe_event.h
# guards the wire-format size but cannot guard the semantic map.
_REASON_NAMES: Dict[int, str] = {
    0: "generic",
    1: "quorum_discrepant",
    2: "quorum_divergent",
    3: "ape_exhaustion",
    4: "privilege_adjust",
    5: "driver_load",
    6: "anti_tamper",
}


def _reason_name(reason: int) -> str:
    """Decode a PE_TRUST_ESCALATE_REASON_* integer to its human-readable
    name. Unknown codes render as ``unknown(<n>)`` so cortex logs can
    surface new kernel-side codes before the Python side learns them."""
    if reason in _REASON_NAMES:
        return _REASON_NAMES[reason]
    return f"unknown({reason})"


def parse_pe_trust_escalate_payload(data: bytes) -> dict:
    """Parse pe_evt_trust_escalate_t: char[128] api_name, int32 from_score,
    int32 to_score, uint32 reason. Mirrors trust_deny payload shape; the
    semantic difference is the cortex *grants* (or refuses) the escalation
    instead of merely auditing the deny. Pre-S76 the C-side emit may be
    absent — this parser is here so any future emit lands on a real consumer.

    S77 Agent 1 schema fix: kernel trust scores live in the signed range
    ``[-1000, +1000]`` (see ``trust_translate.KERNEL_SCORE_MIN/MAX``) so
    from_score / to_score MUST be parsed as signed int32 (``i``), not
    unsigned (``I``). The prior schema silently turned any negative score
    into a huge positive (e.g. -50 → 4294967246), which would have made
    the cortex refuse every escalation whose source band was below
    baseline. ``reason`` is a 32-bit enum bitmap so it stays unsigned.

    S78 Dev C: ``reason`` is now discriminated per cause (see
    :data:`_REASON_NAMES`). The returned dict includes ``reason_name``
    so downstream handlers can route without re-implementing the lookup.
    Unknown reasons decode to ``unknown(<n>)`` (forward-compat)."""
    if len(data) < 140:
        return {"raw_len": len(data)}
    api_name = _decode_cstr(data[:128])
    from_score, to_score, reason = struct.unpack_from("<iiI", data, 128)
    return {
        "api_name": api_name,
        "from_score": from_score,
        "to_score": to_score,
        "reason": reason,
        "reason_name": _reason_name(reason),
    }


def parse_memory_map_payload(data: bytes) -> dict:
    """Parse memory map event: uint64 va, uint32 size, uint32 prot_flags,
    char[256] source_path, char[32] tag."""
    if len(data) < 300:  # 8 + 4 + 4 + 256 + 32 (minimum with all fields)
        return {}
    va, size, prot_flags = struct.unpack_from("<QII", data, 0)
    source_path = _decode_cstr(data[16:272])
    tag = _decode_cstr(data[272:304])
    return {
        "va": va, "size": size, "prot_flags": prot_flags,
        "source_path": source_path, "tag": tag,
    }


def parse_memory_protect_payload(data: bytes) -> dict:
    """Parse memory protection change: uint64 va, uint32 size, char[8] old_prot,
    char[8] new_prot, char[32] tag."""
    if len(data) < 60:  # 8 + 4 + 8 + 8 + 32
        return {}
    va, size = struct.unpack_from("<QI", data, 0)
    old_prot = _decode_cstr(data[12:20])
    new_prot = _decode_cstr(data[20:28])
    tag = _decode_cstr(data[28:60])
    return {"va": va, "size": size, "old_prot": old_prot, "new_prot": new_prot, "tag": tag}


def parse_memory_pattern_payload(data: bytes) -> dict:
    """Parse pattern match: char[64] pattern_id, uint64 va, char[64] region,
    char[32] category, char[128] description."""
    if len(data) < 296:  # 64 + 8 + 64 + 32 + 128
        return {}
    pattern_id = _decode_cstr(data[:64])
    (va,) = struct.unpack_from("<Q", data, 64)
    region = _decode_cstr(data[72:136])
    category = _decode_cstr(data[136:168])
    description = _decode_cstr(data[168:296])
    return {
        "pattern_id": pattern_id, "va": va, "region": region,
        "category": category, "description": description,
    }


def parse_memory_anomaly_payload(data: bytes) -> dict:
    """Parse memory anomaly: uint64 va, uint32 size, char[32] tag,
    char[8] new_prot, char[128] description."""
    if len(data) < 180:  # 8 + 4 + 32 + 8 + 128
        return {}
    va, size = struct.unpack_from("<QI", data, 0)
    tag = _decode_cstr(data[12:44])
    new_prot = _decode_cstr(data[44:52])
    description = _decode_cstr(data[52:180])
    return {
        "va": va, "size": size, "tag": tag,
        "new_prot": new_prot, "description": description,
    }


def parse_stub_called_payload(data: bytes) -> dict:
    """Parse stub called: char[64] dll_name, char[128] function."""
    if len(data) < 192:  # 64 + 128
        return {}
    return {
        "dll": _decode_cstr(data[:64]),
        "function": _decode_cstr(data[64:192]),
    }


# Dispatch table: (source_layer, event_type) -> parser function
_PAYLOAD_PARSERS: Dict[tuple, Callable[[bytes], dict]] = {
    (SourceLayer.RUNTIME, PeEventType.LOAD): parse_pe_load_payload,
    (SourceLayer.RUNTIME, PeEventType.DLL_LOAD): parse_pe_dll_load_payload,
    (SourceLayer.RUNTIME, PeEventType.UNIMPLEMENTED_API): parse_pe_unimplemented_payload,
    (SourceLayer.RUNTIME, PeEventType.EXIT): parse_pe_exit_payload,
    (SourceLayer.RUNTIME, PeEventType.TRUST_DENY): parse_pe_trust_deny_payload,
    (SourceLayer.RUNTIME, PeEventType.TRUST_ESCALATE): parse_pe_trust_escalate_payload,
    (SourceLayer.RUNTIME, PeEventType.MEMORY_MAP): parse_memory_map_payload,
    (SourceLayer.RUNTIME, PeEventType.MEMORY_PROTECT): parse_memory_protect_payload,
    (SourceLayer.RUNTIME, PeEventType.MEMORY_PATTERN): parse_memory_pattern_payload,
    (SourceLayer.RUNTIME, PeEventType.MEMORY_ANOMALY): parse_memory_anomaly_payload,
    (SourceLayer.RUNTIME, PeEventType.STUB_CALLED): parse_stub_called_payload,
}


def parse_payload(source_layer: int, event_type: int, data: bytes) -> Union[dict, bytes]:
    """Parse a raw event payload into a dict using the appropriate struct parser.

    Returns a dict if a parser is registered for the (source_layer, event_type)
    pair and parsing succeeds.  Returns the raw bytes otherwise, so callers
    that handle unknown event types still receive the original data.
    """
    parser = _PAYLOAD_PARSERS.get((source_layer, event_type))
    if parser is not None:
        try:
            result = parser(data)
            if result:
                return result
        except Exception:
            logger.debug(
                "Payload parse failed for src=%d type=0x%02x (%d bytes)",
                source_layer, event_type, len(data),
            )
    return data


# Type alias for event handlers
EventHandler = Callable[["Event"], None]


# ---------------------------------------------------------------------------
# EventBus -- async datagram listener + dispatcher
# ---------------------------------------------------------------------------

class EventBus:
    """
    Async event bus listener.

    Binds a Unix datagram socket at SOCKET_PATH, receives events from all
    layers, parses the 64-byte header, and dispatches to registered handlers.

    Usage::

        bus = EventBus()
        bus.on(SourceLayer.RUNTIME, PeEventType.LOAD, my_handler)
        bus.on_all(audit_logger)
        await bus.start()   # runs until bus.stop() is called
    """

    SOCKET_PATH = "/run/pe-compat/events.sock"

    def __init__(self, socket_path: Optional[str] = None):
        if socket_path is not None:
            self.SOCKET_PATH = socket_path

        self._handlers: Dict[int, Dict[int, List[EventHandler]]] = {}
        self._global_handlers: List[EventHandler] = []
        self._running = False
        self._events_received: int = 0
        self._events_dropped: int = 0
        self._sock: Optional[sock_mod.socket] = None

        # Queue decouples recv from dispatch so slow handlers cannot block recv
        self._event_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self._dispatch_task: Optional[asyncio.Task] = None
        self._stats: Dict[str, int] = {
            "received": 0,
            "dispatched": 0,
            "dropped": 0,
            "errors": 0,
        }

    # -- Handler registration ------------------------------------------------

    def on(self, source_layer: int, event_type: int, handler: EventHandler) -> None:
        """Register a handler for a specific (source_layer, event_type) pair."""
        if source_layer not in self._handlers:
            self._handlers[source_layer] = {}
        if event_type not in self._handlers[source_layer]:
            self._handlers[source_layer][event_type] = []
        self._handlers[source_layer][event_type].append(handler)

    def on_all(self, handler: EventHandler) -> None:
        """Register a handler that receives ALL events (global tap)."""
        self._global_handlers.append(handler)

    # -- Parsing -------------------------------------------------------------

    def _parse_event(self, data: bytes) -> Optional[Event]:
        """Parse a raw datagram into an Event, or None on error."""
        if len(data) < HEADER_SIZE:
            self._events_dropped += 1
            logger.debug("Dropped short datagram (%d bytes)", len(data))
            return None

        try:
            (
                magic, version, source, etype,
                timestamp_ns, pid, tid, subject_id,
                sequence, payload_len, flags,
            ) = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
        except struct.error as exc:
            self._events_dropped += 1
            logger.debug("Dropped malformed header: %s", exc)
            return None

        if magic != EVENT_MAGIC:
            self._events_dropped += 1
            logger.debug("Dropped bad magic: 0x%08x", magic)
            return None

        raw_payload = b""
        if payload_len > 0:
            raw_payload = data[HEADER_SIZE : HEADER_SIZE + payload_len]

        # Parse the payload bytes into a dict when a struct parser is available
        parsed = parse_payload(source, etype, raw_payload)

        return Event(
            magic=magic,
            version=version,
            source_layer=source,
            event_type=etype,
            timestamp_ns=timestamp_ns,
            pid=pid,
            tid=tid,
            subject_id=subject_id,
            sequence=sequence,
            payload_len=payload_len,
            flags=flags,
            payload=parsed,
            raw_payload=raw_payload,
        )

    # -- Dispatch ------------------------------------------------------------

    def _dispatch(self, event: Event) -> None:
        """Dispatch a parsed event to all matching handlers (synchronous).

        Kept for backward compatibility.  The async event loop now uses
        :meth:`_dispatch_async` instead.
        """
        # Global handlers first (audit, logging, metrics)
        for handler in self._global_handlers:
            try:
                handler(event)
            except Exception:
                logger.exception("Global handler error")
                self._stats["errors"] += 1

        # Source+type specific handlers
        layer_handlers = self._handlers.get(event.source_layer, {})
        type_handlers = layer_handlers.get(event.event_type, [])
        for handler in type_handlers:
            try:
                handler(event)
            except Exception:
                logger.exception(
                    "Handler error for %s:%s",
                    event.source_name,
                    event.type_name(),
                )
                self._stats["errors"] += 1

    async def _dispatch_async(self, event: Event) -> None:
        """Dispatch event to all registered handlers, awaiting coroutines."""
        # Global handlers first (audit, logging, metrics)
        for handler in self._global_handlers:
            try:
                result = handler(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception("Global handler error for event %s", event.type_name())
                self._stats["errors"] += 1

        # Source+type specific handlers
        layer_handlers = self._handlers.get(event.source_layer, {})
        type_handlers = layer_handlers.get(event.event_type, [])
        for handler in type_handlers:
            try:
                result = handler(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception(
                    "Handler error for %s:%s",
                    event.source_name,
                    event.type_name(),
                )
                self._stats["errors"] += 1

        self._stats["dispatched"] += 1

    # -- Lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        """
        Start listening for events.

        Creates the datagram socket, binds it, and spawns two async tasks:
        one for receiving datagrams into the internal queue, and one for
        dispatching queued events to handlers.  This decoupling prevents
        slow handlers from blocking recv, which previously caused the OS
        datagram buffer to fill and silently drop events under load.

        Runs until :meth:`stop` is called or the task is cancelled.
        """
        # Ensure the socket directory exists
        sock_dir = os.path.dirname(self.SOCKET_PATH)
        try:
            os.makedirs(sock_dir, exist_ok=True)
        except OSError as exc:
            logger.error("Cannot create socket directory %s: %s", sock_dir, exc)
            raise

        # Remove stale socket file
        try:
            if os.path.exists(self.SOCKET_PATH):
                os.unlink(self.SOCKET_PATH)
        except OSError as exc:
            logger.warning("Cannot remove stale socket %s: %s", self.SOCKET_PATH, exc)

        # Create non-blocking Unix datagram socket
        self._sock = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_DGRAM)
        self._sock.setblocking(False)
        self._sock.bind(self.SOCKET_PATH)
        try:
            os.chmod(self.SOCKET_PATH, 0o660)  # Allow group members to send events
        except OSError as exc:
            logger.warning("Cannot chmod socket %s: %s", self.SOCKET_PATH, exc)
        # Session 69 (Agent R): chgrp to pe-compat so non-root subscribers
        # in that group can connect.  Requires SupplementaryGroups=pe-compat
        # on the service (ai-control.service.d/group.conf drop-in) -- if the
        # group doesn't exist or we lack CAP_CHOWN, fall back silently and
        # leave the socket at the creating process's primary gid.
        try:
            import grp
            gid = grp.getgrnam("pe-compat").gr_gid
            os.chown(self.SOCKET_PATH, -1, gid)
        except (KeyError, PermissionError, OSError) as exc:
            logger.debug("Cannot chgrp socket %s to pe-compat: %s", self.SOCKET_PATH, exc)

        self._running = True
        logger.info("Event bus listening on %s", self.SOCKET_PATH)

        # Launch the dispatch loop as a background task, then enter recv loop
        self._dispatch_task = asyncio.create_task(self._dispatch_loop())
        try:
            await self._recv_loop()
        finally:
            # If recv_loop exits (stop or cancel), ensure dispatch task is cleaned up
            if self._dispatch_task is not None and not self._dispatch_task.done():
                self._dispatch_task.cancel()
                try:
                    await self._dispatch_task
                except asyncio.CancelledError:
                    pass

    async def _recv_loop(self) -> None:
        """Receive datagrams from the socket and enqueue parsed events.

        This loop does minimal work -- just recv + parse + enqueue -- so it
        stays responsive even when handlers are slow.  If the internal queue
        is full, the event is dropped with a warning rather than blocking.
        """
        loop = asyncio.get_running_loop()

        retry_delay = 0.1  # Exponential backoff: start at 100ms
        retry_count = 0
        max_retry_delay = 5.0

        while self._running:
            try:
                data = await loop.sock_recv(self._sock, MAX_DGRAM)
                if data:
                    self._events_received += 1
                    self._stats["received"] += 1
                    event = self._parse_event(data)
                    if event is not None:
                        try:
                            self._event_queue.put_nowait(event)
                        except asyncio.QueueFull:
                            self._events_dropped += 1
                            self._stats["dropped"] += 1
                            logger.warning(
                                "Event queue full, dropping event: %s:%s (seq=%d)",
                                event.source_name,
                                event.type_name(),
                                event.sequence,
                            )
                # Reset backoff on successful recv
                retry_delay = 0.1
                retry_count = 0
            except asyncio.CancelledError:
                break
            except OSError as exc:
                # Socket closed or transient error -- back off to avoid CPU spin
                if self._running:
                    retry_count += 1
                    if retry_count % 10 == 1:
                        logger.warning(
                            "Event bus recv error (attempt %d, backoff %.1fs): %s",
                            retry_count, retry_delay, exc,
                        )
                    await asyncio.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, max_retry_delay)

    async def _dispatch_loop(self) -> None:
        """Dequeue events and dispatch to handlers.

        Runs as a separate task so handler latency never blocks recv.
        Uses a 1-second timeout on the queue get so we can check
        ``_running`` periodically and exit cleanly.
        """
        while self._running:
            try:
                event = await asyncio.wait_for(
                    self._event_queue.get(), timeout=1.0,
                )
                await self._dispatch_async(event)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in dispatch loop")
                self._stats["errors"] += 1

    async def stop(self) -> None:
        """Stop the listener, cancel the dispatch task, close the socket, and clean up."""
        self._running = False

        # Cancel the dispatch task so it doesn't hang waiting on an empty queue
        if self._dispatch_task is not None and not self._dispatch_task.done():
            self._dispatch_task.cancel()
            try:
                await self._dispatch_task
            except asyncio.CancelledError:
                pass
            self._dispatch_task = None

        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if os.path.exists(self.SOCKET_PATH):
            try:
                os.unlink(self.SOCKET_PATH)
            except OSError:
                pass
        logger.info(
            "Event bus stopped. received=%d dispatched=%d dropped=%d errors=%d",
            self._stats["received"],
            self._stats["dispatched"],
            self._stats["dropped"],
            self._stats["errors"],
        )

    # -- Introspection -------------------------------------------------------

    @property
    def stats(self) -> dict:
        """Return current bus statistics including queue depth."""
        handler_count = sum(
            len(h)
            for layer in self._handlers.values()
            for h in layer.values()
        ) + len(self._global_handlers)

        return {
            "events_received": self._stats["received"],
            "events_dispatched": self._stats["dispatched"],
            "events_dropped": self._stats["dropped"],
            "errors": self._stats["errors"],
            "queue_depth": self._event_queue.qsize(),
            "queue_maxsize": self._event_queue.maxsize,
            "handlers_registered": handler_count,
            "running": self._running,
        }

    def get_stats(self) -> dict:
        """Return current bus statistics including queue depth.

        Convenience method (non-property) for callers that prefer a method call.
        """
        return self.stats
