"""S79 Test Agent 4 helpers — payload builders + fakes not in _s77_helpers.

These extend (not replace) the S77 scaffolding with payload builders for
PE event types the S77 suite didn't need: pe_load, dll_load, exit, exception,
memory_map, memory_protect, etc. Import this module as a companion to
``_s77_helpers``.

Layout details are cross-checked against
  * ai-control/cortex/event_bus.py::parse_pe_*_payload
  * pe-loader/include/eventbus/pe_event.h

Mock boundaries documented per helper. Any real wire ingestion would come
through /run/pe-compat/events.sock which is a Unix datagram socket that the
Windows test host does not have — we build bytes in Python and pump them
through ``EventBus._parse_event`` / ``EventBus._dispatch`` directly.
"""

from __future__ import annotations

import struct
from typing import Any


# ---------------------------------------------------------------------------
# Extra PE / Trust / SCM event type constants (mirror event_bus enums so we
# don't import them at module scope and explode if cortex can't be loaded)
# ---------------------------------------------------------------------------

# PeEventType (source=SRC_RUNTIME=2)
PE_EVT_LOAD = 0x01
PE_EVT_DLL_LOAD = 0x02
PE_EVT_UNIMPLEMENTED = 0x03
PE_EVT_EXCEPTION = 0x04
PE_EVT_EXIT = 0x05
# TRUST_DENY / TRUST_ESCALATE live in _s77_helpers (0x06 / 0x07)
PE_EVT_MEMORY_MAP = 0x10
PE_EVT_MEMORY_PROTECT = 0x12
PE_EVT_MEMORY_PATTERN = 0x13
PE_EVT_MEMORY_ANOMALY = 0x14
PE_EVT_STUB_CALLED = 0x15

# TrustEventType (source=SRC_KERNEL=0)
TRUST_EVT_SCORE_CHANGE = 0x01
TRUST_EVT_TOKEN_STARVE = 0x02
TRUST_EVT_IMMUNE_ALERT = 0x03
TRUST_EVT_QUARANTINE = 0x04
TRUST_EVT_APOPTOSIS = 0x05

# SvcEventType (source=SRC_SCM=3)
SRC_SCM = 3
SVC_EVT_CRASH = 0x04


# ---------------------------------------------------------------------------
# Payload builders (bytes-level shape must match parse_pe_* parsers)
# ---------------------------------------------------------------------------


def build_pe_load_payload(
    exe_path: str = "C:\\Windows\\System32\\notepad.exe",
    imports_resolved: int = 20,
    imports_unresolved: int = 0,
    trust_score: int = 50,
    token_budget: int = 1000,
) -> bytes:
    """Pack pe_evt_load_t (256 + 4*4 = 272 bytes).

    Matches parse_pe_load_payload in event_bus.py:203 which reads
    ``char[256] exe_path, uint32 imports_resolved, uint32 imports_unresolved,
    int32 trust_score, uint32 token_budget``.
    """
    path_buf = exe_path.encode("utf-8")[:255].ljust(256, b"\x00")
    tail = struct.pack(
        "<IIiI",
        imports_resolved,
        imports_unresolved,
        trust_score,
        token_budget,
    )
    return path_buf + tail


def build_pe_dll_load_payload(
    dll_name: str = "kernel32.dll",
    resolved: int = 50,
    unresolved: int = 0,
) -> bytes:
    """Pack pe_evt_dll_load_t (64 + 4 + 4 = 72 bytes).

    Matches parse_pe_dll_load_payload in event_bus.py:218.
    """
    name_buf = dll_name.encode("utf-8")[:63].ljust(64, b"\x00")
    return name_buf + struct.pack("<II", resolved, unresolved)


def build_pe_exit_payload(
    exit_code: int = 0,
    stubs_called: int = 0,
    runtime_ms: int = 100,
) -> bytes:
    """Pack pe_evt_exit_t (3 * uint32 = 12 bytes).

    Matches parse_pe_exit_payload in event_bus.py:241.
    """
    return struct.pack("<III", exit_code, stubs_called, runtime_ms)


def build_pe_exception_payload() -> bytes:
    """Minimal non-empty buffer — the cortex handle_pe_exception does not
    need any specific struct payload (event_bus has no parser registered
    for EXCEPTION), so we pass through 8 bytes that survive
    parse_payload's fall-through to raw bytes."""
    return b"\x00" * 8


def build_memory_pattern_payload(
    pattern_id: str = "anti_debug_check",
    va: int = 0x00007FF000000000,
    region: str = ".text",
    category: str = "anti_debug",
    description: str = "IsDebuggerPresent probe",
) -> bytes:
    """Pack memory_pattern (64 + 8 + 64 + 32 + 128 = 296 bytes).

    Matches parse_memory_pattern_payload event_bus.py:364.
    """
    pid_buf = pattern_id.encode()[:63].ljust(64, b"\x00")
    va_buf = struct.pack("<Q", va)
    reg_buf = region.encode()[:63].ljust(64, b"\x00")
    cat_buf = category.encode()[:31].ljust(32, b"\x00")
    desc_buf = description.encode()[:127].ljust(128, b"\x00")
    return pid_buf + va_buf + reg_buf + cat_buf + desc_buf


# ---------------------------------------------------------------------------
# Fakes beyond what _s77_helpers ships
# ---------------------------------------------------------------------------


class RecordingBus:
    """Mimics the minimum of ``event_bus.EventBus`` that observer-side
    code touches: a ``publish(event_dict)`` method (dict, not bytes).

    Unlike ``event_bus.EventBus`` this never opens a real socket and never
    dispatches to handlers — it just archives every published event so a
    test can assert ordering / count / payload shape.
    """

    def __init__(self) -> None:
        self.events: list[dict] = []

    def publish(self, event: dict) -> None:
        self.events.append(dict(event))

    # Some callsites try "emit" before "publish"; offer both.
    def emit(self, event: dict) -> None:
        self.publish(event)


class CollectingHandlers:
    """Record-only stand-in for ``CortexHandlers`` — accepts every
    ``handle_*`` name as a no-op that appends a record tuple.

    Used by tests that want to observe bus-level dispatch without
    building the full CortexHandlers (which requires autonomy +
    orchestrator). The handler signature matches what ``bus.on`` would
    pass: a single ``Event`` dataclass.
    """

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def __getattr__(self, name: str):
        if not name.startswith("handle_"):
            raise AttributeError(name)

        def _recorder(event: Any) -> None:
            self.calls.append((name, event))

        return _recorder


class FakeBeliefUpdater:
    """Tracks calls to BeliefState.from_observers shape without pulling in
    the real module — used when wiring algedonic / trust events that are
    supposed to update a BeliefState downstream."""

    def __init__(self) -> None:
        self.updates: list[dict] = []

    def on_algedonic(self, event: dict) -> None:
        self.updates.append(dict(event))
