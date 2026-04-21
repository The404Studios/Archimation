"""Shared helpers for S77 Agent 5 integration test harness.

These helpers construct PE-event wire bytes, load modules from
`ai-control/cortex/` and `ai-control/daemon/` by path (since those
directories contain hyphens and cannot be imported as packages),
and provide minimal fakes for the autonomy + orchestrator objects
so full-chain tests don't have to stand up the whole daemon.

The scenarios exercised by tests/integration/test_<scenario>_e2e.py:

  A) PE_EVT_TRUST_DENY wire -> parse -> handler -> decision  (S75 Agent H)
  B) PE_EVT_TRUST_ESCALATE wire -> parse -> handler          (S75 follow-up)
  C) library_census population -> BeliefState.token segment  (S75 follow-up)
  D) Monte-Carlo ConfidenceSampler -> DecisionEngine._finalize (S76 Agent E)
  E) differential_observer: tick() baseline -> mutation -> delta
  F) depth_observer: random vs shallow vs deep discrimination

The ``load_module_from_path`` helper mirrors the loader pattern in
tests/unit/test_monte_carlo.py (importlib.util.spec_from_file_location).
"""

from __future__ import annotations

import importlib.util
import struct
import sys
import time
from pathlib import Path
from types import ModuleType


# Repo root: .../arch-linux-with-full-ai-control/
_REPO_ROOT = Path(__file__).resolve().parents[2]
_AI_CONTROL_ROOT = _REPO_ROOT / "ai-control"
_CORTEX_DIR = _AI_CONTROL_ROOT / "cortex"
_DAEMON_DIR = _AI_CONTROL_ROOT / "daemon"


def _ensure_paths_on_sys_path() -> None:
    """Put ``ai-control/`` and ``ai-control/daemon/`` on sys.path.

    Two reasons we need both:

      * ``cortex.main`` uses relative imports (``from .autonomy import ...``).
        For those to resolve we must import it as ``cortex.main``, which
        requires ``ai-control/`` on sys.path (so ``cortex`` resolves as a
        package via its __init__.py).
      * ``daemon/`` modules do flat top-level imports (``import
        memory_observer``) so they need ``ai-control/daemon/`` on sys.path.

    Same pattern as tests/integration/conftest.py:315-325 (S52 Agent Z).
    """
    for p in (_AI_CONTROL_ROOT, _DAEMON_DIR):
        s = str(p)
        if s not in sys.path:
            sys.path.insert(0, s)


def _stub_fcntl_on_windows() -> None:
    """cortex.orchestrator imports ``fcntl`` at module top. On Windows
    that module doesn't exist, so cortex.main's import chain explodes
    before we can even test the trust-deny handler.

    Inject a minimal fcntl stub: the orchestrator only calls
    ``fcntl.ioctl(fd, request, buf)`` inside methods we never trigger
    in integration tests (those paths need /dev/trust anyway). Stubbing
    the module lets the import succeed; any actual ioctl call would
    raise AttributeError at call time, which is the right-ish behaviour
    (tests that need ioctls should patch them on the orchestrator).
    """
    if sys.platform != "win32":
        return
    if "fcntl" in sys.modules:
        return
    import types as _types

    stub = _types.ModuleType("fcntl")

    def _ioctl(*_args, **_kw):  # pragma: no cover - only fires on real ioctl call
        raise NotImplementedError(
            "fcntl.ioctl stub -- not available on Windows test host"
        )

    stub.ioctl = _ioctl
    # Common flags orchestrator.py may reference. If not used, ignored.
    for flag in ("F_GETFL", "F_SETFL", "F_GETFD", "F_SETFD", "LOCK_EX",
                 "LOCK_UN", "LOCK_NB"):
        setattr(stub, flag, 0)
    sys.modules["fcntl"] = stub


def load_module_from_path(name: str, path: Path) -> ModuleType:
    """Load a module by filesystem path under a unique name.

    Kept for modules that don't participate in relative-import chains
    (event_bus standalone, monte_carlo, decision_engine-as-leaf).
    For ``cortex.main`` + its dependency graph use :func:`load_cortex_package_module`.
    """
    spec = importlib.util.spec_from_file_location(name, str(path))
    assert spec is not None and spec.loader is not None, f"cannot spec {path}"
    mod = importlib.util.module_from_spec(spec)
    # Register BEFORE exec so dataclass / @classmethod class construction
    # can resolve cls.__module__ via sys.modules.
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def load_cortex_package_module(basename: str) -> ModuleType:
    """Import ``cortex.<basename>`` as a real package module.

    This path preserves relative imports (``from .autonomy import ...``)
    that ``cortex.main`` and several siblings rely on. Use this for any
    module whose own imports include ``from .``.

    Note: because this uses the normal import machinery, loading the
    same basename twice yields the same module object (Python import
    cache). Tests that need isolation should call ``load_module_from_path``
    instead.
    """
    _ensure_paths_on_sys_path()
    _stub_fcntl_on_windows()
    return importlib.import_module(f"cortex.{basename}")


def load_cortex_module(basename: str, unique_suffix: str = "") -> ModuleType:
    """Load a cortex module from ai-control/cortex/ under a unique name.

    For modules with relative imports (e.g. cortex.main) this falls back
    to :func:`load_cortex_package_module` which uses the normal import
    system so relative imports resolve against the cortex package.
    """
    _ensure_paths_on_sys_path()
    path = _CORTEX_DIR / f"{basename}.py"
    name = f"_s77_cortex_{basename}{unique_suffix}"
    try:
        return load_module_from_path(name, path)
    except ImportError:
        # Relative imports inside basename.py couldn't resolve against a
        # bare spec_from_file_location load. Fall back to the package path.
        return load_cortex_package_module(basename)


def load_daemon_module(basename: str, unique_suffix: str = "") -> ModuleType:
    """Load a daemon module (library_census, depth_observer, ...) from ai-control/daemon/."""
    _ensure_paths_on_sys_path()
    path = _DAEMON_DIR / f"{basename}.py"
    name = f"_s77_daemon_{basename}{unique_suffix}"
    return load_module_from_path(name, path)


# ---------------------------------------------------------------------------
# Wire-byte builders for pe_event header + payloads
# ---------------------------------------------------------------------------

EVENT_MAGIC = 0x45564E54  # "EVNT" in little-endian
EVENT_VERSION = 1
HEADER_SIZE = 64
HEADER_FORMAT = "<IHBBQIIIQHH24x"

# SourceLayer / type constants (mirror event_bus.SourceLayer + PeEventType)
SRC_KERNEL = 0
SRC_RUNTIME = 2
PE_EVT_TRUST_DENY = 0x06
PE_EVT_TRUST_ESCALATE = 0x07


def build_header(
    source_layer: int,
    event_type: int,
    payload_len: int,
    *,
    pid: int = 1000,
    tid: int = 1000,
    subject_id: int = 42,
    sequence: int = 1,
    flags: int = 0,
    timestamp_ns: int | None = None,
) -> bytes:
    """Build a 64-byte pe_event_header_t matching HEADER_FORMAT."""
    if timestamp_ns is None:
        timestamp_ns = int(time.time() * 1_000_000_000)
    return struct.pack(
        HEADER_FORMAT,
        EVENT_MAGIC,
        EVENT_VERSION,
        source_layer,
        event_type,
        timestamp_ns,
        pid,
        tid,
        subject_id,
        sequence,
        payload_len,
        flags,
    )


def build_trust_deny_payload(
    api_name: str = "NtCreateFile",
    category: int = 3,
    score: int = 25,
    tokens: int = 50,
) -> bytes:
    """Pack pe_evt_trust_deny_t (140 bytes, padded layout).

    Layout matches event_bus.parse_pe_trust_deny_payload's padded branch:
        char[128] api_name
        uint8    category
        uint8[3] padding
        int32    score
        uint32   tokens
    """
    name_buf = api_name.encode("utf-8")[:127].ljust(128, b"\x00")
    # Padded layout: category at offset 128, 3 bytes padding, score at 132
    body = struct.pack("<B3xiI", category, score, tokens)
    return name_buf + body


def build_trust_escalate_payload(
    api_name: str = "NtOpenProcessToken",
    from_score: int = 50,
    to_score: int = 75,
    reason: int = 1,
) -> bytes:
    """Pack pe_evt_trust_escalate_t (140 bytes).

    Layout (mirrors trust_deny shape):
        char[128] api_name
        uint32    from_score
        uint32    to_score
        uint32    reason
    """
    name_buf = api_name.encode("utf-8")[:127].ljust(128, b"\x00")
    body = struct.pack("<III", from_score, to_score, reason)
    return name_buf + body


def build_event_bytes(
    source_layer: int,
    event_type: int,
    payload: bytes,
    **header_kw,
) -> bytes:
    """Compose header + payload the way the socket recv path would see them."""
    return build_header(source_layer, event_type, len(payload), **header_kw) + payload


# ---------------------------------------------------------------------------
# Minimal autonomy / orchestrator fakes for handler tests
# ---------------------------------------------------------------------------


class FakeDecision:
    """Matches the surface of cortex.autonomy.Decision that handlers read."""

    def __init__(self, approved: bool | None = True) -> None:
        self.approved = approved
        self.domain = "SECURITY"
        self.action = "fake"
        self.description = "fake decision"
        self.autonomy_level = 2
        self.pid = None
        self.resume_action = None
        self.reject_action = None
        self.approved_at = None


class FakeAutonomy:
    """Drop-in AutonomyController stub that records every create_decision
    call and returns a configurable approval verdict.

    Tests flip ``approved`` between True / False / None to drive the three
    branches of handle_pe_trust_deny / handle_pe_trust_escalate without
    bringing up a real AutonomyController + its score bookkeeping.
    """

    def __init__(self, approved: bool | None = True) -> None:
        self.approved = approved
        self.calls: list[dict] = []

    def create_decision(self, domain, action, description, **kw):
        self.calls.append({
            "domain": domain,
            "action": action,
            "description": description,
            "kw": kw,
        })
        return FakeDecision(approved=self.approved)


class FakeOrchestrator:
    """Drop-in Orchestrator stub. Records every action and returns plausible
    responses. Captures enough surface area that handle_pe_trust_deny can
    exercise its score-check branch + quarantine path.
    """

    def __init__(self, trust_score: int = 50) -> None:
        self.trust_score = int(trust_score)
        self.calls: list[tuple] = []

    def trust_get_score(self, pid: int) -> dict:
        self.calls.append(("trust_get_score", pid))
        return {"success": True, "score": self.trust_score}

    def freeze_process(self, pid: int, force: bool = False) -> dict:
        self.calls.append(("freeze_process", pid, force))
        return {"success": True, "pid": pid}

    def trust_quarantine(self, pid: int) -> dict:
        self.calls.append(("trust_quarantine", pid))
        return {"success": True, "pid": pid}

    def trust_release(self, pid: int) -> dict:
        self.calls.append(("trust_release", pid))
        return {"success": True, "pid": pid}

    def invalidate_score_cache(self, pid: int) -> None:
        self.calls.append(("invalidate_score_cache", pid))

    async def notify(self, title: str, body: str, level: str = "normal") -> dict:
        self.calls.append(("notify", title, body, level))
        return {"success": True}

    async def notify_decision(self, decision) -> dict:
        self.calls.append(("notify_decision", decision))
        return {"success": True}

    def resume_after_approval(self, pid: int) -> None:
        self.calls.append(("resume_after_approval", pid))
