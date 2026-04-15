"""Unified /system/summary endpoint for the AI Control daemon.

A single auth-exempt JSON endpoint that aggregates a *cheap* snapshot of
every subsystem the daemon loaded.  Intended as a single-pane-of-glass
health view for:

  - monitoring tools (cortex, dashboards)
  - the QEMU smoke-test harness
  - the future ``/system/coherence`` aggregator
  - human operators poking at the box with ``curl``

Design contract
---------------
* No I/O inside the summary call.  Every subsystem caches its own state;
  we only read attributes / call pre-populated accessors.  The whole
  response must build in well under 10ms.
* Every subsystem read is try/except wrapped -- a crashed subsystem
  **must not** 500 the endpoint.  A broken entry becomes
  ``{"loaded": true, "error": "..."}`` (or ``{"loaded": false, ...}``).
* Returns HTTP 200 even if *every* subsystem is missing.  Callers use
  the top-level ``"state"`` field to tell ``starting`` from ``ready``.
* Auth-exempt -- Agent 2 adds the path to ``ENDPOINT_TRUST`` in
  ``auth.py`` and/or the middleware exempt list.  This module does not
  touch middleware.

Agent 2 integration
-------------------
``create_app()`` populates an ``app_state`` dict with references to the
subsystems it constructs, marks the ``"ready"`` flag once the lifespan
startup event has fired, then calls::

    from system_summary import make_summary_router
    app.include_router(make_summary_router(app_state))

Field stability
---------------
Field names are stable across minor versions.  New subsystems add new
fields; existing fields never disappear.  See ``docs/system-summary.md``
for the full schema and curl examples.
"""

from __future__ import annotations

import logging
import os
import platform
import time
from typing import Any, Callable, Mapping, MutableMapping, Optional

logger = logging.getLogger("ai-control.summary")

# Version matches the FastAPI ``app.version`` in ``api_server.create_app``.
_DAEMON_VERSION = "0.1.0"

# Monotonic boot marker.  Module-level so `import system_summary` right
# at daemon startup establishes t0 even before ``app_state`` is built.
_BOOT_MONOTONIC = time.monotonic()


# ---------------------------------------------------------------------------
# Per-subsystem introspection helpers
# ---------------------------------------------------------------------------
#
# Each helper accepts the subsystem instance (or ``None``) and returns a
# plain ``dict`` suitable for JSON serialisation.  Returning ``None``
# from any helper is treated as "loaded but featureless" and becomes
# ``{"loaded": True}``.  Raising is fine -- the top-level builder
# wraps each call in try/except and converts exceptions into
# ``{"loaded": True, "error": "<ExcType>: <msg>"}``.
#
# Keep each helper to a handful of attribute reads.  NO subprocess, NO
# filesystem, NO network.  Subsystems already cache telemetry.


def _cheap_getattr(obj, name, default=None):
    """Attribute read that never raises.  Converts AttributeError to default."""
    try:
        return getattr(obj, name, default)
    except Exception:
        return default


def _scanner_summary(scanner) -> dict:
    if scanner is None:
        return {"loaded": False}
    # MemoryScanner exposes ``.db.patterns`` (dict) + optional ``._stats``.
    db = _cheap_getattr(scanner, "db")
    patterns = 0
    if db is not None:
        pats = _cheap_getattr(db, "patterns")
        if isinstance(pats, dict):
            patterns = len(pats)
        elif pats is not None:
            try:
                patterns = len(pats)
            except TypeError:
                patterns = 0
    stats = _cheap_getattr(scanner, "_stats") or {}
    return {
        "loaded": True,
        "patterns": patterns,
        "scans_total": int(stats.get("scans_total", 0)) if isinstance(stats, Mapping) else 0,
        "hits_total": int(stats.get("hits_total", 0)) if isinstance(stats, Mapping) else 0,
    }


def _memory_observer_summary(mo) -> dict:
    if mo is None:
        return {"loaded": False}
    procs = _cheap_getattr(mo, "_processes") or {}
    try:
        tracked = len(procs)
    except TypeError:
        tracked = 0
    running = bool(_cheap_getattr(mo, "_running", False))
    return {
        "loaded": True,
        "tracked_pids": tracked,
        "enabled": running,
    }


def _memory_diff_summary(md) -> dict:
    if md is None:
        return {"loaded": False}
    snaps = _cheap_getattr(md, "_snapshots") or {}
    try:
        pids = len(snaps)
    except TypeError:
        pids = 0
    return {
        "loaded": True,
        "enabled": True,
        "tracked_pids": pids,
    }


def _stub_discovery_summary(sd) -> dict:
    if sd is None:
        return {"loaded": False}
    return {"loaded": True}


def _binary_signatures_summary(bs) -> dict:
    if bs is None:
        return {"loaded": False}
    profiles = _cheap_getattr(bs, "_profiles") or {}
    try:
        count = len(profiles)
    except TypeError:
        count = 0
    return {"loaded": True, "profiles": count}


def _win_api_db_summary(db) -> dict:
    if db is None:
        return {"loaded": False}
    # WinApiDatabase implements __len__; fall back to _signatures.
    try:
        sigs = len(db)
    except TypeError:
        sigs = len(_cheap_getattr(db, "_signatures") or {})
    return {"loaded": True, "signatures": sigs}


def _stub_generator_summary(sg) -> dict:
    if sg is None:
        return {"loaded": False}
    return {"loaded": True}


def _syscall_monitor_summary(sm) -> dict:
    if sm is None:
        return {"loaded": False}
    running = bool(_cheap_getattr(sm, "_running", False))
    procs = _cheap_getattr(sm, "_processes") or {}
    try:
        tracked = len(procs)
    except TypeError:
        tracked = 0
    return {
        "loaded": True,
        "enabled": running,
        "tracked_pids": tracked,
    }


def _syscall_translator_summary(st) -> dict:
    if st is None:
        return {"loaded": False}
    # SyscallTranslator.get_stats() is pure-Python (pre-populated dicts).
    get_stats = _cheap_getattr(st, "get_stats")
    if callable(get_stats):
        stats = get_stats() or {}
        return {
            "loaded": True,
            "linux": int(stats.get("linux_syscalls_mapped", 0)),
            "nt": int(stats.get("nt_syscalls_mapped", 0)),
            "ioctls": int(stats.get("known_ioctls", 0)),
        }
    return {"loaded": True}


def _behavioral_model_summary(bm) -> dict:
    if bm is None:
        return {"loaded": False}
    return {"loaded": True}


def _thermal_summary(th) -> dict:
    if th is None:
        return {"loaded": False}
    hw = _cheap_getattr(th, "_hw") or _cheap_getattr(th, "hardware_class")
    # ``_last_state`` is populated by the poll loop; may be None before
    # the first refresh.  NEVER call snapshot() -- that would do I/O.
    last_state = _cheap_getattr(th, "_last_state")
    snap = _cheap_getattr(th, "_snapshot") or {}
    temp_c: Optional[float] = None
    if isinstance(snap, Mapping):
        t = snap.get("max_temp")
        if isinstance(t, (int, float)):
            temp_c = float(t)
    return {
        "loaded": True,
        "hw_class": hw,
        "temp_c": temp_c,
        "state": last_state or "unknown",
    }


def _power_summary(pw) -> dict:
    if pw is None:
        return {"loaded": False}
    baseline = _cheap_getattr(pw, "_baseline_gov") or "auto"
    boost = bool(_cheap_getattr(pw, "_pe_boost_active", False))
    return {
        "loaded": True,
        "baseline": baseline,
        "boost_active": boost,
    }


def _contusion_summary(cn) -> dict:
    if cn is None:
        return {"loaded": False}
    # The app profile dictionary is module-level; count it without
    # calling list_apps() (which builds a fresh list every call).
    apps = 0
    try:
        from contusion_dictionary import APP_PROFILES  # lazy, optional
        apps = len(APP_PROFILES)
    except Exception:
        apps = 0
    return {"loaded": True, "apps_count": apps}


def _firewall_summary(fw) -> dict:
    if fw is None:
        return {"loaded": False}
    # AppTracker is set IFF cgroup v2 enforcement is active.
    enforcement = _cheap_getattr(fw, "_tracker") is not None
    return {"loaded": True, "cgroup_enforcement": enforcement}


# Ordered mapping: (app_state key, display key, builder).
# Order is preserved in the response so clients can rely on it.
_SUBSYSTEMS: tuple[tuple[str, str, Callable[[Any], dict]], ...] = (
    ("scanner",            "scanner",            _scanner_summary),
    ("memory_observer",    "memory_observer",    _memory_observer_summary),
    ("memory_diff",        "memory_diff",        _memory_diff_summary),
    ("stub_discovery",     "stub_discovery",     _stub_discovery_summary),
    ("binary_signatures",  "binary_signatures",  _binary_signatures_summary),
    ("win_api_db",         "win_api_db",         _win_api_db_summary),
    ("stub_generator",     "stub_generator",     _stub_generator_summary),
    ("syscall_monitor",    "syscall_monitor",    _syscall_monitor_summary),
    ("syscall_translator", "syscall_translator", _syscall_translator_summary),
    ("behavioral_model",   "behavioral_model",   _behavioral_model_summary),
    ("thermal",            "thermal",            _thermal_summary),
    ("power",              "power",              _power_summary),
    ("contusion",          "contusion",          _contusion_summary),
    ("firewall",           "firewall",           _firewall_summary),
)


# ---------------------------------------------------------------------------
# Top-level builders
# ---------------------------------------------------------------------------


def _counters(app_state: Mapping[str, Any]) -> dict:
    """Derive the top-level ``counters`` block.  Pure attribute reads."""
    out: dict = {
        "auth_tokens_issued": 0,
        "auth_tokens_revoked": 0,
        "audit_entries_total": 0,
        "pe_processes_active": 0,
    }

    # auth.py keeps revoked tokens in a module-level dict; issued-token
    # count is a monotonic counter if the auth module exposes one.
    try:
        import auth as _auth_mod  # type: ignore[import-not-found]
        revoked = _cheap_getattr(_auth_mod, "_revoked_tokens") or {}
        try:
            out["auth_tokens_revoked"] = int(len(revoked))
        except TypeError:
            out["auth_tokens_revoked"] = 0
        issued = _cheap_getattr(_auth_mod, "_tokens_issued_total")
        if isinstance(issued, int):
            out["auth_tokens_issued"] = issued
    except Exception:
        pass

    # audit deque length gives a cheap "entries seen since last rotate".
    audit = app_state.get("audit")
    if audit is not None:
        recent = _cheap_getattr(audit, "_recent")
        if recent is not None:
            try:
                out["audit_entries_total"] = int(len(recent))
            except TypeError:
                pass

    # Live PE-process count: prefer memory_observer's cached map; no /proc walk.
    mo = app_state.get("memory_observer")
    if mo is not None:
        procs = _cheap_getattr(mo, "_processes") or {}
        try:
            out["pe_processes_active"] = int(len(procs))
        except TypeError:
            pass

    return out


def _resolve_hostname() -> str:
    """Cheap, non-blocking hostname lookup.  Falls back to 'unknown'."""
    try:
        h = platform.node()
        if h:
            return h
    except Exception:
        pass
    try:
        return os.uname().nodename  # type: ignore[attr-defined]
    except Exception:
        return "unknown"


async def _build_summary(app_state: Mapping[str, Any]) -> dict:
    """Synchronously build the summary dict.

    ``async`` so the route handler can ``await`` it, but the body is
    fully synchronous -- no awaits, no I/O.  This keeps the latency
    budget under 1ms on real hardware.
    """
    subsystems: dict[str, dict] = {}
    for state_key, display_key, builder in _SUBSYSTEMS:
        try:
            inst = app_state.get(state_key)
            entry = builder(inst)
            if entry is None:
                entry = {"loaded": inst is not None}
            elif not isinstance(entry, dict):
                entry = {"loaded": True, "value": entry}
            subsystems[display_key] = entry
        except Exception as exc:  # pylint: disable=broad-except
            # A broken subsystem must NEVER crash the summary call.
            subsystems[display_key] = {
                "loaded": True,
                "error": f"{type(exc).__name__}: {exc}"[:200],
            }

    # Daemon-level fields.
    session = app_state.get("session") or os.environ.get("XDG_SESSION_TYPE") or "headless"
    if session not in ("wayland", "x11", "headless"):
        # Be permissive but don't echo arbitrary env back unsanitised.
        session = "headless"

    ready_flag = app_state.get("ready")
    state = "ready" if ready_flag else "starting"

    start_mono = app_state.get("start_monotonic")
    if not isinstance(start_mono, (int, float)):
        start_mono = _BOOT_MONOTONIC
    uptime_s = max(0, int(time.monotonic() - start_mono))

    return {
        "daemon": "ai-control",
        "version": _DAEMON_VERSION,
        "uptime_s": uptime_s,
        "session": str(session),
        "hostname": _resolve_hostname(),
        "subsystems": subsystems,
        "counters": _counters(app_state),
        "state": state,
    }


# ---------------------------------------------------------------------------
# FastAPI factory (Agent 2 calls this)
# ---------------------------------------------------------------------------


def make_summary_router(app_state: MutableMapping[str, Any]):
    """Return a FastAPI ``APIRouter`` with ``GET /system/summary``.

    Parameters
    ----------
    app_state
        Mapping from subsystem name to instance, populated by
        ``api_server.create_app()``.  The mapping is read on every
        request, so late-initialised subsystems (e.g. those started
        from the lifespan handler) appear automatically once present.

        Expected keys (all optional):
          - ``scanner`` .. ``firewall`` (see :data:`_SUBSYSTEMS`)
          - ``audit`` (AuditLogger instance, for entry counter)
          - ``session`` (``"x11"`` / ``"wayland"`` / ``"headless"``)
          - ``ready`` (bool set to True after startup event)
          - ``start_monotonic`` (float; defaults to module load time)

    Agent 2 is responsible for adding ``/system/summary`` to the
    auth-exempt list in ``auth.py`` (``ENDPOINT_TRUST["/system/summary"]
    = 0``) and ensuring the router is mounted on the app.

    Returns
    -------
    APIRouter
        A router exposing the ``GET /system/summary`` endpoint.  Returns
        HTTP 200 with the summary JSON -- *never* raises from the
        handler.
    """
    try:
        from fastapi import APIRouter
    except ImportError as exc:  # pragma: no cover - FastAPI is a hard dep
        logger.error("FastAPI unavailable for summary router: %s", exc)
        raise

    router = APIRouter(tags=["summary"])

    @router.get(
        "/system/summary",
        include_in_schema=True,
        summary="Unified subsystem health snapshot (auth-exempt)",
    )
    async def system_summary() -> dict:  # noqa: D401 -- FastAPI route
        """Return a single-pane-of-glass view of every loaded subsystem."""
        try:
            return await _build_summary(app_state)
        except Exception as exc:  # pragma: no cover - defensive belt
            # Absolute fail-safe: never 500.  Log + return skeleton.
            logger.exception("system_summary builder crashed: %s", exc)
            return {
                "daemon": "ai-control",
                "version": _DAEMON_VERSION,
                "uptime_s": max(0, int(time.monotonic() - _BOOT_MONOTONIC)),
                "session": "unknown",
                "hostname": _resolve_hostname(),
                "subsystems": {},
                "counters": {},
                "state": "starting",
                "error": f"{type(exc).__name__}: {exc}"[:200],
            }

    return router


__all__ = ["make_summary_router", "_build_summary"]
