"""
differential_observer.py -- Bateson differential filter for observers.

Gregory Bateson's definition of information is "a difference that makes
a difference." Most Archimation observers publish *absolute* values --
total_subjects=42, library_counts={...}, mean_depth=0.31 -- which
carry the current state but lose the signal that the cortex actually
wants: *what changed?*

This module wraps any observer exposing ``snapshot() -> dict`` and
produces a delta-snapshot on each ``tick()``: numeric fields become
arithmetic differences, dict fields are diffed recursively, list fields
are diffed as sets (added / removed), and string fields record an
equality flag.

Design follows ``library_census.py`` (S75 Agent B) and
``depth_observer.py`` (this session, sibling file):

  * Class with ``tick()`` / ``deltas()`` / ``start_polling()`` /
    ``stop_polling()``.
  * RLock thread-safety.
  * ``register_with_daemon(app, event_bus)`` helper.
  * Graceful behavior on first tick (no prior -> returns ``{}``).
  * Stdlib only.

Research reference: Research-H §1.4 (S74 dispatch, parking lot).
S75 roadmap §1.4 (Tier-3 parking-lot item; this is the S76 build).
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Default poll interval. The differential filter is a cheap observer
# wrapper (one extra snapshot() call + diff); it can poll faster than
# the library_census 5s cadence, but 2s is plenty for the cortex.
POLL_INTERVAL_DEFAULT = 2.0


# -- Delta primitives -------------------------------------------------------


_SENTINEL_MISSING = object()
"""Marker for keys that exist in exactly one of the two snapshots."""


def _is_number(x: Any) -> bool:
    """True if *x* is a plain int or float (but not bool, which is-a int)."""
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _delta_value(old: Any, new: Any) -> Any:
    """Compute the Bateson delta between two values of arbitrary shape.

    Semantics:
      * numeric (int/float): arithmetic difference ``new - old``.
      * dict: recursive delta dict; keys appearing only on one side
        get {"added": <val>} or {"removed": <val>} markers.
      * list/tuple/set: set-difference dict
        ``{"added": [...], "removed": [...]}`` for hashable items;
        for unhashable items (nested lists) we fall back to an
        ``{"changed": True, "new_len": ..., "old_len": ...}`` summary.
      * bool / str / None / other: ``{"changed": <bool>, "old": old,
        "new": new}``.  We include both sides so a cortex consumer
        doesn't have to pair the delta with the absolute snapshot.

    Missing-key semantics: if either side is ``_SENTINEL_MISSING`` the
    delta becomes ``{"added": new}`` or ``{"removed": old}``. This is
    how ``_delta_dict`` handles keys that disappear or appear between
    snapshots.
    """
    # Missing-key markers
    if old is _SENTINEL_MISSING and new is _SENTINEL_MISSING:
        return None
    if old is _SENTINEL_MISSING:
        return {"added": new}
    if new is _SENTINEL_MISSING:
        return {"removed": old}

    # None handling -- treat None identically to a missing field.
    if old is None and new is None:
        return 0 if False else None  # no change
    if old is None:
        return {"added": new}
    if new is None:
        return {"removed": old}

    # Numeric delta (not bool -- bool is special-cased below as string-like)
    if _is_number(old) and _is_number(new):
        return new - old

    # Dict -- recurse
    if isinstance(old, dict) and isinstance(new, dict):
        return _delta_dict(old, new)

    # List / tuple / set -- set-difference where feasible
    if (isinstance(old, (list, tuple, set))
            and isinstance(new, (list, tuple, set))):
        return _delta_collection(old, new)

    # Bool / str / anything else -- equality flag + both sides
    changed = (old != new)
    return {"changed": changed, "old": old, "new": new}


def _delta_dict(old: dict, new: dict) -> dict:
    """Recursive dict delta. Keys in exactly one side become added/removed.

    Returns a dict whose keys are the union of old+new keys. Values are
    either:
      * numeric scalar (for numeric fields that changed)
      * nested delta dict (for dict / list / string / bool fields)
      * ``0`` (int, for a numeric field that didn't change)
      * ``None`` (for fields where both sides are None or equal and
        we can't produce a meaningful scalar -- callers should check
        presence, not value, for None equality)
    """
    all_keys = set(old.keys()) | set(new.keys())
    out: dict = {}
    for k in all_keys:
        o = old.get(k, _SENTINEL_MISSING)
        n = new.get(k, _SENTINEL_MISSING)
        out[k] = _delta_value(o, n)
    return out


def _delta_collection(old, new) -> dict:
    """Set-difference for list/tuple/set. Falls back gracefully on unhashable.

    Preserves ordering for the 'added' / 'removed' lists by iterating
    the original collection order (stable diff output).
    """
    try:
        old_set = set(old)
        new_set = set(new)
    except TypeError:
        # Unhashable elements (e.g. list-of-dicts). Fall back to
        # summary -- the cortex can still see that *something* changed
        # and consult the absolute snapshot for details.
        return {
            "changed": list(old) != list(new),
            "old_len": len(old),
            "new_len": len(new),
        }

    added = [x for x in new if x in (new_set - old_set)]
    removed = [x for x in old if x in (old_set - new_set)]
    # Dedup while preserving first-seen order (set membership above
    # may list duplicates otherwise).
    seen: set = set()
    added = [x for x in added if not (x in seen or seen.add(x))]
    seen.clear()
    removed = [x for x in removed if not (x in seen or seen.add(x))]
    return {"added": added, "removed": removed}


# -- Filter -----------------------------------------------------------------


class DifferentialFilter:
    """Wrap any observer with a ``snapshot()`` method; publish deltas.

    Lifecycle::

        flt = DifferentialFilter(upstream_observer)
        flt.tick()                         # first call: prior=None,
                                           # seeds baseline, returns {}
        flt.tick()                         # second call: returns diff
        flt.deltas()                       # latest diff (or {} if none)

        flt.start_polling(interval=2.0)    # background tick() loop
        flt.stop_polling()                 # cleanup

    Thread-safe via RLock: the poller thread and a REST handler can both
    call ``tick()`` / ``deltas()`` without tearing the internal state.

    The wrapped observer is NOT required at construction (``None`` is
    fine -- every ``tick()`` becomes a no-op). A real observer can be
    set later via ``set_observer()``. This matches the algedonic_reader
    pattern of "graceful when upstream is absent."
    """

    def __init__(
        self,
        observer: Any = None,
        event_bus: Any = None,
        name: Optional[str] = None,
    ) -> None:
        self._observer = observer
        self._event_bus = event_bus
        # Descriptive label (e.g. "library_census") -- used as the
        # "observer" field in published events + /metrics/deltas key.
        self._name = name or (
            getattr(observer, "__class__", type(None)).__name__ or "unknown"
        )
        self._lock = threading.RLock()

        # Baseline + latest delta.
        self._prev_snapshot: Optional[dict] = None
        self._latest_delta: dict = {}
        self._tick_count: int = 0
        self._last_tick_ts: float = 0.0

        # Poll thread state.
        self._poll_thread: Optional[threading.Thread] = None
        self._poll_stop: threading.Event = threading.Event()
        self._poll_interval: float = POLL_INTERVAL_DEFAULT

        self._stats = {
            "ticks": 0,
            "ticks_with_change": 0,
            "snapshot_errors": 0,
            "publish_errors": 0,
        }

    # -- Upstream management ------------------------------------------------

    def set_observer(self, observer: Any,
                     name: Optional[str] = None) -> None:
        """Swap in a different upstream observer.

        Resets the baseline so the next ``tick()`` starts fresh. Used
        by the registration helper when the caller wants to point the
        filter at a specific observer instance at daemon boot.
        """
        with self._lock:
            self._observer = observer
            if name is not None:
                self._name = name
            elif observer is not None:
                self._name = observer.__class__.__name__
            self._prev_snapshot = None
            self._latest_delta = {}

    @property
    def name(self) -> str:
        return self._name

    # -- Core tick ----------------------------------------------------------

    def _safe_snapshot(self) -> Optional[dict]:
        """Call upstream.snapshot() with error handling."""
        obs = self._observer
        if obs is None:
            return None
        snap_fn = getattr(obs, "snapshot", None)
        if not callable(snap_fn):
            return None
        try:
            snap = snap_fn()
        except Exception:
            self._stats["snapshot_errors"] += 1
            logger.debug(
                "differential_observer[%s]: upstream snapshot raised",
                self._name, exc_info=True,
            )
            return None
        if not isinstance(snap, dict):
            return None
        return snap

    def tick(self) -> dict:
        """Pull a fresh snapshot from upstream; compute the delta.

        Returns the just-computed delta (same as ``deltas()`` after the
        call). First tick has no prior -> seeds baseline and returns
        ``{}``. If upstream is absent or raises, returns ``{}`` without
        mutating the baseline.
        """
        with self._lock:
            self._stats["ticks"] += 1
            self._tick_count += 1
            self._last_tick_ts = time.time()

            snap = self._safe_snapshot()
            if snap is None:
                # Upstream unavailable -- keep prior baseline as-is so
                # we don't lose it if the upstream blipped.
                return {}

            prev = self._prev_snapshot
            if prev is None:
                # First tick: seed baseline, no delta yet.
                self._prev_snapshot = snap
                self._latest_delta = {}
                return {}

            delta = _delta_dict(prev, snap)
            self._prev_snapshot = snap
            self._latest_delta = delta
            if self._has_meaningful_change(delta):
                self._stats["ticks_with_change"] += 1
                self._publish(delta)
            return delta

    @staticmethod
    def _has_meaningful_change(delta: dict) -> bool:
        """Return True if *delta* contains any non-zero / added / removed.

        Used to decide whether to publish the delta on the event bus --
        a zero-delta tick (nothing moved) doesn't need to wake the
        cortex.
        """
        for v in delta.values():
            if v is None:
                continue
            if _is_number(v):
                if v != 0:
                    return True
                continue
            if isinstance(v, dict):
                if "added" in v or "removed" in v:
                    return True
                if v.get("changed"):
                    return True
                # Nested dict delta -- recurse.
                if DifferentialFilter._has_meaningful_change(v):
                    return True
        return False

    def deltas(self) -> dict:
        """Return the latest computed delta dict.

        Callable from any thread; returns a shallow copy so callers can
        mutate it freely. Empty dict before the first successful
        second-or-later tick.
        """
        with self._lock:
            # Shallow-copy is sufficient; nested dicts in a delta are
            # treated as read-only by convention (the callers that
            # mutate are tests).
            return dict(self._latest_delta)

    # -- Polling lifecycle --------------------------------------------------

    def start_polling(self,
                      observer: Any = None,
                      interval_seconds: float = POLL_INTERVAL_DEFAULT,
                      ) -> None:
        """Spawn a background thread that ticks every *interval_seconds*.

        Accepts an optional *observer* to set before starting (a
        convenience that mirrors the way callers often construct the
        filter with observer=None then want to wire it at lifespan).

        Idempotent: a second call while running is a no-op.
        """
        with self._lock:
            if observer is not None:
                self.set_observer(observer)
            if self._poll_thread is not None and self._poll_thread.is_alive():
                return
            self._poll_interval = max(0.25, float(interval_seconds))
            self._poll_stop.clear()
            self._poll_thread = threading.Thread(
                target=self._poll_loop,
                name=f"differential[{self._name}]",
                daemon=True,
            )
            self._poll_thread.start()
            logger.info(
                "differential_observer[%s]: polling every %.2fs",
                self._name, self._poll_interval,
            )

    def stop_polling(self) -> None:
        """Stop the background poll thread. Safe to call multiple times."""
        self._poll_stop.set()
        thread = self._poll_thread
        self._poll_thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    def _poll_loop(self) -> None:
        while not self._poll_stop.is_set():
            try:
                self.tick()
            except Exception:
                logger.debug("differential_observer[%s]: tick failed",
                             self._name, exc_info=True)
            if self._poll_stop.wait(self._poll_interval):
                return

    # -- Event publishing ---------------------------------------------------

    def _publish(self, delta: dict) -> None:
        """Best-effort publish. Mirrors library_census._publish."""
        bus = self._event_bus
        if bus is None:
            return
        event = {
            "source": "differential_observer",
            "observer": self._name,
            "ts": time.time(),
            "delta": delta,
        }
        for name in ("publish", "emit"):
            fn = getattr(bus, name, None)
            if callable(fn):
                try:
                    fn(event)
                    return
                except Exception:
                    self._stats["publish_errors"] += 1
                    logger.debug(
                        "differential_observer[%s]: bus.%s failed",
                        self._name, name, exc_info=True,
                    )

    # -- Introspection ------------------------------------------------------

    def stats(self) -> dict:
        with self._lock:
            return {
                **self._stats,
                "name": self._name,
                "tick_count": self._tick_count,
                "last_tick_ts": self._last_tick_ts,
                "poll_interval": self._poll_interval,
                "polling": bool(
                    self._poll_thread is not None
                    and self._poll_thread.is_alive()
                ),
                "baseline_set": self._prev_snapshot is not None,
            }


# -- Registry for multi-observer wiring -------------------------------------


class DifferentialRegistry:
    """A small registry keyed by observer-name.

    The integration agent will register N filters (library_census,
    depth_observer, memory_observer, etc.); the REST endpoint
    ``GET /metrics/deltas?observer=<name>`` needs to route to the
    right filter. This class centralizes that lookup and keeps the
    per-filter lifecycle under one lock.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._filters: dict[str, DifferentialFilter] = {}

    def register(self, name: str, flt: DifferentialFilter) -> None:
        with self._lock:
            self._filters[name] = flt

    def get(self, name: str) -> Optional[DifferentialFilter]:
        with self._lock:
            return self._filters.get(name)

    def names(self) -> list:
        with self._lock:
            return sorted(self._filters.keys())

    def snapshot_all(self) -> dict:
        """Return {name: filter.deltas()} for every registered filter."""
        with self._lock:
            return {
                name: flt.deltas() for name, flt in self._filters.items()
            }

    def stop_all(self) -> None:
        with self._lock:
            filters = list(self._filters.values())
        for flt in filters:
            flt.stop_polling()


# -- Wire-up helper ---------------------------------------------------------


def register_with_daemon(
    app: Any,
    event_bus: Any = None,
    observers: Optional[dict] = None,
    poll_interval: float = POLL_INTERVAL_DEFAULT,
) -> "DifferentialRegistry":
    """Construct a registry + per-observer filters; register endpoints.

    *observers* is an optional ``{name: observer}`` mapping. Each
    observer gets its own ``DifferentialFilter`` created eagerly so
    the endpoint has something to serve at daemon boot. The caller
    still owns the ``start_polling`` / ``stop_polling`` lifecycle via
    the FastAPI lifespan context, same as library_census.

    Endpoint::

        GET /metrics/deltas                       -> {name: delta, ...}
        GET /metrics/deltas?observer=<name>       -> filter.deltas()
    """
    registry = DifferentialRegistry()

    for name, obs in (observers or {}).items():
        flt = DifferentialFilter(observer=obs, event_bus=event_bus, name=name)
        flt._poll_interval = max(0.25, float(poll_interval))
        registry.register(name, flt)

    if app is not None:
        try:
            @app.get("/metrics/deltas")  # type: ignore[misc]
            async def _deltas(observer: Optional[str] = None) -> dict:
                if observer:
                    flt = registry.get(observer)
                    if flt is None:
                        return {
                            "error": f"unknown observer: {observer}",
                            "available": registry.names(),
                        }
                    return {
                        "source": "differential_observer",
                        "observer": observer,
                        "ts": time.time(),
                        "delta": flt.deltas(),
                    }
                return {
                    "source": "differential_observer",
                    "ts": time.time(),
                    "observers": registry.names(),
                    "deltas": registry.snapshot_all(),
                }
        except Exception:
            logger.debug(
                "differential_observer: FastAPI route registration skipped",
                exc_info=True,
            )

    return registry


__all__ = [
    "DifferentialFilter",
    "DifferentialRegistry",
    "register_with_daemon",
    "POLL_INTERVAL_DEFAULT",
]
