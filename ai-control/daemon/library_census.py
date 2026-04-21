"""
library_census.py -- Cross-PID ecosystem observer for loaded libraries.

S75 Item 2 deliverable. Closes Maturana-Varela Criterion 1 (self-production
census) by aggregating ``MemoryObserver.dlls_loaded`` histograms across all
tracked PIDs and exposing them as a population census.

Biological analogue: the current memory_observer counts organelles per
cell but cannot distinguish ribosomes from mitochondria -- it knows HOW
MANY DLLs a PID has loaded but not WHICH subjects share WHICH libraries.
This module answers "32 subjects have kernel32.dll, 3 have vulkan-1.dll,
only 1 has aclayers.dll" (the tail is the interesting part).

Event schema (per ``docs/s75_roadmap.md`` §1.1.2):

    {"source": "library_census", "ts": <unix>,
     "library_counts": {"kernel32.dll": 27, "ntdll.dll": 27, ...},
     "total_subjects": 42, "total_libraries": 113,
     "rare_libraries": [names occurring in <=2 subjects],
     "unique_library_ratio": 0.34}

See also:
  * ``ai-control/daemon/memory_observer.py`` -- source of ``dlls_loaded``
  * ``ai-control/daemon/algedonic_reader.py`` -- observer-with-endpoint
    template (S74 Agent K, the pattern we mirror)
  * ``ai-control/daemon/trust_observer.py`` -- sibling census keyed on
    immune/risk/sex axes (``get_anomaly_status``)
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# Libraries occurring in <= this many subjects are reported as "rare".
# Research-H §1.1 uses 2; keeping it configurable on the class.
RARE_THRESHOLD_DEFAULT = 2

# policy_evaluate drift fires when a subject loads a DLL seen in fewer
# than this fraction of other subjects. 5% is the S75 acceptance test
# target ("configure library_census.policy to fire if ... <5% of other
# subjects") from the roadmap.
POLICY_DRIFT_FRACTION_DEFAULT = 0.05

# Default background-poll cadence. 5s matches memory_observer's own
# SIMULATION_POLL_INTERVAL so we don't sample faster than our source.
POLL_INTERVAL_DEFAULT = 5.0


class LibraryCensus:
    """Cross-PID library histogram + drift policy.

    Thread-safe via an RLock. All public methods can be called from
    either the asyncio daemon loop or a background polling thread.

    Lifecycle: construct -> ``register_with_memory_observer()`` (optional,
    enables event-driven updates) -> ``start_polling()`` for periodic
    snapshots -> ``stop_polling()`` on shutdown. Callable without an
    event bus; bus is only used to publish snapshots.
    """

    def __init__(
        self,
        memory_observer: Any = None,
        event_bus: Any = None,
        rare_threshold: int = RARE_THRESHOLD_DEFAULT,
        policy_drift_fraction: float = POLICY_DRIFT_FRACTION_DEFAULT,
    ) -> None:
        self._memory_observer = memory_observer
        self._event_bus = event_bus
        self._rare_threshold = int(rare_threshold)
        self._policy_drift_fraction = float(policy_drift_fraction)

        self._lock = threading.RLock()

        # Cached snapshot -- refreshed by snapshot() / poll tick.
        # Keep last snapshot so policy_evaluate() can consult it
        # without re-walking the memory_observer on every call.
        self._last_snapshot: dict = self._empty_snapshot()

        # Poll thread state.
        self._poll_thread: Optional[threading.Thread] = None
        self._poll_stop: threading.Event = threading.Event()
        self._poll_interval: float = POLL_INTERVAL_DEFAULT

        # Stats for introspection / /metrics/ecosystem debug view.
        self._stats = {
            "snapshots_taken": 0,
            "snapshots_published": 0,
            "policy_fires": 0,
            "publish_errors": 0,
        }

    # -- Census core --------------------------------------------------------

    @staticmethod
    def _empty_snapshot() -> dict:
        """Zero-state snapshot used when memory_observer has no PIDs."""
        return {
            "source": "library_census",
            "ts": time.time(),
            "library_counts": {},
            "total_subjects": 0,
            "total_libraries": 0,
            "rare_libraries": [],
            "unique_library_ratio": 0.0,
        }

    def _collect_pid_maps(self) -> dict[int, set[str]]:
        """Gather {pid: {dll_name, ...}} from the memory_observer.

        Returns an empty dict if the observer is absent, has zero PIDs,
        or raises during introspection. Silent-on-error is deliberate:
        the census should never crash its owner.

        The memory_observer's internal ``_processes`` map is the source
        of truth (see ``memory_observer.py:405``). We read it under a
        best-effort try/except; if a concurrent scan mutates it the
        caller just sees a slightly stale sample.
        """
        mo = self._memory_observer
        if mo is None:
            return {}

        result: dict[int, set[str]] = {}
        try:
            procs = getattr(mo, "_processes", None)
            if procs is None:
                return {}
            # Snapshot the dict items to avoid "dictionary changed size
            # during iteration" from concurrent memory_observer scans.
            items = list(procs.items())
        except Exception:
            logger.debug("library_census: memory_observer introspection failed",
                         exc_info=True)
            return {}

        for pid, pmap in items:
            try:
                dlls = getattr(pmap, "dlls_loaded", None) or {}
                # Only names (keys) contribute to the census. Normalize
                # to lower-case to match case-insensitive DLL resolution.
                names = {str(n).lower() for n in dlls.keys() if n}
                if names:
                    result[int(pid)] = names
            except Exception:
                logger.debug("library_census: skipping pid=%s (bad pmap)", pid,
                             exc_info=True)
                continue
        return result

    def snapshot(self) -> dict:
        """Compute and cache a fresh ecosystem census.

        Returns a JSON-serializable dict matching the schema in the
        module docstring. Also updates ``_last_snapshot`` so subsequent
        ``policy_evaluate()`` calls see the fresh distribution without
        re-walking the memory_observer.
        """
        with self._lock:
            pid_maps = self._collect_pid_maps()
            if not pid_maps:
                snap = self._empty_snapshot()
                self._last_snapshot = snap
                self._stats["snapshots_taken"] += 1
                return snap

            # Aggregate: subject-count per library (not occurrence count --
            # a PID that mapped kernel32 twice still counts once).
            counts: dict[str, int] = {}
            for names in pid_maps.values():
                for n in names:
                    counts[n] = counts.get(n, 0) + 1

            total_subjects = len(pid_maps)
            total_libraries = len(counts)

            # Rare = present in at most rare_threshold subjects.
            rare = sorted(
                n for n, c in counts.items() if c <= self._rare_threshold
            )

            # Unique-library ratio = libraries seen in exactly 1 subject
            # / total_libraries. Matches Shannon / Maturana framing:
            # a population that's all-shared has ratio=0, all-private =1.
            if total_libraries > 0:
                singletons = sum(1 for c in counts.values() if c == 1)
                uniq_ratio = round(singletons / total_libraries, 4)
            else:
                uniq_ratio = 0.0

            # Sort counts desc by count, then name, for stable output.
            sorted_counts = dict(
                sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
            )

            snap = {
                "source": "library_census",
                "ts": time.time(),
                "library_counts": sorted_counts,
                "total_subjects": total_subjects,
                "total_libraries": total_libraries,
                "rare_libraries": rare,
                "unique_library_ratio": uniq_ratio,
            }
            self._last_snapshot = snap
            self._stats["snapshots_taken"] += 1
            return snap

    # -- Policy -------------------------------------------------------------

    def policy_evaluate(self, subject_pid: int) -> Optional[dict]:
        """Return a drift event if *subject_pid* loads rare libraries.

        A library is "rare for this subject" if it appears in fewer
        than ``policy_drift_fraction`` of OTHER subjects (excluding
        this one). Returns None if no drift is detected, the PID isn't
        tracked, or the population is too small for meaningful ratios
        (<= 1 other subject).

        Event shape (published + returned):
            {"source": "library_census.policy", "ts": ...,
             "subject_pid": 1234, "rare_loaded": [...],
             "total_other_subjects": N, "drift_threshold": 0.05}
        """
        with self._lock:
            pid_maps = self._collect_pid_maps()
            if subject_pid not in pid_maps:
                return None

            subject_dlls = pid_maps[subject_pid]
            other_maps = {p: d for p, d in pid_maps.items() if p != subject_pid}
            total_others = len(other_maps)

            # Need at least 2 other subjects for a population ratio to
            # be meaningful (else every DLL is either 0% or 100%).
            if total_others < 2:
                return None

            rare_for_subject: list[str] = []
            threshold_count = max(
                1, int(self._policy_drift_fraction * total_others)
            )
            # "Rare" here: present in STRICTLY LESS than threshold_count
            # of the other subjects. When policy_drift_fraction=0.05 and
            # total_others=20, threshold_count=1, so only DLLs loaded by
            # ZERO other subjects fire -- intentional: the roadmap's
            # "<5% of other subjects" is a strict inequality.
            for name in subject_dlls:
                occurrences = sum(1 for d in other_maps.values() if name in d)
                if occurrences < threshold_count:
                    rare_for_subject.append(name)

            if not rare_for_subject:
                return None

            event = {
                "source": "library_census.policy",
                "ts": time.time(),
                "subject_pid": int(subject_pid),
                "rare_loaded": sorted(rare_for_subject),
                "total_other_subjects": total_others,
                "drift_threshold": self._policy_drift_fraction,
            }
            self._stats["policy_fires"] += 1
            self._publish(event)
            return event

    # -- Event publishing ---------------------------------------------------

    def _publish(self, event: dict) -> None:
        """Best-effort publish to the event_bus.

        Mirrors ``algedonic_reader._dispatch``: tries ``publish`` then
        ``emit``, swallows exceptions, logs at debug. The rest of the
        daemon must not suffer if the bus is misconfigured.
        """
        if self._event_bus is None:
            return
        for name in ("publish", "emit"):
            fn = getattr(self._event_bus, name, None)
            if callable(fn):
                try:
                    fn(event)
                    self._stats["snapshots_published"] += 1
                    return
                except Exception:
                    self._stats["publish_errors"] += 1
                    logger.debug("library_census: bus.%s failed",
                                 name, exc_info=True)

    # -- DLL-load hook (called by memory_observer) --------------------------

    def on_dll_load(self, pid: int, dll_name: str) -> None:
        """Invoked by memory_observer when a DLL load is detected.

        The hook is intentionally cheap: we do NOT recompute the full
        census on every DLL load (O(N_proc) under the lock, too hot for
        the mmap path). Instead we just invalidate the cached snapshot
        timestamp so the next ``snapshot()`` is forced to recompute.
        The background poll thread catches up on the next tick.

        If you want synchronous per-load policy evaluation, call
        ``policy_evaluate(pid)`` directly from your caller -- this hook
        stays non-blocking.
        """
        if not dll_name:
            return
        with self._lock:
            # Invalidate cache by zeroing ts -- cheap and lock-local.
            if self._last_snapshot is not None:
                self._last_snapshot["ts"] = 0.0

    # -- Polling lifecycle --------------------------------------------------

    def start_polling(self, interval_seconds: float = POLL_INTERVAL_DEFAULT) -> None:
        """Spawn a background thread that publishes snapshots every *interval*.

        Idempotent: a second call while already running is a no-op.
        The thread is daemon=True so it does not block interpreter exit
        if stop_polling() is skipped.

        Each call installs a fresh stop Event dedicated to the new thread,
        so a stop_polling()/start_polling() race cannot leave the previous
        thread polling against a cleared global Event. (S76 Agent B fix.)
        """
        with self._lock:
            if self._poll_thread is not None and self._poll_thread.is_alive():
                return
            self._poll_interval = max(0.5, float(interval_seconds))
            # Fresh per-thread stop Event. The OLD self._poll_stop (if any)
            # was set by stop_polling() and will remain set for the lifetime
            # of any straggler thread observing it; we never clear it.
            self._poll_stop = threading.Event()
            my_stop = self._poll_stop
            self._poll_thread = threading.Thread(
                target=self._poll_loop,
                args=(my_stop,),
                name="library_census_poller",
                daemon=True,
            )
            self._poll_thread.start()
            logger.info(
                "library_census: polling every %.1fs (rare<=%d, drift<%.2f)",
                self._poll_interval, self._rare_threshold,
                self._policy_drift_fraction,
            )

    def stop_polling(self) -> None:
        """Stop the background poll thread. Safe to call multiple times."""
        with self._lock:
            self._poll_stop.set()
            thread = self._poll_thread
            self._poll_thread = None
        if thread is not None and thread.is_alive():
            # Brief join; don't hang shutdown if the thread misbehaves.
            # Joined OUTSIDE self._lock so the poll thread can still
            # acquire it inside snapshot() while winding down.
            thread.join(timeout=2.0)

    def _poll_loop(self, stop_event: threading.Event) -> None:
        """Periodic snapshot + publish loop for the background thread.

        ``stop_event`` is the per-thread Event captured at start_polling()
        time. Even if start_polling() later installs a fresh Event for a
        new thread, this thread keeps checking its OWN event and exits
        cleanly when stop_polling() sets it.
        """
        while not stop_event.is_set():
            try:
                snap = self.snapshot()
                self._publish(snap)
            except Exception:
                logger.debug("library_census: poll tick failed", exc_info=True)
            # wait() returns True if stop was signaled -> exit promptly.
            if stop_event.wait(self._poll_interval):
                return

    # -- Introspection ------------------------------------------------------

    def stats(self) -> dict:
        """Return observer counters (for /metrics/ecosystem diagnostics)."""
        with self._lock:
            return {
                **self._stats,
                "rare_threshold": self._rare_threshold,
                "policy_drift_fraction": self._policy_drift_fraction,
                "poll_interval": self._poll_interval,
                "polling": bool(
                    self._poll_thread is not None
                    and self._poll_thread.is_alive()
                ),
                "cached_subjects": self._last_snapshot.get("total_subjects", 0),
                "cached_libraries": self._last_snapshot.get("total_libraries", 0),
            }


# -- Wire-up helper (called by api_server.py) --------------------------------


def register_with_daemon(
    app: Any,
    event_bus: Any = None,
    memory_observer: Any = None,
    poll_interval: float = POLL_INTERVAL_DEFAULT,
) -> LibraryCensus:
    """Construct a LibraryCensus, register its endpoint on *app*, return it.

    Mirrors ``algedonic_reader.register_with_daemon``. Caller owns the
    ``start_polling()`` / ``stop_polling()`` lifecycle via the daemon's
    FastAPI ``lifespan`` context.

    Also registers the module as a DLL-load callback on the supplied
    ``memory_observer`` so the census can invalidate its cache on new
    loads without waiting for the next poll tick.
    """
    census = LibraryCensus(
        memory_observer=memory_observer,
        event_bus=event_bus,
    )

    # Register DLL-load hook -- additive; memory_observer ignores it
    # if the attribute isn't present (e.g. older build).
    if memory_observer is not None:
        register_fn = getattr(
            memory_observer, "register_dll_load_callback", None,
        )
        if callable(register_fn):
            try:
                register_fn(census.on_dll_load)
                logger.info("library_census: DLL-load hook registered")
            except Exception:
                logger.debug(
                    "library_census: DLL-load hook registration failed",
                    exc_info=True,
                )
        else:
            logger.debug(
                "library_census: memory_observer has no "
                "register_dll_load_callback (pre-S75 build); "
                "relying on periodic poll only"
            )

    # Register the REST endpoint.
    if app is not None:
        try:
            @app.get("/metrics/ecosystem")  # type: ignore[misc]
            async def _ecosystem_snapshot() -> dict:
                return census.snapshot()
        except Exception:
            logger.debug(
                "library_census: FastAPI route registration skipped",
                exc_info=True,
            )

    # Poll interval is stored but the thread is NOT started here --
    # lifespan hook owns start/stop (same pattern as algedonic_reader).
    census._poll_interval = max(0.5, float(poll_interval))
    return census


__all__ = [
    "LibraryCensus",
    "register_with_daemon",
    "RARE_THRESHOLD_DEFAULT",
    "POLICY_DRIFT_FRACTION_DEFAULT",
    "POLL_INTERVAL_DEFAULT",
]
