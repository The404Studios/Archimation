# PE-Compat Windows-Style Firewall
"""
Top-level firewall package.

Exposes :func:`bootstrap_firewall` which orchestrates the three objects
that need to be wired together for per-application firewall rules to
actually enforce:

  * :class:`~firewall.backend.nft_manager.NftManager` -- compiles and
    applies ``nft`` rules including ``socket cgroupv2`` predicates for
    application-bound rules.
  * :class:`~firewall.backend.app_tracker.AppTracker` -- polls /proc
    and moves running PIDs into the correct cgroup scope so the
    predicate above actually matches.
  * :mod:`~firewall.backend.cgroup_manager` -- ensures
    ``pe-compat.slice`` exists and enables controllers.

This is the single entry point both the AI-control daemon and the
``winfw`` CLI use so the wiring stays consistent in one place.  Prior
to this module, only the GUI created an AppTracker; the daemon created
NftManager without a tracker, so ``block firefox`` rules compiled but
never matched any traffic on the running system.
"""

from __future__ import annotations

import logging
from typing import Optional, Tuple

logger = logging.getLogger("firewall.bootstrap")


def bootstrap_firewall(
    nft_manager=None,
    start_connection_monitor: bool = False,
) -> Tuple[object, Optional[object]]:
    """Wire NftManager <-> AppTracker and ensure pe-compat.slice exists.

    Args:
        nft_manager: An already-constructed ``NftManager`` (or compatible)
            instance.  If ``None``, a fresh ``NftManager()`` is created.
        start_connection_monitor: If True, also starts a
            :class:`ConnectionMonitor`.  Left False by default because most
            callers (GUI, daemon) create their own monitor.

    Returns:
        ``(nft_manager, app_tracker)`` tuple.  The tracker is ``None`` on
        systems where cgroup v2 isn't available or we don't have write
        permission on ``/sys/fs/cgroup`` (typically: non-root, container
        without cgroup delegation, or kernel built without cgroup v2).

    Never raises on ordinary failures -- logs and returns a partial tuple
    so callers don't need a try/except around firewall initialisation.
    """
    # Import lazily so packaging / test environments without the backend
    # modules present can still import the top-level firewall package.
    try:
        from .backend.nft_manager import NftManager
        from .backend import app_tracker as _app_tracker_mod
        from .backend import cgroup_manager as _cgm
    except ImportError as exc:
        logger.warning("bootstrap_firewall: backend import failed: %s", exc)
        return nft_manager, None

    if nft_manager is None:
        nft_manager = NftManager()

    # Check cgroup v2 availability.  detect_cgroupv2() returns False on
    # cgroup v1 systems, non-Linux build hosts, and in test environments
    # that mock /sys/fs/cgroup -- any of which should make us skip
    # attachment without failing.
    try:
        v2 = bool(_cgm.detect_cgroupv2())
    except Exception:
        v2 = False

    if not v2:
        logger.warning(
            "cgroup v2 unavailable -- application-scoped firewall rules "
            "will compile but not enforce.  Kernel-level cgroup v2 with "
            "write access to /sys/fs/cgroup is required."
        )
        return nft_manager, None

    # Pre-create the slice.  ensure_slice() is idempotent and logs its own
    # failures; we catch here only to isolate bootstrap from a buggy
    # cgroup_manager release.
    try:
        _cgm.ensure_slice()
    except Exception:
        logger.exception("ensure_slice() failed during bootstrap")

    # Build and attach the tracker.
    try:
        tracker = _app_tracker_mod.AppTracker()
        tracker.attach_to_nft_manager(nft_manager)
    except Exception:
        logger.exception(
            "AppTracker.attach_to_nft_manager() failed -- "
            "application rules will not enforce"
        )
        return nft_manager, None

    logger.info(
        "Firewall bootstrap complete: NftManager + AppTracker + cgroup v2 active"
    )
    return nft_manager, tracker


def prune_exited_pids(tracker) -> int:
    """Garbage-collect the tracker's ``_cgrouped_pids`` memoisation set.

    The tracker memoises ``(pid, app_name)`` tuples so it doesn't re-move
    the same PID on every poll.  But the set is never pruned -- if an app
    cycles through many short-lived PIDs (Firefox content processes,
    Electron workers) the set grows unbounded.  Worse, because Linux
    recycles PID numbers, a stale ``(1234, "firefox")`` entry can cause a
    new Chrome process with PID 1234 to skip scoping.

    This helper removes entries whose PID no longer has a
    ``/proc/<pid>`` directory.  Call periodically (e.g. once per minute
    from the daemon's housekeeping loop).

    Returns the number of entries pruned.  Safe to call on ``None``
    (returns 0) so callers with optional tracker handles don't need to
    guard.
    """
    import os
    if tracker is None:
        return 0

    cgrouped = getattr(tracker, "_cgrouped_pids", None)
    if not cgrouped:
        return 0

    # Snapshot and rebuild to avoid mutate-during-iteration on the live
    # set (the tracker's poll loop may concurrently add entries).
    stale = []
    for pid, app in list(cgrouped):
        try:
            if not os.path.isdir(f"/proc/{pid}"):
                stale.append((pid, app))
        except OSError:
            stale.append((pid, app))

    if stale:
        for entry in stale:
            cgrouped.discard(entry)
        logger.debug("Pruned %d exited PIDs from tracker memoisation", len(stale))
    return len(stale)
