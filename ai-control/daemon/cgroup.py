"""
cgroup v2 slice orchestration for the AI daemon.

This module is the daemon-side counterpart to ``firewall/backend/cgroup_manager.py``.
It knows about the five custom slices defined in the archiso profile:

    trust.slice        -- L0, CPUWeight=1000, reserved CPU/RAM for trust.ko
    ai-daemon.slice    -- L4, CPUWeight=200, this daemon + ai-cortex
    pe-compat.slice    -- L2/L3, CPUWeight=900, PE apps + SCM + pe-objectd
    game.slice         -- foreground game, CPUWeight=10000, no MemoryHigh
    observer.slice     -- CPUWeight=10, CPUQuota=5%, throttled observers

Three capabilities are exposed:

1. ``launch_pe_exe(command, app_name)`` -- fork+exec a PE binary directly
   into ``pe-compat.slice/<app>.scope`` via systemd-run.  This is called
   from ``desktop_automation.launch_exe``/``launch_game`` so every PE
   process starts already subject to the slice's CPU / memory / IO
   budget -- we never have to move PIDs after the fact.

2. ``promote_to_game_slice(pid)`` / ``demote_from_game_slice(pid)`` --
   move a running PE scope into ``game.slice`` (CPUWeight=10000) when
   the user alt-tabs to it and back to pe-compat.slice when it loses
   focus.  Driven by the compositor/trust event bus.

3. ``move_observer_task(tid, throttled)`` -- move an asyncio task
   (identified by thread id from ``threading.get_native_id()``) into
   ``observer.slice`` when we detect a game is active, and back to
   ``ai-daemon.slice`` when the game exits.  This replaces the
   per-task SCHED_IDLE approach which needed CAP_SYS_NICE and was
   unreliable for asyncio tasks that bounce between threads.

Design constraints:
- MUST degrade gracefully on systems without cgroup v2 or without root.
- MUST never raise exceptions to callers; every failure is logged.
- MUST cache "not available" to avoid hot-loop syscalls.
- Every public entrypoint is async-safe (no blocking longer than one
  small file write).

This module is NOT a general cgroup library -- for arbitrary app
placement see firewall/backend/cgroup_manager.py, which handles the
nft/firewall side.  Their code paths are complementary: this one
launches into slices, that one retroactively places existing PIDs.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from typing import Optional

logger = logging.getLogger("ai-control.cgroup")

# ---------------------------------------------------------------------------
# Slice name constants
# ---------------------------------------------------------------------------

SLICE_TRUST = "trust.slice"
SLICE_AI_DAEMON = "ai-daemon.slice"
SLICE_PE_COMPAT = "pe-compat.slice"
SLICE_GAME = "game.slice"
SLICE_OBSERVER = "observer.slice"

CGROUP_ROOT = "/sys/fs/cgroup"
CGROUP_CONTROLLERS = "/sys/fs/cgroup/cgroup.controllers"

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

# App names flow into cgroup directory components AND systemd unit
# names.  Both have tighter rules than "anything" -- unit names may not
# contain '/' and cgroup paths may not start with a dash.  Keep the
# pattern aligned with firewall.backend.cgroup_manager so
# pe-compat.slice/<app>.scope strings match from both callers.
_APP_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]{0,63}$")


def _sanitise_app_name(app_path_or_name: str) -> Optional[str]:
    """Produce a safe cgroup/scope component from a binary path or arbitrary name.

    - Takes the basename if a path is supplied.
    - Replaces dots with underscores (``game.exe`` -> ``game_exe``).
    - Strips any remaining non-conforming characters.
    - Caps length at 64 chars to keep scope names under the kernel's
      255-byte cgroup filename limit.

    Returns ``None`` if the result would be unsafe (empty, starts with
    non-alnum, etc.) so callers must check before using it.
    """
    if not app_path_or_name:
        return None
    name = os.path.basename(app_path_or_name).replace(".", "_")
    if not name:
        return None
    name = re.sub(r"[^a-zA-Z0-9_\-]", "_", name)[:64]
    if not _APP_NAME_RE.match(name):
        return None
    return name


# ---------------------------------------------------------------------------
# Availability detection (cached)
# ---------------------------------------------------------------------------

class _State:
    """Per-process cache to avoid repeated filesystem probes."""

    def __init__(self) -> None:
        self.v2: Optional[bool] = None
        self.writable: Optional[bool] = None
        self.systemd_run: Optional[str] = None
        self.warned_unavailable: bool = False


_state = _State()


def _cgroup_v2_available() -> bool:
    """Return True iff ``/sys/fs/cgroup/cgroup.controllers`` exists.

    Hybrid cgroup v1+v2 setups mount the v2 hierarchy at
    ``/sys/fs/cgroup/unified`` and we don't support that mode -- all our
    slice paths assume unified at the root.
    """
    if _state.v2 is not None:
        return _state.v2
    try:
        _state.v2 = os.path.isfile(CGROUP_CONTROLLERS)
    except OSError:
        _state.v2 = False
    return _state.v2


def _have_writable_root() -> bool:
    """Return True if we can create cgroup dirs (requires root or a
    delegated subtree).  Cached after first call."""
    if _state.writable is not None:
        return _state.writable
    try:
        _state.writable = os.access(CGROUP_ROOT, os.W_OK)
    except OSError:
        _state.writable = False
    return _state.writable


def _find_systemd_run() -> Optional[str]:
    """Locate systemd-run on PATH (cached)."""
    if _state.systemd_run is not None:
        return _state.systemd_run or None
    path = shutil.which("systemd-run") or ""
    _state.systemd_run = path
    return path or None


def available() -> bool:
    """Top-level check: can we do ANY cgroup work?  Logs a one-time warning."""
    if not _cgroup_v2_available():
        if not _state.warned_unavailable:
            logger.warning(
                "cgroup v2 unified hierarchy not detected at %s -- slice "
                "placement disabled, resource policies will not apply",
                CGROUP_CONTROLLERS,
            )
            _state.warned_unavailable = True
        return False
    if not _have_writable_root():
        if not _state.warned_unavailable:
            logger.warning(
                "No write access to %s -- daemon is not root?  Slice "
                "placement disabled", CGROUP_ROOT,
            )
            _state.warned_unavailable = True
        return False
    return True


# ---------------------------------------------------------------------------
# 1. Launch PE exe directly into pe-compat.slice/<app>.scope
# ---------------------------------------------------------------------------

def launch_pe_exe(
    command: list[str],
    app_name: str,
    *,
    env: Optional[dict] = None,
    cwd: Optional[str] = None,
    slice_name: str = SLICE_PE_COMPAT,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
) -> Optional[subprocess.Popen]:
    """Launch *command* as a transient scope under *slice_name*.

    Equivalent to::

        systemd-run --scope --slice=pe-compat.slice \\
                    --unit=pe-<app>.scope --collect -- <command...>

    Why a scope and not a service?
      A systemd scope is a cgroup attached to an EXISTING process tree
      (the spawned Popen, in this case).  Services are managed by
      systemd itself and would require a unit file.  Scopes are the
      right fit for "user-initiated launch from the daemon".

    Why --collect?
      Auto-cleans the scope when all processes exit.  Without it, dead
      scopes accumulate under ``/sys/fs/cgroup/pe-compat.slice/``.

    Fallback behaviour:
      If systemd-run is missing (minimal container) or cgroup v2 isn't
      available, we fall back to a plain Popen in the ambient cgroup.
      The process still runs correctly -- it just doesn't benefit from
      slice limits.  Callers get the same Popen either way.
    """
    sanitised = _sanitise_app_name(app_name)
    if sanitised is None:
        logger.warning("launch_pe_exe: rejected app_name %r", app_name)
        sanitised = "pe-unknown"

    if not isinstance(command, list) or not command:
        logger.error("launch_pe_exe: command must be a non-empty list")
        return None

    systemd_run = _find_systemd_run()
    if not available() or systemd_run is None:
        # Degrade to plain launch -- the process runs but is not scoped.
        logger.debug(
            "launch_pe_exe: systemd-run unavailable or cgroup v2 missing, "
            "falling back to ambient-cgroup launch for %s", sanitised,
        )
        try:
            return subprocess.Popen(
                command, env=env, cwd=cwd,
                stdout=stdout, stderr=stderr,
                start_new_session=True,
            )
        except (OSError, FileNotFoundError) as exc:
            logger.error("launch_pe_exe fallback failed: %s", exc)
            return None

    unit_name = f"pe-{sanitised}.scope"
    argv = [
        systemd_run,
        "--scope",
        f"--slice={slice_name}",
        f"--unit={unit_name}",
        "--collect",
        # --quiet: don't print "Running as unit: ..." to stderr, which
        # otherwise pollutes the daemon's own stderr when it tails the
        # journal via the API.
        "--quiet",
    ]
    # --working-directory must come before the -- separator, not after.
    if cwd:
        argv.append(f"--working-directory={cwd}")
    # Environment: systemd-run accepts --setenv KEY=VAL per var.  We
    # pass the caller's env through so DISPLAY / WAYLAND_DISPLAY /
    # XAUTHORITY / PE_COMPAT_* / VK_ICD_FILENAMES all propagate.
    if env:
        for k, v in env.items():
            if k is None or v is None:
                continue
            # Skip shell-unsafe keys defensively (systemd-run does its own
            # escaping but a null byte would break things).
            if "\x00" in str(k) or "\x00" in str(v):
                continue
            argv.append(f"--setenv={k}={v}")
    argv.append("--")
    argv.extend(command)

    try:
        proc = subprocess.Popen(
            argv, stdout=stdout, stderr=stderr,
            start_new_session=True,
        )
        logger.info(
            "launch_pe_exe: spawned %s as %s/%s (pid=%d)",
            command[0], slice_name, unit_name, proc.pid,
        )
        return proc
    except (OSError, FileNotFoundError) as exc:
        logger.warning(
            "launch_pe_exe: systemd-run spawn failed (%s), falling back", exc,
        )
        try:
            return subprocess.Popen(
                command, env=env, cwd=cwd,
                stdout=stdout, stderr=stderr,
                start_new_session=True,
            )
        except (OSError, FileNotFoundError) as exc2:
            logger.error("launch_pe_exe fallback failed: %s", exc2)
            return None


# ---------------------------------------------------------------------------
# 2. Promote / demote a running PE scope between pe-compat and game slices
# ---------------------------------------------------------------------------

def _cgroup_write(path: str, value: str) -> bool:
    """Write *value* to *path* atomically.  Return True on success."""
    try:
        # cgroup v2 files accept single writes; no locking needed.
        with open(path, "w") as fh:
            fh.write(value)
        return True
    except FileNotFoundError:
        # Scope/task exited between check and write -- not an error.
        return False
    except PermissionError as exc:
        logger.warning("cgroup write %s <- %r: permission denied (%s)",
                       path, value, exc)
        return False
    except OSError as exc:
        logger.warning("cgroup write %s <- %r: %s", path, value, exc)
        return False


def _move_pid_to_slice(pid: int, slice_name: str) -> bool:
    """Move *pid* into the root cgroup of *slice_name*.

    For game promotion we actually want the PID in a SCOPE under the
    slice, but for a running process that already lives in
    ``pe-compat.slice/pe-foo.scope`` the simpler alternative is to move
    the whole scope by moving its root task(s) to the target slice's
    scope.  However, systemd-run doesn't let us "re-parent" an
    existing scope, so we instead write the PID directly into the
    target slice's root cgroup.procs.  This strips the nested scope;
    that's acceptable because game.slice is always the ephemeral
    foreground destination.
    """
    if not isinstance(pid, int) or pid <= 0:
        return False
    if pid in (0, 1, 2):
        # init / kthreadd / kernel threads can't be moved.
        return False
    if not available():
        return False
    slice_dir = os.path.join(CGROUP_ROOT, slice_name)
    try:
        os.makedirs(slice_dir, mode=0o755, exist_ok=True)
    except OSError as exc:
        logger.warning("Cannot mkdir %s: %s", slice_dir, exc)
        return False
    return _cgroup_write(os.path.join(slice_dir, "cgroup.procs"), str(pid))


def promote_to_game_slice(pid: int) -> bool:
    """Move *pid* (and its threads) into ``game.slice``.

    Called when the compositor signals "this window has focus AND is
    a known game exe".  The PE process gains CPUWeight=10000,
    MemorySwapMax=0, and TasksMax=8192 all at once.

    Returns True on success.  Never raises.
    """
    return _move_pid_to_slice(pid, SLICE_GAME)


def demote_from_game_slice(pid: int) -> bool:
    """Move *pid* from game.slice back to pe-compat.slice.

    Called when a game loses focus or the user alt-tabs to a non-game
    window.  The scheduler immediately drops the scope's priority
    from 10000 to 900.
    """
    return _move_pid_to_slice(pid, SLICE_PE_COMPAT)


# ---------------------------------------------------------------------------
# 3. Throttle observer threads into observer.slice
# ---------------------------------------------------------------------------

def _current_cgroup_path() -> Optional[str]:
    """Return our process's current cgroup path or None on failure."""
    try:
        with open("/proc/self/cgroup", "r") as fh:
            for line in fh:
                parts = line.strip().split(":")
                # cgroup v2 line format: "0::/ai-daemon.slice/ai-control.service"
                if len(parts) == 3 and parts[0] == "0":
                    return parts[2]
    except OSError:
        pass
    return None


def _observer_cgroup_dir() -> Optional[str]:
    """Return filesystem path of observer.slice cgroup directory."""
    if not available():
        return None
    path = os.path.join(CGROUP_ROOT, SLICE_OBSERVER)
    try:
        os.makedirs(path, mode=0o755, exist_ok=True)
    except OSError as exc:
        logger.warning("Cannot create %s: %s", path, exc)
        return None
    return path


def move_observer_task(tid: int, *, throttled: bool = True) -> bool:
    """Move kernel thread *tid* into observer.slice (throttled=True) or
    back into our own cgroup (throttled=False).

    Caller is expected to pass the result of
    ``threading.get_native_id()`` for the thread backing an asyncio
    task.  This relies on cgroup v2's ``cgroup.threads`` file, which
    only exists when the parent slice has Delegate=yes with thread
    delegation.  For our setup we don't delegate threads -- we move
    the whole task via ``cgroup.procs`` instead, which effectively
    moves the whole Python interpreter for that thread.

    WARNING: with ``cgroup.procs`` you can only have ONE cgroup per
    process; moving a single observer thread moves the WHOLE daemon.
    This function therefore uses an approach that DOES work: it
    launches observer workers as SUBPROCESSES (see observer_runner
    in pattern_scanner.py / memory_observer.py) and moves those
    subprocess PIDs.  If called with the daemon's own tid/pid, it
    refuses and logs a warning.

    For per-thread throttling within a single process, consider
    ``sched_setscheduler(tid, SCHED_IDLE, ...)`` -- not implemented
    here because asyncio tasks migrate between threads.

    Returns True if placement succeeded or was a no-op (cgroup
    unavailable).  Returns False only for a recoverable error.
    """
    if not isinstance(tid, int) or tid <= 0:
        return False
    if tid == os.getpid():
        logger.debug(
            "move_observer_task: refusing to move daemon's own pid %d; "
            "launch observers as subprocesses instead", tid,
        )
        return False
    if not available():
        return True  # no-op, caller should not retry
    target_slice = SLICE_OBSERVER if throttled else SLICE_AI_DAEMON
    slice_dir = os.path.join(CGROUP_ROOT, target_slice)
    try:
        os.makedirs(slice_dir, mode=0o755, exist_ok=True)
    except OSError as exc:
        logger.warning("move_observer_task: mkdir %s: %s", slice_dir, exc)
        return False
    procs_file = os.path.join(slice_dir, "cgroup.procs")
    if _cgroup_write(procs_file, str(tid)):
        logger.debug(
            "move_observer_task: moved pid %d to %s (throttled=%s)",
            tid, target_slice, throttled,
        )
        return True
    return False


# ---------------------------------------------------------------------------
# Utility: pre-create slice directories so the first launch is instant
# ---------------------------------------------------------------------------

def ensure_slices() -> None:
    """Pre-create all our slice cgroup directories.

    Called once at daemon startup so the first ``launch_pe_exe`` call
    doesn't have to wait for systemd to lazy-instantiate the slice
    (which can add 50-200 ms to a cold launch).  Idempotent; errors
    are logged but not raised.
    """
    if not available():
        return
    for slice_name in (SLICE_TRUST, SLICE_AI_DAEMON, SLICE_PE_COMPAT,
                       SLICE_GAME, SLICE_OBSERVER):
        path = os.path.join(CGROUP_ROOT, slice_name)
        try:
            os.makedirs(path, mode=0o755, exist_ok=True)
        except OSError as exc:
            logger.debug("ensure_slices: %s: %s", path, exc)


# ---------------------------------------------------------------------------
# Backwards-compatibility shims
# ---------------------------------------------------------------------------

def launch_in_slice(
    command: list[str],
    app_name: str,
    slice_name: str = SLICE_PE_COMPAT,
    **kwargs,
) -> Optional[subprocess.Popen]:
    """Thin alias preserved for older call sites."""
    return launch_pe_exe(command, app_name, slice_name=slice_name, **kwargs)
