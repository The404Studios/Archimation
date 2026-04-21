"""
coherence_bridge.py -- workload-aware setpoint bridge from cortex to coherenced.

Session 41 audit finding: coherenced is workload-blind.  Its 4-state arbiter
uses a single set of thresholds (theta_latency_enter / theta_thermal_enter
etc.) regardless of whether the foreground workload is an idle desktop, a
latency-sensitive game, or a throughput-dominated compile job.  The cortex
already knows what PE binaries are live and what anti-cheat environment was
detected, so it is the only component with enough context to pick a setpoint.

Wire:
    PE_LOAD  -> classify binary -> write /etc/coherence/overrides/app-active.conf
                                   -> SIGHUP coherenced (pidfile /var/run/coherenced.pid
                                      or fallback systemctl MAINPID lookup)
    PE_EXIT  -> ref-count decrement; remove override file + SIGHUP when last game exits

Override grammar (one key=value per line, identical to primary coherence.conf):

    # /etc/coherence/overrides/app-active.conf
    # Written by cortex CoherenceBridge.  DO NOT EDIT BY HAND.
    # active=DungeonCrawler-Win64-Shipping.exe pid=4711 classification=game
    theta_latency_enter = 0.75
    theta_latency_exit  = 0.55
    theta_thermal_enter = 0.75
    theta_thermal_exit  = 0.60

The primary coherence.conf already loads first at startup and on SIGHUP;
coherenced's config.c was extended in the same session to glob
/etc/coherence/overrides/*.conf after the primary and apply keys on top
(last-write-wins).  game_cpuset / system_cpuset are not coh_config_t
fields (they live in the actuation vector which the arbiter plans from
derived signals), so we intentionally restrict the override surface to
the threshold + weight knobs that coh_config_load() accepts — unknown
keys trigger config_unknown_key warnings on coherenced's side.

Why thresholds work as a game-knob: shifting theta_latency_enter DOWN
from 1.00 to 0.75 makes the arbiter trip into LATENCY_CRITICAL at a
lower pressure value, which in turn asks cpufreq to bump min_perf_pct
and the actuator plans tighter cpuset masks -- all of this is already
wired, we just flip the setpoint.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional, Dict, Set, Tuple

from .event_bus import (
    EventBus,
    Event,
    SourceLayer,
    PeEventType,
)

# Session 50 / Agent I: outbound I/O to coherenced (override file write,
# override unlink, SIGHUP, pidfile / systemctl probes) is now gated
# through the daemon's shared CircuitBreaker.  When coherenced is
# misbehaving (slow, dead, signalling EPERM in a tight loop) the breaker
# trips OPEN after CB_COHERENCE.failure_threshold consecutive failures
# and we degrade to log-warning-and-skip until the recovery window
# elapses.  Import is best-effort because the daemon package may not be
# importable in all cortex test rigs (e.g. when the cortex is built
# standalone for unit tests); a None CB falls back to direct calls so
# the bridge still functions, just without breaker semantics.
try:
    # The daemon package ships under hyphenated path "ai-control/daemon"
    # which is not importable as ``ai-control.daemon`` (Python disallows
    # the hyphen).  Operators install it onto sys.path under the
    # underscore alias ``ai_control.daemon`` via a console script in
    # packages/ai-control-daemon/PKGBUILD; cortex shares the same venv.
    from ai_control.daemon.safety import (  # type: ignore
        CB_COHERENCE,
        CircuitOpenError,
    )
except Exception:  # pragma: no cover - defensive import
    CB_COHERENCE = None  # type: ignore[assignment]

    class CircuitOpenError(Exception):  # type: ignore[no-redef]
        """Stand-in when safety.py isn't importable; nothing ever raises it."""


logger = logging.getLogger("cortex.coherence_bridge")

# Canonical locations; coherence.service owns coherenced and only pins MAINPID
# into $NOTIFY_SOCKET — it does NOT write a pidfile.  We try the conventional
# /var/run path first (operators may create one via a tmpfiles rule), then
# fall back to the systemd-reported MAINPID lookup.
_COHERENCE_PIDFILE_PRIMARY = "/var/run/coherenced.pid"
_COHERENCE_PIDFILE_FALLBACK = "/run/coherenced.pid"
_COHERENCE_SYSTEMD_UNIT = "coherence.service"

_OVERRIDE_DIR = Path("/etc/coherence/overrides")
_OVERRIDE_FILE = _OVERRIDE_DIR / "app-active.conf"

# Bumped whenever the on-disk override grammar/semantics change; written as
# a `# version=N` comment so a future bridge can refuse to SIGHUP on top of
# a file it doesn't understand.
_OVERRIDE_VERSION = 1

# Runaway-spawn guard: if more than this many games are simultaneously
# "active" according to our ref-count, something is pathological (test
# harness, fork bomb, anti-cheat relauncher loop) and we stop emitting
# setpoint churn.
_MAX_ACTIVE_GAMES = 8

# Upper bound for every asyncio.to_thread() call that touches /etc or
# /var filesystem state or issues kill(2).  A stuck NFS/FUSE mount or a
# kernel D-state coherenced cannot otherwise be distinguished from a
# slow-but-live call, and the handler task would hang indefinitely,
# leaking through _pending_tasks into the shutdown drain.
_TO_THREAD_TIMEOUT_S: float = 5.0

# Setpoints for "game" classification.  Values chosen so the validator in
# coh_config_validate (enter > exit + 0.10 hysteresis gap) still passes.
_GAME_SETPOINTS: Dict[str, float] = {
    "theta_latency_enter": 0.75,
    "theta_latency_exit":  0.55,
    "theta_thermal_enter": 0.75,
    "theta_thermal_exit":  0.60,
}

# Known game-binary basenames harvested from services/anticheat/ac_compat.c
# detect_* functions.  Lower-cased; match against os.path.basename(exe_path).
# Kept small on purpose — the PE loader also ships richer detection and may
# flag via event payload fields (checked first, see _classify()).
_KNOWN_GAME_BINARIES: Set[str] = {
    # IRONMACE / Blackshield
    "dungeoncrawler.exe",
    "dungeoncrawler-win64-shipping.exe",
    "tavern.exe",
    "taverncomn.exe",
    "tavernworker.exe",
    # Riot / Vanguard
    "vgc.exe",
    "riotclientservices.exe",
    # BattlEye hosts (service binary, not a game but always co-resident)
    "beservice.exe",
    "beservice_x64.exe",
    # Generic signal: EAC self-launcher ships next to the game .exe
    "easyanticheat.exe",
    "easyanticheat_setup.exe",
    # PunkBuster
    "pnkbstra.exe",
    "pnkbstrb.exe",
}


class CoherenceBridge:
    """Translate PE_LOAD / PE_EXIT into coherenced override-config edits.

    Single instance per cortex process.  All filesystem + signal operations
    run under asyncio.to_thread() so a stuck coherenced cannot block the
    event-bus dispatcher.
    """

    def __init__(self, bus: EventBus) -> None:
        self._bus = bus
        # pid -> basename(lower); needed because PE_EXIT payload doesn't
        # always carry exe_path, so we remember what we classified on LOAD.
        self._active_games: Dict[int, str] = {}
        self._lock = asyncio.Lock()
        # Latched on __init__: if coherenced wasn't running at startup we
        # log one warning and degrade silently for the lifetime of cortex.
        self._disabled: bool = False
        self._disabled_reason: str = ""
        self._pidfile_path_at_boot: Optional[str] = None
        # Strong refs for every async task we spawn from sync bus-handler
        # entrypoints — otherwise CPython's GC can collect a still-pending
        # task mid-flight (Session 37/39 lesson).  Tasks auto-discard
        # themselves from this set via add_done_callback.
        self._pending_tasks: Set[asyncio.Task] = set()
        # Throttle: last body we wrote to the override file.  If the next
        # _write_override_atomic would produce the same text, we skip the
        # write+SIGHUP to prevent coherenced reload-storms when a game
        # launcher rapid-fires child PE_LOADs.
        # Throttle key is the rendered setpoint section only — header
        # carries a timestamp that would defeat byte-equal comparison.
        self._last_override_key: Optional[str] = None
        # Latched once _active_games exceeds _MAX_ACTIVE_GAMES — beyond that
        # point we stop ACTING on new LOADs, but still track the memo so
        # EXITs can clean up correctly.
        self._classification_suspended: bool = False

        bus.on(SourceLayer.RUNTIME, PeEventType.LOAD, self._on_pe_load)
        bus.on(SourceLayer.RUNTIME, PeEventType.EXIT, self._on_pe_exit)

    # ------------------------------------------------------------------
    # Startup probe -- called from main.py right after construction so the
    # cortex startup log captures whether the bridge is live or degraded.
    # ------------------------------------------------------------------

    def probe_pidfile(self) -> Optional[int]:
        """Look for coherenced's pid; log-and-latch on failure.  Returns the
        resolved pid or None if coherenced isn't running.  Safe to call
        before the event loop is started.

        Resolution order: primary pidfile -> fallback pidfile ->
        `systemctl show -p MainPID --value coherence.service`.

        Also runs a one-shot stale-override reconciliation (see Session 45
        deliverable A): if cortex crashed with a game active, the override
        file persists with the game's tighter thresholds even after the
        game exits.  We inspect it here — before the event bus starts
        dispatching PE_LOAD/PE_EXIT — and tear it down if the owner pid
        no longer exists (or points at a different binary).
        """
        pid = self._read_pidfile_sync()
        if pid is None:
            # Sync systemctl call is acceptable here — probe_pidfile runs
            # once at startup before the event loop spins.
            pid = self._systemctl_mainpid_sync()
            if pid is not None:
                self._pidfile_path_at_boot = f"systemctl:{_COHERENCE_SYSTEMD_UNIT}"
        if pid is None:
            self._disabled = True
            self._disabled_reason = (
                f"no pidfile at {_COHERENCE_PIDFILE_PRIMARY} or "
                f"{_COHERENCE_PIDFILE_FALLBACK} and systemctl MainPID "
                f"unavailable for {_COHERENCE_SYSTEMD_UNIT}"
            )
            logger.warning(
                "CoherenceBridge disabled: %s. Override writes will no-op "
                "until coherenced starts and a pidfile appears.",
                self._disabled_reason,
            )
            # Still reconcile — we may have permission to unlink even if
            # SIGHUP has no recipient.  The stale file is what's harmful;
            # the SIGHUP is merely a nicety.
            self._reconcile_stale_override_sync(coherenced_pid=None)
            return None
        logger.info(
            "CoherenceBridge: coherenced pid=%d found at %s",
            pid, self._pidfile_path_at_boot,
        )
        self._reconcile_stale_override_sync(coherenced_pid=pid)
        return pid

    # ------------------------------------------------------------------
    # Stale-override reconciliation (Session 45, deliverable A)
    #
    # If cortex crashes while a game is running, the override file
    # persists with the game's tighter thresholds after the game exits.
    # Next startup: parse the `# active=... pid=N` header, kill(pid, 0)
    # to check liveness, verify /proc/<pid>/comm against the recorded
    # basename, and remove+SIGHUP if the owner is gone or has changed.
    #
    # Runs ONCE per cortex startup, synchronously, before the event loop
    # spins.  Mirrors the same rationale as probe_pidfile's sync systemctl
    # call — one-shot boot work, not an async hot path.
    # ------------------------------------------------------------------

    def _reconcile_stale_override_sync(
        self, coherenced_pid: Optional[int],
    ) -> None:
        """One-shot cleanup of a left-behind override file.

        Decision flow:
          1. Override file absent     -> no-op (structured log: clean_boot).
          2. File present, header unparseable -> remove + SIGHUP
             (structured log: header_unparseable).
          3. Owner pid no longer exists (ESRCH on kill(pid, 0))
             -> remove + SIGHUP (structured log: owner_gone).
          4. Owner pid exists but /proc/<pid>/comm differs from recorded
             basename -> remove + SIGHUP (structured log: exe_changed).
          5. Owner pid alive and name matches -> KEEP the override
             (structured log: owner_alive).  The PE_LOAD that will arrive
             shortly will rewrite the file idempotently; we do not want
             to drop the game's setpoint during the small window between
             cortex restart and the first bus dispatch.
        """
        try:
            exists = _OVERRIDE_FILE.exists()
        except OSError as exc:
            logger.debug(
                "CoherenceBridge: reconcile stat %s failed: %s",
                _OVERRIDE_FILE, exc,
            )
            return

        if not exists:
            logger.debug(
                "CoherenceBridge: reconcile decision=clean_boot "
                "file=%s action=none",
                _OVERRIDE_FILE,
            )
            return

        parsed = self._parse_override_header_sync()
        if parsed is None:
            logger.warning(
                "CoherenceBridge: reconcile decision=header_unparseable "
                "file=%s action=remove+sighup",
                _OVERRIDE_FILE,
            )
            self._reconcile_remove_and_sighup(coherenced_pid)
            return

        owner_base, owner_pid = parsed
        if owner_pid is None or owner_pid <= 1:
            logger.warning(
                "CoherenceBridge: reconcile decision=header_unparseable "
                "file=%s exe=%s pid=%s action=remove+sighup",
                _OVERRIDE_FILE, owner_base, owner_pid,
            )
            self._reconcile_remove_and_sighup(coherenced_pid)
            return

        if not self._pid_alive(owner_pid):
            logger.info(
                "CoherenceBridge: reconcile decision=owner_gone "
                "file=%s exe=%s pid=%d action=remove+sighup",
                _OVERRIDE_FILE, owner_base, owner_pid,
            )
            self._reconcile_remove_and_sighup(coherenced_pid)
            return

        current_comm = self._read_proc_comm_sync(owner_pid)
        if current_comm is not None and owner_base:
            # /proc/<pid>/comm is truncated to TASK_COMM_LEN-1 = 15 chars
            # and carries no .exe suffix; compare the prefix of the
            # stripped basename so "DungeonCrawler.exe" (18 chars) matches
            # comm="DungeonCrawler" without a false positive.
            expected_prefix = owner_base
            for suffix in (".exe",):
                if expected_prefix.endswith(suffix):
                    expected_prefix = expected_prefix[: -len(suffix)]
                    break
            expected_prefix = expected_prefix[:15].lower()
            if current_comm.lower() != expected_prefix:
                logger.info(
                    "CoherenceBridge: reconcile decision=exe_changed "
                    "file=%s recorded=%s pid=%d current_comm=%s "
                    "action=remove+sighup",
                    _OVERRIDE_FILE, owner_base, owner_pid, current_comm,
                )
                self._reconcile_remove_and_sighup(coherenced_pid)
                return

        logger.info(
            "CoherenceBridge: reconcile decision=owner_alive "
            "file=%s exe=%s pid=%d action=keep",
            _OVERRIDE_FILE, owner_base, owner_pid,
        )

    def _reconcile_remove_and_sighup(
        self, coherenced_pid: Optional[int],
    ) -> None:
        if self._remove_override():
            self._last_override_key = None
        if coherenced_pid is not None:
            self._sighup(coherenced_pid)

    def _parse_override_header_sync(
        self,
    ) -> Optional[Tuple[str, Optional[int]]]:
        """Parse the `# active=<exe> pid=<N>` header.  Returns
        (basename_lower, pid_or_None) or None if the file cannot be read
        or contains no header at all."""
        try:
            with open(_OVERRIDE_FILE, "r", encoding="utf-8") as fh:
                # Header lines appear in the first few lines; don't read
                # the whole file just to parse a comment.
                header_region = fh.read(4096)
        except FileNotFoundError:
            return None
        except OSError as exc:
            logger.debug(
                "CoherenceBridge: reconcile read %s failed: %s",
                _OVERRIDE_FILE, exc,
            )
            return None

        active: Optional[str] = None
        pid: Optional[int] = None
        for line in header_region.splitlines():
            if not line.startswith("#"):
                # Once we hit the first non-comment line we're past the
                # header; stop scanning regardless.
                break
            stripped = line.lstrip("#").strip()
            if not stripped.startswith("active="):
                continue
            # Grammar: "active=<basename> pid=<N> classification=<C> t_ns=<T>"
            # We consume tokens defensively; a future header extension
            # that inserts extra keys shouldn't break this parse.
            for tok in stripped.split():
                if tok.startswith("active="):
                    active = tok[len("active="):].strip().lower()
                elif tok.startswith("pid="):
                    try:
                        pid = int(tok[len("pid="):])
                    except ValueError:
                        pid = None
            break

        if active is None and pid is None:
            return None
        return (active or "", pid)

    @staticmethod
    def _read_proc_comm_sync(pid: int) -> Optional[str]:
        """Return /proc/<pid>/comm stripped of the trailing newline, or
        None on read error (process gone, permission denied, or non-Linux
        build host under test)."""
        try:
            with open(f"/proc/{int(pid)}/comm", "r", encoding="ascii",
                      errors="replace") as fh:
                return fh.read().strip()
        except (FileNotFoundError, ProcessLookupError):
            return None
        except OSError:
            return None

    # ------------------------------------------------------------------
    # CircuitBreaker plumbing (Session 50 / Agent I)
    #
    # Every outbound I/O to coherenced -- override file write/remove,
    # SIGHUP, pidfile / systemctl probes -- runs through CB_COHERENCE.
    # When the breaker is OPEN the call is skipped and we log at WARNING
    # so the operator sees the degradation but the cortex event loop
    # never blocks.  Returns a sentinel _CB_SKIPPED on degradation;
    # callers must check before treating the result as a real value.
    # ------------------------------------------------------------------

    async def _cb_call(
        self,
        site: str,
        coro_factory,
        *,
        skipped_value=None,
    ):
        """Run *coro_factory()* under CB_COHERENCE.call_callable.

        - On normal success: returns the awaitable's result.
        - On asyncio.TimeoutError / OSError raised by the inner I/O:
          re-raises (caller's existing try/except handles + counts).
        - On CircuitOpenError: logs WARNING and returns *skipped_value*
          (defaults to None).  The factory is NOT invoked, so a coro
          that opens a file or sends a signal does not partial-execute.

        Falls back to direct ``await coro_factory()`` if CB_COHERENCE
        was not importable at module load time.
        """
        if CB_COHERENCE is None:
            return await coro_factory()
        try:
            return await CB_COHERENCE.call_callable(coro_factory)
        except CircuitOpenError as exc:
            logger.warning(
                "CoherenceBridge: circuit OPEN at %s -- skipping call "
                "until %.1fs (consecutive failures hit threshold)",
                site, getattr(exc, "until_ts", 0.0),
            )
            return skipped_value

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _spawn(self, coro, name: str) -> None:
        try:
            task = asyncio.get_running_loop().create_task(coro, name=name)
        except RuntimeError:
            logger.debug("%s arrived without running loop; skipped", name)
            coro.close()
            return
        self._pending_tasks.add(task)
        task.add_done_callback(self._pending_tasks.discard)

    def _on_pe_load(self, event: Event) -> None:
        # Synchronous bus dispatch entry; hand off to a tracked task so the
        # dispatcher is never blocked on filesystem / signal I/O.
        payload = event.payload if isinstance(event.payload, dict) else {}
        pid = int(event.pid)
        exe_path = str(payload.get("exe_path", ""))
        flags = int(event.flags)
        self._spawn(
            self._handle_load(pid, exe_path, flags, payload),
            name=f"coherence_bridge.load.{pid}",
        )

    def _on_pe_exit(self, event: Event) -> None:
        payload = event.payload if isinstance(event.payload, dict) else {}
        pid = int(event.pid)
        exe_path = str(payload.get("exe_path", ""))
        self._spawn(
            self._handle_exit(pid, exe_path),
            name=f"coherence_bridge.exit.{pid}",
        )

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def _classify(self, exe_path: str, flags: int, payload: dict) -> str:
        """Return "game" or "other" for the given PE load.

        Inputs (priority order):
          1. payload["anticheat"] set to a truthy value by the PE loader
             (anticheat_bridge.c emits the detected AC type into the
             pe_evt_load_t in-flight for games that tripped ac_compat.c).
             Any non-empty string or non-zero int here means "game".
          2. payload["is_game"] explicit boolean hint from cortex_cmd.c.
          3. Known basename set harvested from services/anticheat/ac_compat.c
             detect_blackshield / detect_vanguard / detect_eac helpers.

        We deliberately do not treat EVENT_FLAG_URGENT as a game signal --
        memory anomalies also carry that bit.
        """
        ac = payload.get("anticheat")
        if ac:
            return "game"
        if payload.get("is_game"):
            return "game"
        if exe_path:
            base = os.path.basename(exe_path).lower()
            if base in _KNOWN_GAME_BINARIES:
                return "game"
        return "other"

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    async def _handle_load(
        self,
        pid: int,
        exe_path: str,
        flags: int,
        payload: dict,
    ) -> None:
        if self._disabled:
            return

        classification = self._classify(exe_path, flags, payload)
        base = os.path.basename(exe_path).lower() if exe_path else f"pid_{pid}"

        if classification != "game":
            return

        async with self._lock:
            was_empty = not self._active_games
            self._active_games[pid] = base

            # Runaway spawn defence: once we're tracking more than
            # _MAX_ACTIVE_GAMES live games the override is already in
            # place and extra churn gains us nothing — suspend new
            # classification work until the count drains.
            if len(self._active_games) > _MAX_ACTIVE_GAMES:
                if not self._classification_suspended:
                    self._classification_suspended = True
                    logger.warning(
                        "CoherenceBridge: active game count %d exceeded "
                        "cap %d (latest pid=%d exe=%s); suspending new "
                        "overrides until drain",
                        len(self._active_games), _MAX_ACTIVE_GAMES, pid, base,
                    )
                return

            if self._classification_suspended:
                return

            if not was_empty:
                logger.info(
                    "CoherenceBridge: game pid=%d (%s) joins %d active; "
                    "override already in place",
                    pid, base, len(self._active_games) - 1,
                )
                return

        setpoints = dict(_GAME_SETPOINTS)
        header = (
            f"# active={base} pid={pid} classification={classification} "
            f"t_ns={time.time_ns()}"
        )
        body = self._render_override_body(header, setpoints)
        key = self._throttle_key(classification, setpoints)

        # Throttle SIGHUP storms when launchers spawn a flock of children
        # with the same classification in the first few ms.
        if key == self._last_override_key:
            logger.debug(
                "CoherenceBridge: PE_LOAD pid=%d exe=%s class=%s override "
                "unchanged; skipping write+SIGHUP",
                pid, base, classification,
            )
            return

        async def _write_factory():
            return await asyncio.wait_for(
                asyncio.to_thread(self._write_override_atomic, body),
                timeout=_TO_THREAD_TIMEOUT_S,
            )

        try:
            ok_write = await self._cb_call(
                "write_override_atomic",
                _write_factory,
                skipped_value=False,
            )
        except asyncio.TimeoutError:
            logger.error(
                "CoherenceBridge: write_override_atomic hung >%.1fs "
                "(pid=%d exe=%s); abandoning this PE_LOAD",
                _TO_THREAD_TIMEOUT_S, pid, base,
            )
            return
        if ok_write:
            self._last_override_key = key
        pidfile_pid, pidfile_src = await self._resolve_coherenced_pid()
        ok_signal = False
        if pidfile_pid is not None:
            async def _sighup_factory():
                return await asyncio.wait_for(
                    asyncio.to_thread(self._sighup, pidfile_pid),
                    timeout=_TO_THREAD_TIMEOUT_S,
                )

            try:
                ok_signal = await self._cb_call(
                    "sighup",
                    _sighup_factory,
                    skipped_value=False,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "CoherenceBridge: SIGHUP pid=%d hung >%.1fs",
                    pidfile_pid, _TO_THREAD_TIMEOUT_S,
                )

        logger.info(
            "CoherenceBridge: PE_LOAD pid=%d exe=%s class=%s "
            "override_written=%s pidfile=%s coherenced_pid=%s sighup=%s "
            "setpoints=%s",
            pid, base, classification,
            ok_write, pidfile_src, pidfile_pid, ok_signal, setpoints,
        )

    async def _handle_exit(self, pid: int, exe_path: str = "") -> None:
        if self._disabled:
            return

        # Prefer the self-describing exe_path from the event payload — this
        # survives cortex crash/restart mid-game because the memo may be
        # empty.  Fall back to the LOAD-time memo for older PE events.
        base_from_event = (
            os.path.basename(exe_path).lower() if exe_path else ""
        )

        async with self._lock:
            memo_base = self._active_games.pop(pid, None)
            base = base_from_event or memo_base
            if memo_base is None and base_from_event:
                # We never classified this pid as a game (or the memo was
                # lost on restart).  Only act if the exe_path itself marks
                # it as a known game binary, otherwise bail quietly.
                if base_from_event not in _KNOWN_GAME_BINARIES:
                    return
            elif memo_base is None:
                return
            remaining = len(self._active_games)
            if remaining <= _MAX_ACTIVE_GAMES and self._classification_suspended:
                self._classification_suspended = False
                logger.info(
                    "CoherenceBridge: drained below cap (%d <= %d); "
                    "resuming classification",
                    remaining, _MAX_ACTIVE_GAMES,
                )

        if remaining > 0:
            logger.info(
                "CoherenceBridge: game pid=%d (%s) exited; %d still active; "
                "override retained",
                pid, base, remaining,
            )
            return

        async def _remove_factory():
            return await asyncio.wait_for(
                asyncio.to_thread(self._remove_override),
                timeout=_TO_THREAD_TIMEOUT_S,
            )

        try:
            ok_remove = await self._cb_call(
                "remove_override",
                _remove_factory,
                skipped_value=False,
            )
        except asyncio.TimeoutError:
            logger.error(
                "CoherenceBridge: remove_override hung >%.1fs "
                "(pid=%d exe=%s); leaving override in place",
                _TO_THREAD_TIMEOUT_S, pid, base,
            )
            return
        if ok_remove:
            self._last_override_key = None
        pidfile_pid, pidfile_src = await self._resolve_coherenced_pid()
        ok_signal = False
        if pidfile_pid is not None:
            async def _sighup_factory():
                return await asyncio.wait_for(
                    asyncio.to_thread(self._sighup, pidfile_pid),
                    timeout=_TO_THREAD_TIMEOUT_S,
                )

            try:
                ok_signal = await self._cb_call(
                    "sighup",
                    _sighup_factory,
                    skipped_value=False,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "CoherenceBridge: SIGHUP pid=%d hung >%.1fs",
                    pidfile_pid, _TO_THREAD_TIMEOUT_S,
                )

        logger.info(
            "CoherenceBridge: PE_EXIT pid=%d exe=%s (last game) "
            "override_removed=%s pidfile=%s coherenced_pid=%s sighup=%s",
            pid, base, ok_remove, pidfile_src, pidfile_pid, ok_signal,
        )

    # ------------------------------------------------------------------
    # Filesystem + signal helpers (all run in worker threads)
    # ------------------------------------------------------------------

    @staticmethod
    def _throttle_key(classification: str, setpoints: Dict[str, float]) -> str:
        items = ",".join(f"{k}={v}" for k, v in sorted(setpoints.items()))
        return f"{classification}|{items}|v{_OVERRIDE_VERSION}"

    @staticmethod
    def _render_override_body(header: str, setpoints: Dict[str, float]) -> str:
        lines = [
            "# /etc/coherence/overrides/app-active.conf",
            "# Written by cortex CoherenceBridge. DO NOT EDIT BY HAND.",
            f"# version={_OVERRIDE_VERSION}",
            header,
        ]
        for k, v in setpoints.items():
            lines.append(f"{k} = {v}")
        return "\n".join(lines) + "\n"

    def _write_override_atomic(self, body: str) -> bool:
        try:
            _OVERRIDE_DIR.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.error("CoherenceBridge: cannot create %s: %s", _OVERRIDE_DIR, exc)
            return False

        # Atomic install: write to sibling tmp in the same dir, fsync, rename.
        # Same-dir rename is POSIX-atomic; a reader that races with us either
        # sees the old file or the new one, never a truncated intermediate.
        tmp_fd = None
        tmp_path = None
        try:
            tmp_fd, tmp_path = tempfile.mkstemp(
                prefix=".app-active.", suffix=".conf.tmp", dir=str(_OVERRIDE_DIR),
            )
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
                tmp_fd = None  # fdopen owns it now
                fh.write(body)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp_path, 0o644)
            os.replace(tmp_path, _OVERRIDE_FILE)
            return True
        except OSError as exc:
            logger.error(
                "CoherenceBridge: atomic write to %s failed: %s",
                _OVERRIDE_FILE, exc,
            )
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            return False
        finally:
            if tmp_fd is not None:
                try:
                    os.close(tmp_fd)
                except OSError:
                    pass

    def _remove_override(self) -> bool:
        try:
            _OVERRIDE_FILE.unlink()
            return True
        except FileNotFoundError:
            return True
        except OSError as exc:
            logger.error(
                "CoherenceBridge: cannot remove %s: %s",
                _OVERRIDE_FILE, exc,
            )
            return False

    def _read_pidfile_sync(self) -> Optional[int]:
        for candidate in (_COHERENCE_PIDFILE_PRIMARY, _COHERENCE_PIDFILE_FALLBACK):
            try:
                with open(candidate, "r", encoding="ascii") as fh:
                    raw = fh.read().strip()
                if not raw:
                    continue
                pid = int(raw.split()[0])
                if pid > 1 and self._pid_alive(pid):
                    self._pidfile_path_at_boot = candidate
                    return pid
            except FileNotFoundError:
                continue
            except (OSError, ValueError) as exc:
                logger.debug("pidfile %s unreadable: %s", candidate, exc)
                continue
        return None

    @staticmethod
    def _systemctl_mainpid_sync() -> Optional[int]:
        # MainPID=0 means "not running" per systemd's docs; any positive
        # value is the current leader pid.  We clamp output to keep a
        # malformed systemctl from blocking us.
        try:
            result = subprocess.run(
                ["systemctl", "show", "-p", "MainPID", "--value",
                 _COHERENCE_SYSTEMD_UNIT],
                capture_output=True, text=True, timeout=2.0, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            logger.debug("systemctl MainPID lookup failed: %s", exc)
            return None
        if result.returncode != 0:
            logger.debug(
                "systemctl MainPID rc=%d stderr=%s",
                result.returncode, (result.stderr or "").strip(),
            )
            return None
        raw = (result.stdout or "").strip()
        if not raw:
            return None
        try:
            pid = int(raw.split()[0])
        except (ValueError, IndexError):
            return None
        if pid <= 1:
            return None
        if not CoherenceBridge._pid_alive(pid):
            return None
        return pid

    def _read_pidfile_logged(self) -> Tuple[Optional[int], str]:
        pid = self._read_pidfile_sync()
        if pid is not None:
            return pid, self._pidfile_path_at_boot or "none"
        pid = self._systemctl_mainpid_sync()
        if pid is not None:
            return pid, f"systemctl:{_COHERENCE_SYSTEMD_UNIT}"
        return None, "none"

    async def _resolve_coherenced_pid(self) -> Tuple[Optional[int], str]:
        async def _probe_factory():
            return await asyncio.wait_for(
                asyncio.to_thread(self._read_pidfile_logged),
                timeout=_TO_THREAD_TIMEOUT_S,
            )

        try:
            result = await self._cb_call(
                "resolve_coherenced_pid",
                _probe_factory,
                skipped_value=(None, "circuit_open"),
            )
        except asyncio.TimeoutError:
            logger.warning(
                "CoherenceBridge: resolve_coherenced_pid hung >%.1fs "
                "(stuck /var/run or systemctl?)",
                _TO_THREAD_TIMEOUT_S,
            )
            return (None, "timeout")
        # Defensive: _cb_call's skipped_value already returns the right
        # tuple shape, but if a malformed factory ever returns None we
        # normalise to (None, 'unknown') rather than crashing the caller.
        if result is None:
            return (None, "unknown")
        return result

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        # signal 0 = existence probe only; EPERM also counts as alive
        # (we're merely confirming the process is still in the process table).
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError as exc:
            return exc.errno != errno.ESRCH
        return True

    @staticmethod
    def _sighup(pid: int) -> bool:
        try:
            os.kill(pid, signal.SIGHUP)
            return True
        except ProcessLookupError:
            logger.warning(
                "CoherenceBridge: SIGHUP target pid=%d vanished between "
                "pidfile read and kill()", pid,
            )
            return False
        except PermissionError as exc:
            logger.error(
                "CoherenceBridge: SIGHUP pid=%d denied: %s "
                "(cortex must run as root or share coherenced's uid)",
                pid, exc,
            )
            return False
        except OSError as exc:
            logger.error("CoherenceBridge: SIGHUP pid=%d failed: %s", pid, exc)
            return False

    # ------------------------------------------------------------------
    # Introspection (used by /status endpoint if wired)
    # ------------------------------------------------------------------

    @property
    def is_active(self) -> bool:
        return not self._disabled and bool(self._active_games)

    @property
    def active_games(self) -> Dict[int, str]:
        return dict(self._active_games)

    @property
    def disabled_reason(self) -> str:
        return self._disabled_reason
