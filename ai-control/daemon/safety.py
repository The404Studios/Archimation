"""
safety.py — Sanitizer / Throttler / CircuitBreaker (Session 49, Agent D).

Three orthogonal hardening primitives that the daemon used to inline in
~30 different sites:

  Sanitizer       — single chokepoint for input normalize-and-reject.
  Throttler       — token-bucket rate limiter, per (key, route).
  CircuitBreaker  — three-state (CLOSED -> OPEN -> HALF_OPEN -> CLOSED)
                    wrapper for unreliable upstreams.

Why one file: every bug we shipped in the rate-limiter / path-validation
class came from a divergent re-implementation. Centralising all three
gives one set of invariants to break, one set of tests, and one place
audits look for "did the daemon enforce X here?".

Importable as:

    from safety import (
        Sanitizer, SanitizerError,
        Throttler, THROTTLE_AUTH_FAIL, THROTTLE_DRIVER_LOAD,
        THROTTLE_GAME_LAUNCH, THROTTLE_MEIOSIS,
        CircuitBreaker, CircuitOpenError,
        CB_CORTEX, CB_LLAMA, CB_COHERENCE,
    )

Run as a script for the smoke test:

    python3 safety.py

Constraints honoured:
  * Pure stdlib (asyncio + threading); no third-party deps.
  * Async-first: Throttler + CircuitBreaker take asyncio.Lock; Sanitizer
    is stateless so it's safe from any thread.
  * No global state outside the documented module-level singletons.
"""

from __future__ import annotations

import asyncio
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Iterable, List, Optional, TypeVar

# ---------------------------------------------------------------------------
# Sanitizer
# ---------------------------------------------------------------------------


class SanitizerError(ValueError):
    """Raised when input fails Sanitizer normalize-and-reject.

    Inherits from ValueError so existing FastAPI handlers that catch
    ValueError to emit 422 still work; new sites should catch
    SanitizerError specifically and emit 400/403 for clarity.
    """

    def __init__(self, message: str, *, kind: str, value: object = None):
        super().__init__(message)
        self.kind = kind          # "traversal", "metachar", "regex", ...
        self.value = value        # the rejected input (truncated by caller)

    def as_dict(self) -> dict:
        v = self.value
        if isinstance(v, str) and len(v) > 256:
            v = v[:253] + "..."
        return {"error": "sanitizer_reject", "kind": self.kind,
                "message": str(self), "value": v}


# Default shell metacharacters that must NEVER appear in argv coming
# from untrusted callers. NUL is included to defend against C-string
# truncation (Linux argv is NUL-terminated; an embedded NUL silently
# truncates the argument from the kernel's POV but the daemon still
# logs the full string, creating a misleading audit trail).
_DEFAULT_SHELL_METACHARS = frozenset(";|&$`\n\r\x00")

_MODULE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_UNIT_NAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,128}$")


class Sanitizer:
    """Stateless validators. All raise SanitizerError on rejection."""

    @staticmethod
    def path(p: str, *, must_exist: bool = False,
             allow_relative: bool = False,
             allowlist: Optional[Iterable[str]] = None) -> str:
        """Normalise *p* via realpath() and apply guard-rails.

        - Empty / non-string inputs reject with kind='empty' / 'type'.
        - realpath() collapses `..` AND symlinks; abspath alone leaves
          symlink-escapes (`/tmp/evil -> /etc/shadow`) intact.
        - When allow_relative=False, the input must already be absolute
          OR the realpath must agree with abspath (i.e. no surprising
          cwd-relative resolution).
        - When allowlist is given, the realpath must be EXACTLY equal
          to one of its entries (not a substring/prefix match — allowlist
          membership is the security boundary).
        - When must_exist=True, the realpath must exist on disk after
          resolution.
        """
        if not isinstance(p, str):
            raise SanitizerError("path must be a string",
                                 kind="type", value=p)
        if not p:
            raise SanitizerError("path is empty", kind="empty", value=p)
        if "\x00" in p:
            raise SanitizerError("path contains NUL", kind="nul", value=p)

        if not allow_relative and not os.path.isabs(p):
            raise SanitizerError("path must be absolute",
                                 kind="relative", value=p)

        # Resolve symlinks + ../ in one pass. realpath does NOT raise on
        # missing files; that's intentional — caller picks must_exist.
        resolved = os.path.realpath(p)

        if must_exist and not os.path.exists(resolved):
            raise SanitizerError("path does not exist after realpath",
                                 kind="missing", value=resolved)

        if allowlist is not None:
            allow = set(allowlist)
            if resolved not in allow:
                raise SanitizerError(
                    f"path {resolved!r} not on allowlist",
                    kind="allowlist", value=resolved,
                )

        return resolved

    @staticmethod
    def argv(args: Iterable[str], *, max_args: int = 64,
             forbidden_chars: Optional[Iterable[str]] = None) -> List[str]:
        """Validate an argv list intended for execve.

        - Each element must be a string (no None / int / bytes leaks).
        - No element may contain shell metacharacters from the default
          set (or the caller-supplied set). The daemon uses execve()
          directly so metacharacters technically don't get expanded —
          but rejecting them defensively closes future regressions
          where someone reroutes through a shell.
        - List length capped at max_args.
        """
        if args is None:
            return []
        if isinstance(args, (str, bytes)):
            raise SanitizerError(
                "argv must be a list/iterable, not a single string",
                kind="type", value=args,
            )
        out: List[str] = []
        bad = (frozenset(forbidden_chars)
               if forbidden_chars is not None
               else _DEFAULT_SHELL_METACHARS)
        for i, a in enumerate(args):
            if i >= max_args:
                raise SanitizerError(
                    f"argv exceeds max_args={max_args}",
                    kind="length", value=i,
                )
            if not isinstance(a, str):
                raise SanitizerError(
                    f"argv[{i}] is not a string",
                    kind="type", value=a,
                )
            if any(c in a for c in bad):
                raise SanitizerError(
                    f"argv[{i}] contains forbidden character",
                    kind="metachar", value=a,
                )
            out.append(a)
        return out

    @staticmethod
    def module_name(name: str) -> str:
        """Validate a kernel module name for /driver/{load,unload}.

        Conservative: `[A-Za-z0-9_-]{1,64}`. modprobe accepts more, but
        the daemon's allowlist never needs anything else. Stripping
        whitespace is the caller's job — we reject unstripped input
        rather than silently normalise it.
        """
        if not isinstance(name, str):
            raise SanitizerError("module name must be a string",
                                 kind="type", value=name)
        if not _MODULE_NAME_RE.match(name):
            raise SanitizerError(
                "module name must match [A-Za-z0-9_-]{1,64}",
                kind="regex", value=name,
            )
        return name

    @staticmethod
    def unit_name(name: str) -> str:
        """Validate a systemd unit name for /service/{start,stop,...}.

        Allowed: `[A-Za-z0-9._@-]{1,128}`. systemd permits a wider set
        but the daemon's allowlist (firewall, NetworkManager, ...) never
        uses anything else; rejecting `:`, `+`, `=`, `,` defends against
        propagation of attacker-controlled bytes into journalctl/audit.
        """
        if not isinstance(name, str):
            raise SanitizerError("unit name must be a string",
                                 kind="type", value=name)
        if not _UNIT_NAME_RE.match(name):
            raise SanitizerError(
                "unit name must match [A-Za-z0-9._@-]{1,128}",
                kind="regex", value=name,
            )
        return name


# ---------------------------------------------------------------------------
# Throttler — token-bucket per key
# ---------------------------------------------------------------------------


@dataclass
class _Bucket:
    last_refill: float
    tokens: float


class Throttler:
    """Token-bucket throttler keyed on caller-supplied identifier.

    Per-instance state, asyncio-lock-protected. A single Throttler is
    appropriate per (logical-route, dimension) tuple — instantiate one
    THROTTLE_* singleton at module level for each rate-limited surface.

    Memory bound: keys are pruned when their bucket has been at full
    capacity AND idle for >5 * (burst / rate) seconds. That window is
    long enough that a steady-state caller will never be evicted while
    active, but short enough that a botnet sweeping random IPs cannot
    grow the dict unboundedly.
    """

    def __init__(self, rate_per_sec: float, burst: int,
                 *, name: str = "throttler"):
        if rate_per_sec <= 0:
            raise ValueError("rate_per_sec must be > 0")
        if burst <= 0:
            raise ValueError("burst must be > 0")
        self.rate = float(rate_per_sec)
        self.burst = int(burst)
        self.name = name
        self._buckets: dict[str, _Bucket] = {}
        self._lock = asyncio.Lock()
        # Threading lock as a fallback for any sync caller that hasn't
        # been ported to async yet (auth.py, currently). Either lock is
        # held, never both — see _refill_locked() comment.
        self._sync_lock = threading.Lock()
        # Idle eviction horizon (seconds). 5 full-bucket refills.
        self._idle_horizon = 5.0 * (self.burst / self.rate)

    def _refill_locked(self, key: str, now: float) -> _Bucket:
        """Compute current tokens for *key*; caller holds the lock."""
        b = self._buckets.get(key)
        if b is None:
            b = _Bucket(last_refill=now, tokens=float(self.burst))
            self._buckets[key] = b
            return b
        elapsed = max(0.0, now - b.last_refill)
        b.tokens = min(float(self.burst), b.tokens + elapsed * self.rate)
        b.last_refill = now
        return b

    def _maybe_evict(self, now: float) -> None:
        """O(N) sweep when the dict gets too large. Cheap for our sizes."""
        if len(self._buckets) < 1024:
            return
        cutoff = now - self._idle_horizon
        dead = [k for k, b in self._buckets.items()
                if b.tokens >= self.burst and b.last_refill < cutoff]
        for k in dead:
            del self._buckets[k]

    async def try_acquire(self, key: str) -> bool:
        """Non-blocking. Return True if a token was consumed."""
        now = time.monotonic()
        async with self._lock:
            b = self._refill_locked(key, now)
            if b.tokens >= 1.0:
                b.tokens -= 1.0
                return True
            self._maybe_evict(now)
            return False

    async def acquire(self, key: str, timeout: Optional[float] = None) -> bool:
        """Blocking variant. Return True iff a token was consumed within
        *timeout* seconds (None = wait forever, with cooperative sleeps)."""
        deadline = (time.monotonic() + timeout) if timeout else None
        while True:
            if await self.try_acquire(key):
                return True
            if deadline is not None and time.monotonic() >= deadline:
                return False
            # Sleep at most until the next token would be available, capped
            # so a tiny rate doesn't sleep for minutes uninterruptibly.
            wait = min(1.0, 1.0 / self.rate)
            await asyncio.sleep(wait)

    # Sync escape hatch (auth.py middleware sometimes runs outside the
    # event loop). NEVER call from within an async coroutine; you'll
    # block the loop thread.
    def try_acquire_sync(self, key: str) -> bool:
        now = time.monotonic()
        with self._sync_lock:
            b = self._buckets.get(key)
            if b is None:
                b = _Bucket(last_refill=now, tokens=float(self.burst))
                self._buckets[key] = b
            else:
                elapsed = max(0.0, now - b.last_refill)
                b.tokens = min(float(self.burst),
                               b.tokens + elapsed * self.rate)
                b.last_refill = now
            if b.tokens >= 1.0:
                b.tokens -= 1.0
                return True
            return False


# Pre-built singletons. Tuned per surface:
#
#   THROTTLE_DRIVER_LOAD   — modprobe is slow; 1/s sustained, 3 burst
#                            so a careful rebuild script can flip 3
#                            modules in a row without backoff.
#   THROTTLE_GAME_LAUNCH   — game launches spawn DXVK shaders + audio,
#                            ~0.5/s sustained is plenty; burst 2.
#   THROTTLE_MEIOSIS       — cortex meiosis_request is heavy decision
#                            work; 0.2/s sustained, burst 2.
#   THROTTLE_AUTH_FAIL     — auth-failure recording. Mirrors the
#                            existing 10/60s window in auth.py:
#                            10/60 = 0.167/s, burst 10.
#
# Tweak only if you've measured the actual call rate of the legitimate
# clients first.
THROTTLE_DRIVER_LOAD = Throttler(1.0, 3, name="driver_load")
THROTTLE_GAME_LAUNCH = Throttler(0.5, 2, name="game_launch")
THROTTLE_MEIOSIS = Throttler(0.2, 2, name="meiosis")
THROTTLE_AUTH_FAIL = Throttler(10.0 / 60.0, 10, name="auth_fail")


# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------


class CircuitOpenError(RuntimeError):
    """Raised by CircuitBreaker.call when the circuit is OPEN."""

    def __init__(self, name: str, until_ts: float):
        super().__init__(f"circuit {name!r} OPEN until {until_ts:.1f}")
        self.name = name
        self.until_ts = until_ts


T = TypeVar("T")


@dataclass
class _CBState:
    state: str = "CLOSED"               # CLOSED | OPEN | HALF_OPEN
    consecutive_failures: int = 0
    last_state_change_ts: float = field(default_factory=time.monotonic)
    total_failures: int = 0
    total_successes: int = 0
    half_open_in_flight: int = 0


class CircuitBreaker:
    """Three-state breaker.

    CLOSED: forward all calls; count consecutive failures. After
            *failure_threshold* in a row, transition -> OPEN.
    OPEN:   reject immediately with CircuitOpenError. After
            *recovery_timeout_s* elapsed, transition -> HALF_OPEN.
    HALF_OPEN: allow up to *half_open_max_calls* trial calls in flight.
            On success -> CLOSED (counters reset). On failure -> OPEN
            again (timer reset).

    Wrap any awaitable that hits an unreliable upstream (cortex HTTP,
    llama backend, coherence socket). If the upstream is down, we stop
    hammering it within failure_threshold calls, give it
    recovery_timeout_s to come back, then trial one request before
    fully reopening the gate.
    """

    def __init__(self, name: str, *, failure_threshold: int = 5,
                 recovery_timeout_s: float = 30.0,
                 half_open_max_calls: int = 1):
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if recovery_timeout_s <= 0:
            raise ValueError("recovery_timeout_s must be > 0")
        if half_open_max_calls < 1:
            raise ValueError("half_open_max_calls must be >= 1")
        self.name = name
        self.failure_threshold = int(failure_threshold)
        self.recovery_timeout_s = float(recovery_timeout_s)
        self.half_open_max_calls = int(half_open_max_calls)
        self._s = _CBState()
        self._lock = asyncio.Lock()

    @property
    def state(self) -> str:
        return self._s.state

    def metrics(self) -> dict:
        s = self._s
        return {
            "name": self.name,
            "state": s.state,
            "consecutive_failures": s.consecutive_failures,
            "last_state_change_ts": s.last_state_change_ts,
            "total_failures": s.total_failures,
            "total_successes": s.total_successes,
            "failure_threshold": self.failure_threshold,
            "recovery_timeout_s": self.recovery_timeout_s,
            "half_open_max_calls": self.half_open_max_calls,
            "half_open_in_flight": s.half_open_in_flight,
        }

    async def _gate_open_to_half_open(self, now: float) -> None:
        """OPEN -> HALF_OPEN if enough time has passed. Caller holds lock."""
        if self._s.state != "OPEN":
            return
        if (now - self._s.last_state_change_ts) >= self.recovery_timeout_s:
            self._s.state = "HALF_OPEN"
            self._s.last_state_change_ts = now
            self._s.half_open_in_flight = 0

    async def _admit(self) -> str:
        """Decide whether the next call may proceed.

        Returns the state under which the caller is admitted: 'CLOSED'
        or 'HALF_OPEN'. Raises CircuitOpenError if the breaker is OPEN
        (or HALF_OPEN at capacity)."""
        now = time.monotonic()
        async with self._lock:
            await self._gate_open_to_half_open(now)
            if self._s.state == "OPEN":
                until = self._s.last_state_change_ts + self.recovery_timeout_s
                raise CircuitOpenError(self.name, until)
            if self._s.state == "HALF_OPEN":
                if self._s.half_open_in_flight >= self.half_open_max_calls:
                    until = (self._s.last_state_change_ts
                             + self.recovery_timeout_s)
                    raise CircuitOpenError(self.name, until)
                self._s.half_open_in_flight += 1
                return "HALF_OPEN"
            return "CLOSED"

    async def _record_success(self, admitted_under: str) -> None:
        async with self._lock:
            self._s.total_successes += 1
            self._s.consecutive_failures = 0
            if admitted_under == "HALF_OPEN":
                self._s.half_open_in_flight = max(
                    0, self._s.half_open_in_flight - 1,
                )
                if self._s.state == "HALF_OPEN":
                    self._s.state = "CLOSED"
                    self._s.last_state_change_ts = time.monotonic()

    async def _record_failure(self, admitted_under: str) -> None:
        async with self._lock:
            self._s.total_failures += 1
            self._s.consecutive_failures += 1
            if admitted_under == "HALF_OPEN":
                self._s.half_open_in_flight = max(
                    0, self._s.half_open_in_flight - 1,
                )
                # Any HALF_OPEN failure trips back to OPEN immediately.
                self._s.state = "OPEN"
                self._s.last_state_change_ts = time.monotonic()
                return
            if (self._s.state == "CLOSED"
                    and self._s.consecutive_failures >= self.failure_threshold):
                self._s.state = "OPEN"
                self._s.last_state_change_ts = time.monotonic()

    async def call(self, coro: Awaitable[T]) -> T:
        """Wrap *coro* and apply breaker semantics.

        Pass an already-constructed awaitable (e.g.
        ``await cb.call(client.get(url))``). On CircuitOpenError the
        coro is NOT awaited — caller's responsibility to discard.

        Any exception raised by the coro counts as a failure; the
        breaker re-raises after recording. Use ``call_callable`` if
        you need to construct the coro lazily (so it isn't created
        when the gate is OPEN).
        """
        admitted_under = await self._admit()
        try:
            result = await coro
        except Exception:
            await self._record_failure(admitted_under)
            raise
        await self._record_success(admitted_under)
        return result

    async def call_callable(self, factory: Callable[[], Awaitable[T]]) -> T:
        """Like .call but defers awaitable construction until admission.

        Use when constructing the coroutine itself has side effects
        (opens a socket, schedules a task) you don't want to pay
        when the breaker is OPEN.
        """
        admitted_under = await self._admit()
        try:
            result = await factory()
        except Exception:
            await self._record_failure(admitted_under)
            raise
        await self._record_success(admitted_under)
        return result


# Pre-built singletons. One per upstream the daemon depends on.
#
#   CB_CORTEX     — cortex HTTP on 127.0.0.1:8421. Must be reasonably
#                   tolerant: cortex restarts during a fix-and-restart
#                   cycle, and we don't want to lock out emergency
#                   surfaces for 30s if it just blipped. 5 fails @ 2s
#                   timeout = 10s open-detect; recovery 15s.
#   CB_LLAMA      — llama-cpp inference. Slow + variable; 3 fails
#                   (model load can fail spuriously on cold disks),
#                   recovery 30s (model reload cost).
#   CB_COHERENCE  — coherenced unix socket / HTTP. Drops happen during
#                   actuation rate-limit; 5 fails / 10s recovery.
CB_CORTEX = CircuitBreaker("cortex", failure_threshold=5,
                           recovery_timeout_s=15.0)
CB_LLAMA = CircuitBreaker("llama", failure_threshold=3,
                          recovery_timeout_s=30.0)
CB_COHERENCE = CircuitBreaker("coherence", failure_threshold=5,
                              recovery_timeout_s=10.0)


# ---------------------------------------------------------------------------
# __main__ smoke test
# ---------------------------------------------------------------------------


async def _smoke_throttler() -> int:
    """Drain a bucket, sleep to refill, drain again. Returns pass count."""
    passes = 0
    th = Throttler(rate_per_sec=10.0, burst=3, name="smoke")
    # Drain burst.
    drained_first = []
    for _ in range(3):
        drained_first.append(await th.try_acquire("k"))
    if all(drained_first):
        passes += 1
    # Next call immediately should fail.
    if not await th.try_acquire("k"):
        passes += 1
    # Wait long enough to refill ~3 tokens (3 / 10 = 0.3s; +safety margin).
    await asyncio.sleep(0.5)
    drained_second = []
    for _ in range(3):
        drained_second.append(await th.try_acquire("k"))
    if all(drained_second):
        passes += 1
    return passes


async def _smoke_circuit_breaker() -> int:
    """5 fails -> OPEN; sleep recovery; success -> CLOSED."""
    passes = 0
    cb = CircuitBreaker("smoke", failure_threshold=5,
                        recovery_timeout_s=0.3,
                        half_open_max_calls=1)

    async def boom():
        raise RuntimeError("simulated upstream fault")

    async def ok():
        return "alive"

    # 5 failures -> OPEN. Use call_callable so the coro is constructed
    # only when admitted (avoids "coroutine never awaited" warnings).
    for _ in range(5):
        try:
            await cb.call_callable(boom)
        except RuntimeError:
            pass
    if cb.state == "OPEN":
        passes += 1

    # Immediate next call must reject without invoking the factory.
    try:
        await cb.call_callable(ok)
    except CircuitOpenError:
        passes += 1

    # Wait recovery_timeout_s; next call should be admitted as HALF_OPEN.
    await asyncio.sleep(0.4)
    try:
        result = await cb.call_callable(ok)
        if result == "alive" and cb.state == "CLOSED":
            passes += 1
    except Exception:
        pass

    return passes


def _smoke_sanitizer() -> int:
    """3 reject + 3 accept cases. Returns pass count (max 6)."""
    passes = 0

    # --- Accept cases ---

    # Pick a path that's absolute on both POSIX and Windows so the
    # smoke test runs in either dev environment. tempfile.gettempdir()
    # returns /tmp on Linux, C:\Users\...\Temp on Windows.
    import tempfile
    abs_tmp = tempfile.gettempdir()

    try:
        # Absolute path (no allowlist) returns realpath unchanged.
        out = Sanitizer.path(abs_tmp)
        if isinstance(out, str) and os.path.isabs(out):
            passes += 1
    except Exception:
        pass

    try:
        out = Sanitizer.argv(["arg1", "arg2", "--flag", "value"])
        if out == ["arg1", "arg2", "--flag", "value"]:
            passes += 1
    except Exception:
        pass

    try:
        out = Sanitizer.module_name("nvidia_uvm")
        if out == "nvidia_uvm":
            passes += 1
    except Exception:
        pass

    # --- Reject cases ---

    # Allowlist-rejection: pass an absolute path that exists; the
    # rejection must be 'allowlist', not 'relative'/'missing'.
    try:
        Sanitizer.path(abs_tmp, allowlist=["/usr/bin/firefox"])
    except SanitizerError as e:
        if e.kind == "allowlist":
            passes += 1

    try:
        Sanitizer.argv(["safe", "rm -rf /; echo pwned"])
    except SanitizerError as e:
        if e.kind == "metachar":
            passes += 1

    try:
        Sanitizer.module_name("nvidia; rmmod trust")
    except SanitizerError as e:
        if e.kind == "regex":
            passes += 1

    return passes


async def _main() -> int:
    san = _smoke_sanitizer()
    thr = await _smoke_throttler()
    cb = await _smoke_circuit_breaker()
    total = san + thr + cb
    expected = 6 + 3 + 3
    print(f"safety.py smoke test: sanitizer={san}/6  "
          f"throttler={thr}/3  circuit_breaker={cb}/3  "
          f"total={total}/{expected}")
    return 0 if total == expected else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
