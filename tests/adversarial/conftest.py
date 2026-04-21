"""
S75 Agent A — Adversarial theorem harness: pytest fixtures.

This conftest provides the minimal wiring that all seven T1..T7 test classes
in :mod:`theorem_violation_suite` share:

- a ``trust_env`` fixture exposing "can we actually run against a live
  trust.ko?" so tests gate themselves via ``pytest.mark.skipif`` instead of
  hard-failing on build hosts (WSL2, CI runners) where ``/dev/trust`` and
  ``/sys/kernel/trust_invariants/`` don't exist;

- a ``counters`` fixture: a snapshot/diff helper for the sysfs invariant
  counters documented in ``trust/include/trust_theorems.h:27-34``;

- a ``subject_factory`` fixture: creates disposable trust subjects via
  ``/dev/trust`` ioctls and reliably tears them down on test exit;

- a ``helpers_bin`` fixture: resolves the companion ``helpers`` binary
  built by ``tests/adversarial/Makefile`` (APE state snapshot / proof-replay
  / entropy sampler).

No kernel-module source is touched by this harness — it is a pure read
path over sysfs + ioctl surface. See
``docs/runtime-theorem-validation.md`` §1 (harness architecture) and
``docs/s75_roadmap.md`` §1.1.1 (why this is Item #1).
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional

import pytest


# ---------------------------------------------------------------------------
# Paths + environment discovery
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
ADV_DIR = Path(__file__).resolve().parent
TRUST_INVARIANTS_DIR = Path("/sys/kernel/trust_invariants")
TRUST_DEV = Path("/dev/trust")

# Mapping of test-facing short names to sysfs node names.  The set of nodes
# is dictated by trust/kernel/trust_invariants.c:325-333 (the
# trust_invariants_attrs[] table).
COUNTER_NODES: Dict[str, str] = {
    "t1": "theorem1_violations",
    "t2": "theorem2_violations",
    "t4": "theorem4_violations",
    "t5": "theorem5_violations",
    "t5_max_us": "theorem5_max_us",
    "t6": "theorem6_violations",
    "nonce": "global_nonce",
}


@dataclass
class TrustEnv:
    """Runtime environment snapshot — 'can we run a live adversarial test?'

    Kept intentionally read-only after construction so tests can branch on
    a single flag (``live``) instead of probing the filesystem repeatedly.
    """

    live: bool
    dev_trust: bool
    sysfs: bool
    libtrust_so: Optional[Path]
    helpers_bin: Optional[Path]
    reason: str = ""


def _safe_exists(p: Path) -> bool:
    """Defensive existence probe.

    On Windows hosts, repo paths that were created inside WSL may be
    symlinks the Win32 layer cannot follow (WinError 1920), which
    raises OSError from ``Path.exists()``.  Treat such paths as "not
    present" so the harness skips live tests cleanly on the build
    host instead of erroring out of fixture setup.
    """
    try:
        return p.exists()
    except OSError:
        return False


def _detect_env() -> TrustEnv:
    has_dev = _safe_exists(TRUST_DEV)
    try:
        has_sysfs = TRUST_INVARIANTS_DIR.is_dir()
    except OSError:
        has_sysfs = False
    libtrust = REPO_ROOT / "trust" / "lib" / "libtrust.so"
    helpers = ADV_DIR / "helpers"

    reasons = []
    if not has_dev:
        reasons.append("/dev/trust missing (trust.ko not loaded)")
    if not has_sysfs:
        reasons.append("/sys/kernel/trust_invariants/ missing")
    live = has_dev and has_sysfs

    return TrustEnv(
        live=live,
        dev_trust=has_dev,
        sysfs=has_sysfs,
        libtrust_so=libtrust if _safe_exists(libtrust) else None,
        helpers_bin=helpers if _safe_exists(helpers) else None,
        reason="; ".join(reasons) if reasons else "",
    )


@pytest.fixture(scope="session")
def trust_env() -> TrustEnv:
    return _detect_env()


# ---------------------------------------------------------------------------
# Counter snapshot / diff helper
# ---------------------------------------------------------------------------


@dataclass
class CounterSnapshot:
    """Frozen snapshot of the sysfs invariant surface."""
    values: Dict[str, int] = field(default_factory=dict)

    def __sub__(self, other: "CounterSnapshot") -> "CounterDelta":
        if not isinstance(other, CounterSnapshot):
            return NotImplemented
        return CounterDelta(
            {k: self.values.get(k, 0) - other.values.get(k, 0)
             for k in set(self.values) | set(other.values)}
        )

    def get(self, key: str, default: int = 0) -> int:
        return self.values.get(key, default)


@dataclass
class CounterDelta:
    """Post - pre difference between two :class:`CounterSnapshot`s."""
    values: Dict[str, int] = field(default_factory=dict)

    def __getattr__(self, name: str) -> int:  # noqa: D401
        # Accessors to mirror research-J §5 Proposal A: delta.theorem2_violations
        if name.startswith("theorem"):
            return self.values.get(name, 0)
        raise AttributeError(name)

    def get(self, key: str, default: int = 0) -> int:
        return self.values.get(key, default)

    def __repr__(self) -> str:
        nonzero = {k: v for k, v in self.values.items() if v}
        return f"CounterDelta({nonzero!r})"


class CountersSnapshotter:
    """Lightweight sysfs reader.  Reads every file in COUNTER_NODES
    and returns a :class:`CounterSnapshot`.  Silently zero-fills any
    missing node (so the fixture survives a partial kernel with fewer
    invariant attributes than we expect).

    We deliberately swallow read errors rather than raising — the test
    itself will fail-closed via ``pytest.skip`` upstream if the whole
    sysfs subtree is absent.  A single unreadable node should not
    abort a test run.
    """

    def __init__(self, base: Path = TRUST_INVARIANTS_DIR) -> None:
        self.base = base

    def snapshot(self) -> CounterSnapshot:
        values: Dict[str, int] = {}
        for short, node in COUNTER_NODES.items():
            path = self.base / node
            try:
                raw = path.read_text().strip()
                values[node] = int(raw) if raw else 0
            except (OSError, ValueError):
                values[node] = 0
            # Also stash short alias for ergonomic access.
            values.setdefault(short, values[node])
        return CounterSnapshot(values=values)


@pytest.fixture
def counters(trust_env: TrustEnv) -> CountersSnapshotter:
    """Return a snapshotter.  Does NOT skip on missing sysfs — the test
    decides whether zero-filled snapshots are useful (for unit-level
    structural checks) or whether it must skip (for live counter-fire
    assertions).  The skip decision lives in the test, keyed on
    ``trust_env.live``.
    """
    return CountersSnapshotter()


# ---------------------------------------------------------------------------
# Subject factory — wraps /dev/trust ioctl via the helpers binary
# ---------------------------------------------------------------------------


class SubjectFactory:
    """Creates disposable trust subjects for the duration of a test.

    Implementation strategy: shell out to the companion ``helpers`` binary
    (built by ``tests/adversarial/Makefile``) which is a thin wrapper over
    libtrust — this avoids re-implementing the 30-odd ioctl wrappers in
    Python ctypes, and keeps the TOCTOU window tight (the helper opens,
    registers, and closes /dev/trust in a single short-lived process).

    Every subject allocated via :meth:`register` is tracked and torn down
    on fixture teardown, even if the test raises mid-body.
    """

    def __init__(self, helpers_bin: Optional[Path]) -> None:
        self.helpers_bin = helpers_bin
        self._allocated: List[int] = []

    def available(self) -> bool:
        return self.helpers_bin is not None and self.helpers_bin.exists()

    def register(self, subject_id: int, authority: int = 1,
                 initial_score: int = 500) -> bool:
        """Register a subject.  Returns True on success, False on any
        failure path (including helpers binary absent or ioctl error)."""
        if not self.available():
            return False
        try:
            r = subprocess.run(
                [str(self.helpers_bin), "register",
                 str(subject_id), str(authority), str(initial_score)],
                capture_output=True, timeout=5, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if r.returncode == 0:
            self._allocated.append(subject_id)
            return True
        return False

    def apoptosis(self, subject_id: int) -> bool:
        if not self.available():
            return False
        try:
            r = subprocess.run(
                [str(self.helpers_bin), "apoptosis", str(subject_id)],
                capture_output=True, timeout=5, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if subject_id in self._allocated:
            self._allocated.remove(subject_id)
        return r.returncode == 0

    def cleanup(self) -> None:
        # Copy because apoptosis() mutates _allocated.
        for sid in list(self._allocated):
            self.apoptosis(sid)
        self._allocated.clear()


@pytest.fixture
def subject_factory(trust_env: TrustEnv) -> Iterator[SubjectFactory]:
    f = SubjectFactory(trust_env.helpers_bin)
    try:
        yield f
    finally:
        f.cleanup()


# ---------------------------------------------------------------------------
# Helpers binary — path + executability check
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def helpers_bin(trust_env: TrustEnv) -> Optional[Path]:
    if trust_env.helpers_bin is None:
        return None
    # Be defensive: a stale helpers file that's not executable would cause
    # surprising behaviour later.  Probe for the x-bit.  On Windows the
    # st_mode x-bits are synthetic — accept any stat() that succeeds.
    try:
        st = trust_env.helpers_bin.stat()
    except OSError:
        return None
    if os.name == "posix" and not (
            st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
        return None
    return trust_env.helpers_bin


# ---------------------------------------------------------------------------
# Convenience skip-if-not-live marker factory
# ---------------------------------------------------------------------------


def pytest_configure(config: pytest.Config) -> None:
    """Register the ``adversarial`` marker so ``pytest -m adversarial``
    targets this suite without warnings.  Also register ``live`` for
    tests that require a real trust.ko (vs structural checks that run
    anywhere).
    """
    config.addinivalue_line(
        "markers",
        "adversarial: Root of Authority theorem violation tests (S75 Item 1)",
    )
    config.addinivalue_line(
        "markers",
        "live: requires a running trust.ko (skipped on build hosts)",
    )


@pytest.fixture
def skip_if_not_live(trust_env: TrustEnv) -> None:
    """Inline-callable variant of the ``live`` marker for parametrized
    tests that need to skip on a per-case basis."""
    if not trust_env.live:
        pytest.skip(f"trust.ko not live: {trust_env.reason}")
