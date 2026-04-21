"""pytest fixtures for the bisim suite.

Kept deliberately tiny: the harness is importable as plain python so the
heavy lifting happens in the modules, not in pytest plumbing.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


# Ensure the bisim dir is on sys.path so ``ape_pure_cross``,
# ``trace_harness``, and ``discrepancy_detector`` resolve when pytest
# is invoked either from the repo root or from within tests/bisim.
_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
for p in (_HERE, _REPO_ROOT):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return _REPO_ROOT


@pytest.fixture(scope="session")
def bisim_dir() -> Path:
    return Path(__file__).resolve().parent


@pytest.fixture
def fixture_path(bisim_dir: Path) -> Path:
    return bisim_dir / "fixtures" / "ape_vectors.json"


@pytest.fixture
def kernel_available() -> bool:
    """Whether /dev/trust is accessible on this host.

    On WSL / dev laptops this is False; on an ARCHIMATION-booted QEMU VM
    it's True. The smoke test consults this to decide whether to skip
    the kernel arm of the bisim.
    """
    return os.path.exists("/dev/trust")
