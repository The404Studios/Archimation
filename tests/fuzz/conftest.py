"""Shared configuration / path setup for S79 fuzz tests.

All fuzz tests in this directory are gated behind the ``FUZZ_TESTS=1``
environment variable. Each test suite declares:

    @unittest.skipUnless(os.environ.get('FUZZ_TESTS'),
                         'fuzz tests disabled by default')

so the default ``python -m unittest discover`` call here is a no-op.

We deliberately avoid any external dependency (no hypothesis, no atheris):
the project convention is stdlib-only tests, and fuzz iterations here are
hand-rolled with ``random.Random(seed=42)`` for reproducibility plus one
``random.SystemRandom`` cousin per suite to find rare paths.

S79 Test Agent 1 deliverable.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Resolve repo root and add the daemon + cortex dirs onto sys.path so each
# fuzz module can ``import library_census`` / ``import monte_carlo`` / etc.
# directly without PYTHONPATH gymnastics.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DAEMON_DIR = _REPO_ROOT / "ai-control" / "daemon"
_CORTEX_DIR = _REPO_ROOT / "ai-control" / "cortex"

for _p in (_DAEMON_DIR, _CORTEX_DIR):
    sp = str(_p)
    if sp not in sys.path:
        sys.path.insert(0, sp)


# Expose the gate flag as a module-level constant so suites share one
# import rather than each re-reading the env var.
FUZZ_ENABLED: bool = bool(os.environ.get("FUZZ_TESTS"))
FUZZ_ITERATIONS: int = int(os.environ.get("FUZZ_ITERATIONS", "1000"))

# Shared deterministic seed. Individual suites should build their own
# random.Random(seed) instances derived from this root value so that
# ticking a single test's seed doesn't shift the entire campaign.
FUZZ_ROOT_SEED: int = 42
