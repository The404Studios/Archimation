"""Unit tests for the canonical trust-ontology translator.

Exercises ``ai-control/daemon/trust_translate.py`` (and its sibling copy
in ``ai-control/cortex/trust_translate.py``) per the Session 45 A5 sweep.

Why this file exists
--------------------
Session 41 A5 catalogued a family of silent cross-ontology comparison
bugs (API band vs kernel score vs cortex reputation, all plain ``int``
with overlapping ranges).  Session 45 A10 introduced the translator.
If the translator's anchors ever drift, these tests fail before any
comparison has a chance to go wrong at runtime.
"""

from __future__ import annotations

import importlib
import os
import sys
import unittest
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[2]
_DAEMON_DIR = _REPO_ROOT / "ai-control" / "daemon"
_CORTEX_DIR = _REPO_ROOT / "ai-control" / "cortex"


def _load_module(label: str, path: Path):
    """Load ``trust_translate.py`` from a specific directory as a fresh module.

    Necessary so both copies can coexist in ``sys.modules`` keyed by
    ``label`` without one shadowing the other.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location(label, path / "trust_translate.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {label} from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _TranslatorContract(unittest.TestCase):
    """Shared test body -- instantiated once per translator copy below."""

    tt = None  # subclasses set this to the loaded module

    # ── Round-trip for each anchor band ──

    def test_round_trip_each_anchor_band(self):
        tt = self.tt
        for band in tt.API_BAND_TO_KERNEL_FLOOR:
            score = tt.api_band_to_kernel_score(band)
            # Floor must match the canonical table.
            self.assertEqual(
                score, tt.API_BAND_TO_KERNEL_FLOOR[band],
                f"band {band} floor mismatch",
            )
            # Round-trip must land on a band whose floor equals ``score``.
            rt = tt.kernel_score_to_api_band(score)
            self.assertEqual(
                tt.API_BAND_TO_KERNEL_FLOOR[rt], score,
                f"round-trip of band {band} (score {score}) -> "
                f"band {rt} (floor {tt.API_BAND_TO_KERNEL_FLOOR[rt]})",
            )

    def test_band_anchors_match_documented_values(self):
        tt = self.tt
        self.assertEqual(tt.api_band_to_kernel_score(0), -1000)
        self.assertEqual(tt.api_band_to_kernel_score(200), 0)
        self.assertEqual(tt.api_band_to_kernel_score(400), 300)
        self.assertEqual(tt.api_band_to_kernel_score(600), 700)
        self.assertEqual(tt.api_band_to_kernel_score(900), 1000)
        self.assertEqual(tt.api_band_to_kernel_score(1000), 1000)

    def test_off_anchor_band_floors_down(self):
        tt = self.tt
        # 250 → between 200 and 300; should floor to band 200's value (0).
        self.assertEqual(tt.api_band_to_kernel_score(250), 0)
        # 650 → floors to band 600 (score 700).
        self.assertEqual(tt.api_band_to_kernel_score(650), 700)

    def test_band_clamps_out_of_range(self):
        tt = self.tt
        self.assertEqual(tt.api_band_to_kernel_score(-50), -1000)
        self.assertEqual(tt.api_band_to_kernel_score(99_999), 1000)

    # ── Kernel -> band inverse ──

    def test_kernel_score_to_band_monotonic(self):
        tt = self.tt
        prev = 0
        for score in (-1000, -500, -200, 0, 150, 300, 500, 700, 800, 900, 1000):
            band = tt.kernel_score_to_api_band(score)
            self.assertGreaterEqual(band, prev, f"non-monotonic at score {score}")
            prev = band

    def test_kernel_score_clamp(self):
        tt = self.tt
        self.assertEqual(tt.kernel_score_to_api_band(-99_999),
                         tt.kernel_score_to_api_band(tt.KERNEL_SCORE_MIN))
        self.assertEqual(tt.kernel_score_to_api_band(99_999),
                         tt.kernel_score_to_api_band(tt.KERNEL_SCORE_MAX))

    # ── Malformed input rejection ──

    def test_rejects_float_band(self):
        tt = self.tt
        with self.assertRaises(TypeError):
            tt.api_band_to_kernel_score(1.5)  # type: ignore[arg-type]

    def test_rejects_string_band(self):
        tt = self.tt
        with self.assertRaises(TypeError):
            tt.api_band_to_kernel_score("600")  # type: ignore[arg-type]

    def test_rejects_none_score(self):
        tt = self.tt
        with self.assertRaises(TypeError):
            tt.kernel_score_to_api_band(None)  # type: ignore[arg-type]

    def test_rejects_float_reputation(self):
        tt = self.tt
        with self.assertRaises(TypeError):
            tt.cortex_reputation_to_kernel_score(0.5)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            tt.is_cortex_quarantined(9.9)  # type: ignore[arg-type]

    def test_accepts_bool_as_int(self):
        # bool is an int subclass; we accept it (documented behavior).
        tt = self.tt
        self.assertEqual(
            tt.api_band_to_kernel_score(False),
            tt.api_band_to_kernel_score(0),
        )
        self.assertEqual(
            tt.api_band_to_kernel_score(True),
            tt.api_band_to_kernel_score(1),
        )

    # ── Cortex-reputation mapping ──

    def test_cortex_reputation_endpoints(self):
        tt = self.tt
        self.assertEqual(tt.cortex_reputation_to_kernel_score(0), -200)
        self.assertEqual(tt.cortex_reputation_to_kernel_score(100), 1000)

    def test_cortex_reputation_neutral(self):
        # rep=50 -> -200 + 12*50 = 400
        tt = self.tt
        self.assertEqual(tt.cortex_reputation_to_kernel_score(50), 400)

    def test_cortex_reputation_clamped(self):
        tt = self.tt
        # Above range clamps to 100 → 1000
        self.assertEqual(tt.cortex_reputation_to_kernel_score(500), 1000)
        # Below range clamps to 0 → -200
        self.assertEqual(tt.cortex_reputation_to_kernel_score(-500), -200)

    def test_cortex_reputation_monotonic(self):
        tt = self.tt
        prev = tt.KERNEL_SCORE_MIN - 1
        for rep in range(0, 101, 5):
            ker = tt.cortex_reputation_to_kernel_score(rep)
            self.assertGreaterEqual(ker, prev, f"rep {rep} regression")
            prev = ker

    # ── Quarantine flag for rep < 10 ──

    def test_quarantine_flag_below_threshold(self):
        tt = self.tt
        for rep in range(0, tt.CORTEX_QUARANTINE_THRESHOLD):
            self.assertTrue(
                tt.is_cortex_quarantined(rep),
                f"rep {rep} should be quarantined",
            )

    def test_quarantine_flag_at_and_above_threshold(self):
        tt = self.tt
        for rep in (
            tt.CORTEX_QUARANTINE_THRESHOLD,
            tt.CORTEX_QUARANTINE_THRESHOLD + 1,
            50,
            99,
            100,
        ):
            self.assertFalse(
                tt.is_cortex_quarantined(rep),
                f"rep {rep} should NOT be quarantined",
            )

    def test_quarantine_clamps_garbage(self):
        tt = self.tt
        # Negative clamps to 0 (quarantined).
        self.assertTrue(tt.is_cortex_quarantined(-100))
        # Above range clamps to 100 (not quarantined).
        self.assertFalse(tt.is_cortex_quarantined(500))

    # ── Range-constant sanity ──

    def test_range_constants(self):
        tt = self.tt
        self.assertEqual(tt.KERNEL_SCORE_MIN, -1000)
        self.assertEqual(tt.KERNEL_SCORE_MAX, 1000)
        self.assertEqual(tt.API_BAND_MIN, 0)
        self.assertEqual(tt.API_BAND_MAX, 1000)
        self.assertEqual(tt.CORTEX_REP_MIN, 0)
        self.assertEqual(tt.CORTEX_REP_MAX, 100)
        self.assertEqual(tt.CORTEX_QUARANTINE_THRESHOLD, 10)


class DaemonTrustTranslateTest(_TranslatorContract):
    """Run the contract against ``ai-control/daemon/trust_translate.py``."""

    @classmethod
    def setUpClass(cls):
        cls.tt = _load_module("daemon_trust_translate", _DAEMON_DIR)


class CortexTrustTranslateTest(_TranslatorContract):
    """Run the contract against ``ai-control/cortex/trust_translate.py``.

    Cortex runs in a separate Python process; its copy must stay in sync.
    These tests fail loudly if the two copies diverge on behavior.
    """

    @classmethod
    def setUpClass(cls):
        cls.tt = _load_module("cortex_trust_translate", _CORTEX_DIR)


class CopiesStayInSyncTest(unittest.TestCase):
    """Detect byte-drift between the two copies on every invariant."""

    @classmethod
    def setUpClass(cls):
        cls.daemon = _load_module("daemon_sync_check", _DAEMON_DIR)
        cls.cortex = _load_module("cortex_sync_check", _CORTEX_DIR)

    def test_anchor_tables_identical(self):
        self.assertEqual(
            self.daemon.API_BAND_TO_KERNEL_FLOOR,
            self.cortex.API_BAND_TO_KERNEL_FLOOR,
            "daemon and cortex copies drifted on API_BAND_TO_KERNEL_FLOOR",
        )

    def test_range_constants_identical(self):
        for name in (
            "KERNEL_SCORE_MIN", "KERNEL_SCORE_MAX",
            "API_BAND_MIN", "API_BAND_MAX",
            "CORTEX_REP_MIN", "CORTEX_REP_MAX",
            "CORTEX_QUARANTINE_THRESHOLD",
        ):
            self.assertEqual(
                getattr(self.daemon, name), getattr(self.cortex, name),
                f"{name} drifted between copies",
            )

    def test_examples_payload_identical(self):
        self.assertEqual(self.daemon.EXAMPLES, self.cortex.EXAMPLES)


# Prevent the contract base class from being picked up as its own suite.
del _TranslatorContract


if __name__ == "__main__":
    unittest.main()
