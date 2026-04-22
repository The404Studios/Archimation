"""Regression-pinning unit tests for the S82 auth + token bootstrap fixes.

Pins the two bug fixes delivered in S82+C:

1. ``ai-control/daemon/auth.py`` gained explicit ``ENDPOINT_TRUST`` entries
   for four observer/metric endpoints that previously fell through to the
   fail-secure 600 default, making them admin-only by accident (breaking
   every S75-S78 feature for normal users).

2. ``profile/airootfs/etc/skel/.bashrc`` now auto-mints a trust=400 token
   on interactive shell startup via the localhost-bootstrap exemption on
   ``POST /auth/token``, exporting it as ``AI_CONTROL_TOKEN`` so raw curl
   calls don't get ``{"error":"forbidden","reason":"missing_token"}``.

These tests lock the CURRENT correct behavior so neither regresses
silently.  They import ``auth.py`` directly via ``importlib.util``
because the parent directory (``ai-control``) contains a hyphen and is
not importable as a package.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import unittest
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[2]
_AUTH_PATH = _REPO_ROOT / "ai-control" / "daemon" / "auth.py"
_BASHRC_PATH = _REPO_ROOT / "profile" / "airootfs" / "etc" / "skel" / ".bashrc"


def _load_auth():
    """Load ``ai-control/daemon/auth.py`` as the module named ``auth_s82``."""
    name = "auth_s82_under_test"
    spec = importlib.util.spec_from_file_location(name, _AUTH_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


auth = _load_auth()


class _StubTrustObserver:
    """Minimal stand-in for ``trust_observer.TrustObserver`` in tests.

    ``check_auth`` only invokes the observer when one is passed in.
    Supplying a stub lets us pin the real-trust-score-vs-required-threshold
    comparison (``identity.trust_level`` alone isn't consulted by
    ``check_auth`` -- the comparison lives in the observer path).
    """

    def __init__(self, score: int, frozen: bool = False):
        self._score = score
        self._frozen = frozen

    def get_subject(self, subject_id: int) -> dict:
        return {"score": self._score, "frozen": self._frozen}

    def get_adaptive_threshold(self, subject_id: int, base: int) -> int:
        return base  # no adaptive offset in tests


# --------------------------------------------------------------------------
# Group 1 -- ENDPOINT_TRUST map (the S82+C primary fix)
# --------------------------------------------------------------------------


class EndpointTrustMapTests(unittest.TestCase):
    """Pins the explicit trust requirements added in S82+C."""

    def test_endpoint_trust_has_metrics_ecosystem(self) -> None:
        """/metrics/ecosystem must be 200 (aggregate counters, user-tier)."""
        self.assertEqual(auth.ENDPOINT_TRUST["/metrics/ecosystem"], 200)

    def test_endpoint_trust_has_metrics_depth(self) -> None:
        """/metrics/depth must be 200 (aggregate counters, user-tier)."""
        self.assertEqual(auth.ENDPOINT_TRUST["/metrics/depth"], 200)

    def test_endpoint_trust_has_metrics_deltas(self) -> None:
        """/metrics/deltas must be 200 (aggregate counters, user-tier)."""
        self.assertEqual(auth.ENDPOINT_TRUST["/metrics/deltas"], 200)

    def test_endpoint_trust_has_cortex_monte_carlo_rollout(self) -> None:
        """/cortex/monte_carlo/rollout is compute-heavy (300, matches /ai/query)."""
        self.assertEqual(auth.ENDPOINT_TRUST["/cortex/monte_carlo/rollout"], 300)

    def test_endpoint_trust_unknown_path_falls_to_600(self) -> None:
        """``get_required_trust('/foo/bar')`` must fall back to 600 (fail-secure)."""
        self.assertEqual(auth.get_required_trust("/foo/bar"), 600)
        self.assertEqual(
            auth.get_required_trust("/definitely/not/a/real/endpoint"), 600
        )

    def test_endpoint_trust_table_size_grew(self) -> None:
        """The table must stay at or above the S82+C baseline size (~220).

        Chosen well below the current 220 so a rename or minor refactor
        doesn't trip this, but a wholesale gutting of the table does.
        """
        self.assertGreaterEqual(len(auth.ENDPOINT_TRUST), 200)


# --------------------------------------------------------------------------
# Group 2 -- check_auth flow
# --------------------------------------------------------------------------


class CheckAuthFlowTests(unittest.TestCase):
    """Pins the allow/deny contract of ``check_auth`` for S82 endpoints."""

    def test_check_auth_missing_token_returns_forbidden(self) -> None:
        """Bare GET to a gated endpoint without a token = (False, None, 'missing_token')."""
        allowed, ident, reason = auth.check_auth(
            "/metrics/ecosystem", "GET", None, client_ip="127.0.0.1"
        )
        self.assertFalse(allowed)
        self.assertIsNone(ident)
        self.assertEqual(reason, "missing_token")

    def test_check_auth_valid_user_token_can_read_ecosystem(self) -> None:
        """A trust=200 token must be authorized for /metrics/ecosystem."""
        token = auth.create_token(subject_id=42, name="test", trust_level=200, ttl=60)
        obs = _StubTrustObserver(score=200)
        allowed, ident, reason = auth.check_auth(
            "/metrics/ecosystem", "GET", token,
            trust_observer=obs, client_ip="127.0.0.1",
        )
        self.assertTrue(allowed, f"denied with reason={reason}")
        self.assertIsNotNone(ident)
        self.assertEqual(reason, "authorized")

    def test_check_auth_valid_user_token_can_read_depth(self) -> None:
        """A trust=200 token must be authorized for /metrics/depth."""
        token = auth.create_token(subject_id=43, name="test", trust_level=200, ttl=60)
        obs = _StubTrustObserver(score=200)
        allowed, _ident, reason = auth.check_auth(
            "/metrics/depth", "GET", token,
            trust_observer=obs, client_ip="127.0.0.1",
        )
        self.assertTrue(allowed, f"denied with reason={reason}")
        self.assertEqual(reason, "authorized")

    def test_check_auth_user_token_can_compute_monte_carlo(self) -> None:
        """A trust=300 token must be authorized for /cortex/monte_carlo/rollout."""
        token = auth.create_token(subject_id=44, name="test", trust_level=300, ttl=60)
        obs = _StubTrustObserver(score=300)
        allowed, _ident, reason = auth.check_auth(
            "/cortex/monte_carlo/rollout", "POST", token,
            trust_observer=obs, client_ip="127.0.0.1",
        )
        self.assertTrue(allowed, f"denied with reason={reason}")
        self.assertEqual(reason, "authorized")

    def test_check_auth_low_trust_rejects_compute(self) -> None:
        """A trust=100 caller must be rejected by /cortex/monte_carlo/rollout (needs 300).

        Note: ``check_auth`` only compares actual score vs required when a
        trust observer is supplied -- so this test uses a stub observer
        that reports score=100, which is below the required 300.
        """
        token = auth.create_token(subject_id=45, name="test", trust_level=100, ttl=60)
        obs = _StubTrustObserver(score=100)
        allowed, _ident, reason = auth.check_auth(
            "/cortex/monte_carlo/rollout", "POST", token,
            trust_observer=obs, client_ip="127.0.0.1",
        )
        self.assertFalse(allowed)
        self.assertEqual(reason, "insufficient_trust")

    def test_check_auth_unknown_endpoint_rejects_user_token(self) -> None:
        """Even a trust=400 caller must be rejected for an unknown path (fail-secure 600).

        The default for unmapped paths is 600, and the observer path
        enforces ``actual_score < required``.
        """
        token = auth.create_token(subject_id=46, name="test", trust_level=400, ttl=60)
        obs = _StubTrustObserver(score=400)
        allowed, _ident, reason = auth.check_auth(
            "/foo/bar", "GET", token,
            trust_observer=obs, client_ip="127.0.0.1",
        )
        self.assertFalse(allowed)
        self.assertEqual(reason, "insufficient_trust")


# --------------------------------------------------------------------------
# Group 3 -- Localhost bootstrap exemption
# --------------------------------------------------------------------------


class LocalhostBootstrapTests(unittest.TestCase):
    """Pins the ``POST /auth/token`` localhost exemption (auth.py:640-643)."""

    def test_post_auth_token_exempt_for_localhost(self) -> None:
        """Local callers must get the bootstrap pass (chicken-and-egg fix)."""
        for ip in ("127.0.0.1", "::1", "localhost", "local", "unknown"):
            allowed, ident, reason = auth.check_auth(
                "/auth/token", "POST", None, client_ip=ip,
            )
            self.assertTrue(allowed, f"{ip} should bootstrap: reason={reason}")
            self.assertIsNone(ident)
            self.assertEqual(reason, "localhost_bootstrap")

    def test_post_auth_token_rejected_for_remote(self) -> None:
        """Remote callers without a token must NOT get the bootstrap pass.

        With no token and no localhost exemption, the request falls through
        to the normal ``missing_token`` denial (required=600 for
        /auth/token).
        """
        allowed, ident, reason = auth.check_auth(
            "/auth/token", "POST", None, client_ip="203.0.113.5",
        )
        self.assertFalse(allowed)
        self.assertIsNone(ident)
        self.assertEqual(reason, "missing_token")

    def test_get_auth_token_not_exempt_even_for_localhost(self) -> None:
        """Exemption is POST-only; GET /auth/token from localhost still gated."""
        allowed, _ident, reason = auth.check_auth(
            "/auth/token", "GET", None, client_ip="127.0.0.1",
        )
        self.assertFalse(allowed)
        self.assertNotEqual(reason, "localhost_bootstrap")


# --------------------------------------------------------------------------
# Group 4 -- Token creation / verify roundtrip
# --------------------------------------------------------------------------


class TokenRoundtripTests(unittest.TestCase):
    """End-to-end mint -> verify -> authorize pin for S82 token flow."""

    def test_create_token_then_check_auth_authorized(self) -> None:
        """Mint a trust=200 token, present it on /metrics/ecosystem, expect accept."""
        token = auth.create_token(subject_id=100, name="roundtrip",
                                  trust_level=200, ttl=120)
        ident = auth.verify_token(token)
        self.assertIsNotNone(ident)
        self.assertEqual(ident.trust_level, 200)
        self.assertEqual(ident.name, "roundtrip")

        obs = _StubTrustObserver(score=200)
        allowed, _ident, reason = auth.check_auth(
            "/metrics/ecosystem", "GET", token,
            trust_observer=obs, client_ip="127.0.0.1",
        )
        self.assertTrue(allowed)
        self.assertEqual(reason, "authorized")

    def test_create_token_with_trust_400_authorized_at_200_endpoints(self) -> None:
        """A trust=400 token (the level S82 bashrc mints) must pass 200 endpoints.

        This is the key scenario: the bashrc-minted token must work for the
        whole tier of S75-S78 read-only surfaces (all 200) and should even
        clear 300-tier compute endpoints.
        """
        token = auth.create_token(subject_id=101, name="bashrc-user",
                                  trust_level=400, ttl=120)
        obs = _StubTrustObserver(score=400)

        for path in ("/metrics/ecosystem", "/metrics/depth", "/metrics/deltas",
                     "/cortex/monte_carlo/rollout"):
            method = "POST" if "monte_carlo" in path else "GET"
            allowed, _ident, reason = auth.check_auth(
                path, method, token,
                trust_observer=obs, client_ip="127.0.0.1",
            )
            self.assertTrue(
                allowed,
                f"trust=400 should authorize {path}: reason={reason}",
            )


# --------------------------------------------------------------------------
# Group 5 -- bashrc token-bootstrap snippet (offline parse)
# --------------------------------------------------------------------------


class BashrcBootstrapTests(unittest.TestCase):
    """Static-analysis pins for ``profile/airootfs/etc/skel/.bashrc``.

    These are shell-script unit tests: read the file, check the shape
    of the S82+C block without actually sourcing it.  Run on Windows --
    we only invoke ``bash -n`` if a bash interpreter is available.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = _BASHRC_PATH.read_text(encoding="utf-8")

    def test_bashrc_path_exists(self) -> None:
        """The skel bashrc file must exist on disk."""
        self.assertTrue(_BASHRC_PATH.exists(),
                        f"expected {_BASHRC_PATH} to exist")

    def test_bashrc_has_s82_token_block(self) -> None:
        """The S82+C guarded ``if [ -z "${AI_CONTROL_TOKEN:-}" ]`` block must be present."""
        self.assertIn('AI_CONTROL_TOKEN', self.text)
        # Match the guard exactly -- stops someone from dropping the
        # ``-z`` check and minting a token on every shell startup.
        self.assertRegex(
            self.text,
            r'if\s*\[\s*-z\s*"\$\{AI_CONTROL_TOKEN:-\}"\s*\]',
        )

    def test_bashrc_post_payload_has_correct_shape(self) -> None:
        """The curl payload must include trust_level:400 and hit /auth/token."""
        # The block must POST to /auth/token on 127.0.0.1:8420
        self.assertIn("http://127.0.0.1:8420/auth/token", self.text)
        self.assertRegex(self.text, r"-X\s+POST")
        # Payload must request trust_level 400 (user tier, matches the
        # ``export AI_CONTROL_TOKEN`` contract).
        self.assertRegex(self.text, r'"trust_level"\s*:\s*400')
        # Must export the result for child processes
        self.assertIn('export AI_CONTROL_TOKEN=', self.text)

    def test_bashrc_has_curl_timeout_guard(self) -> None:
        """Curl call must have a short -m <seconds> timeout (don't hang shells)."""
        self.assertRegex(self.text, r'curl\s+[^|]*-m\s+\d+')

    def test_bashrc_runs_via_bash_n(self) -> None:
        """The bashrc must parse clean via ``bash -n`` (syntax check only).

        Silently skipped if no bash interpreter is on PATH (Windows hosts
        without Git Bash / WSL).  This check is the cheapest guard against
        someone breaking the script with a missing quote.
        """
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("no bash on PATH (Windows without Git Bash / WSL)")
        result = subprocess.run(
            [bash, "-n", str(_BASHRC_PATH)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(
            result.returncode, 0,
            f"bash -n failed: stdout={result.stdout!r} stderr={result.stderr!r}",
        )


if __name__ == "__main__":
    unittest.main()
