"""Boundary tests for ``ai-control/daemon/software_catalog.py``.

S79 Test Agent 3 -- URL resolution edges in S78 Dev F catalog.

Boundaries probed:
  * resolve("git") -- pinned alias returns git-for-windows entry
  * resolve("nonexistent") -- returns None (not KeyError)
  * resolve("") / resolve(None) -- returns None
  * All catalog keys resolve to http(s) URL (regression for Dev F fix)
  * All key aliases round-trip (alias -> same entry)
  * suggest() empty / unknown

Not gated. Must complete <5s.
"""

from __future__ import annotations

import importlib
import re
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DAEMON_DIR = _REPO_ROOT / "ai-control" / "daemon"

if str(_DAEMON_DIR) not in sys.path:
    sys.path.insert(0, str(_DAEMON_DIR))


def _load():
    sys.modules.pop("software_catalog", None)
    return importlib.import_module("software_catalog")


_URL_RE = re.compile(r"^https?://[^\s]+$")


class ResolveBoundaries(unittest.TestCase):
    """resolve() edge cases."""

    def setUp(self) -> None:
        self.mod = _load()

    def test_git_alias_resolves(self) -> None:
        """resolve('git') -> git-for-windows entry (S78 Dev F pinned URL)."""
        r = self.mod.resolve("git")
        self.assertIsNotNone(r)
        self.assertEqual(r["key"], "git-for-windows")
        # The S78 Dev F fix pinned to an explicit /download/<tag>/ URL.
        self.assertIn("/download/", r["url"])

    def test_nonexistent_returns_none(self) -> None:
        """resolve('nonexistent-foo') -> None (NOT KeyError)."""
        self.assertIsNone(self.mod.resolve("nonexistent-foo"))

    def test_empty_string_returns_none(self) -> None:
        """resolve('') -> None (early-return in source line 295)."""
        self.assertIsNone(self.mod.resolve(""))

    def test_none_input_returns_none(self) -> None:
        """resolve(None) -> None (falsy early-return)."""
        self.assertIsNone(self.mod.resolve(None))  # type: ignore[arg-type]

    def test_whitespace_only_returns_none(self) -> None:
        """resolve('   ') -> None (normalized to empty string, no match).

        Documented: `_normalize("   ")` collapses to `""`; no catalog key
        matches `""` so resolve returns None."""
        self.assertIsNone(self.mod.resolve("   "))

    def test_case_insensitive_match(self) -> None:
        """resolve('GIT') -> git-for-windows (case insensitive)."""
        r = self.mod.resolve("GIT")
        self.assertIsNotNone(r)
        self.assertEqual(r["key"], "git-for-windows")

    def test_extra_whitespace_tolerated(self) -> None:
        """resolve('  git  ') -> git-for-windows (whitespace collapsed)."""
        r = self.mod.resolve("  git  ")
        self.assertIsNotNone(r)
        self.assertEqual(r["key"], "git-for-windows")


class CatalogUrlRegressionBoundaries(unittest.TestCase):
    """Every catalog entry URL is a valid HTTP/HTTPS URL (S78 Dev F fix)."""

    def setUp(self) -> None:
        self.mod = _load()

    def test_every_entry_has_http_url(self) -> None:
        """Regression for S78 Dev F: every CATALOG URL matches http(s) scheme."""
        for key, entry in self.mod.CATALOG.items():
            with self.subTest(key=key):
                url = entry.get("url", "")
                self.assertTrue(
                    bool(_URL_RE.match(url)),
                    f"{key} URL does not match http/https pattern: {url!r}",
                )

    def test_every_entry_has_required_keys(self) -> None:
        """Every CATALOG entry has 'names', 'url', 'installer_type',
        'silent_args', 'category', 'size_mb'."""
        required = {
            "names", "url", "installer_type", "silent_args", "category",
            "size_mb",
        }
        for key, entry in self.mod.CATALOG.items():
            with self.subTest(key=key):
                self.assertTrue(
                    required.issubset(set(entry.keys())),
                    f"{key} missing keys: {required - set(entry.keys())}",
                )

    def test_every_key_resolvable(self) -> None:
        """resolve(key) round-trips for every catalog key."""
        for key in self.mod.CATALOG.keys():
            with self.subTest(key=key):
                r = self.mod.resolve(key)
                self.assertIsNotNone(r)
                self.assertEqual(r["key"], key)

    def test_every_alias_resolvable(self) -> None:
        """resolve(alias) -> same entry key as the alias points to."""
        for key, entry in self.mod.CATALOG.items():
            for alias in entry.get("names", []):
                with self.subTest(key=key, alias=alias):
                    r = self.mod.resolve(alias)
                    self.assertIsNotNone(r)
                    self.assertEqual(r["key"], key)


class SuggestBoundaries(unittest.TestCase):
    """suggest() empty / unknown / partial matches."""

    def setUp(self) -> None:
        self.mod = _load()

    def test_suggest_empty_returns_empty(self) -> None:
        """suggest('') -> []."""
        self.assertEqual(self.mod.suggest(""), [])

    def test_suggest_unknown_returns_empty(self) -> None:
        """suggest('xyzzyplover123') -> [] (no catalog entry contains it)."""
        self.assertEqual(self.mod.suggest("xyzzyplover123"), [])

    def test_suggest_limit_zero_returns_empty(self) -> None:
        """suggest('git', limit=0) -> empty slice."""
        self.assertEqual(self.mod.suggest("git", limit=0), [])

    def test_suggest_partial_match(self) -> None:
        """suggest('visual') -> visual-studio-community in top results."""
        hits = self.mod.suggest("visual")
        self.assertIn("visual-studio-community", hits)


class ListKeysBoundary(unittest.TestCase):
    """list_keys() returns non-empty stable list."""

    def setUp(self) -> None:
        self.mod = _load()

    def test_list_keys_non_empty(self) -> None:
        """Catalog has entries."""
        keys = self.mod.list_keys()
        self.assertGreater(len(keys), 0)
        # Sanity: well-known entry present.
        self.assertIn("git-for-windows", keys)


if __name__ == "__main__":
    unittest.main()
