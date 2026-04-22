"""S82 cross-file CONSISTENCY tests.

These tests guard invariants that the project has broken repeatedly: paths
written by a build (PKGBUILD) but probed by scripts / banner / motd at a
DIFFERENT path; route registrations that the auth gate does not know about;
bootloader menus that drift between grub/syslinux/sd-boot; .gitignore *.d
patterns that accidentally exclude ~20 config directories.

Every test here protects an invariant SPANNING TWO OR MORE FILES. Failing
tests mean the files are inconsistent with each other, which historically
manifested as silent boot-time degradation ("unavailable" banner message,
fail-secure 600 on a registered route, etc).

Rule: stdlib only. Skip bash-based tests cleanly on Windows if bash is
absent. JSONC parsing uses a minimal strip-comments helper.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import unittest

# Project root: this file lives at tests/unit/, so root is two parents up.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _read(*parts: str) -> str:
    path = os.path.join(ROOT, *parts)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments from a JSONC source, preserving strings."""
    out = []
    i, n = 0, len(text)
    in_str = False
    quote = ""
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                in_str = False
            i += 1
            continue
        if ch in ("'", '"'):
            in_str = True
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            # Line comment: skip to newline
            j = text.find("\n", i)
            if j == -1:
                break
            i = j
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            if j == -1:
                break
            i = j + 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


class DictionaryPathConsistency(unittest.TestCase):
    """Group 1: /var/cache/ai-control/dictionary_v2.pkl.zst is ONE path.

    S82 fixed a bug where PKGBUILD installed to /var/cache/ai-control/ but
    motd + fastfetch + smoke probed /usr/share/ai-control/, resulting in
    'absent' banner messages every boot despite the artifact being present.
    """

    CANONICAL = "/var/cache/ai-control/dictionary_v2.pkl.zst"
    WRONG = "/usr/share/ai-control/dictionary_v2"

    def test_dictionary_v2_path_pkgbuild_writes_var_cache(self):
        """PKGBUILD must install dictionary_v2 to /var/cache/ai-control/."""
        pkgbuild = _read("packages", "ai-control-daemon", "PKGBUILD")
        # Find the dictionary_v2 --build target, tolerating bash line
        # continuations: `--build \\\n    "$pkgdir/var/cache/..."`
        m = re.search(
            r'dictionary_v2\.py\s+--build[\s\\]+"([^"]+)"', pkgbuild
        )
        self.assertIsNotNone(m, "dictionary_v2 --build line missing from PKGBUILD")
        install_target = m.group(1)
        self.assertIn(
            "/var/cache/ai-control/",
            install_target,
            f"PKGBUILD installs dictionary_v2 to {install_target!r} — "
            f"must contain /var/cache/ai-control/",
        )
        # Also assert the chmod 644 target matches (parallel invariant —
        # S63 pickle hardening breaks if the chmod path drifts).
        self.assertIn(
            '"$pkgdir/var/cache/ai-control/dictionary_v2.pkl.zst"', pkgbuild,
            "PKGBUILD chmod target must match the install target",
        )

    def test_dictionary_v2_path_motd_consistent(self):
        """/etc/motd must point at /var/cache/... (no /usr/share/... stale refs)."""
        motd = _read("profile", "airootfs", "etc", "motd")
        self.assertNotIn(
            self.WRONG, motd,
            "/etc/motd references /usr/share/ai-control/dictionary_v2 — "
            "PKGBUILD writes to /var/cache/, so banner lies about absence",
        )
        self.assertIn(self.CANONICAL, motd,
                      "/etc/motd must reference the canonical dict v2 path")

    def test_dictionary_v2_path_fastfetch_consistent(self):
        """fastfetch config.jsonc must probe the canonical path."""
        cfg = _read("profile", "airootfs", "etc", "fastfetch", "config.jsonc")
        self.assertNotIn(self.WRONG, cfg,
                         "fastfetch probes a stale /usr/share/... path")
        self.assertIn(self.CANONICAL, cfg,
                      "fastfetch must probe /var/cache/ai-control/dictionary_v2.pkl.zst")

    def test_dictionary_v2_path_smoke_script_consistent(self):
        """v2_smoke_run.sh must verify the canonical path."""
        smoke = _read("scripts", "v2_smoke_run.sh")
        self.assertNotIn(self.WRONG, smoke,
                         "v2_smoke_run.sh probes stale /usr/share/... path")
        self.assertIn(self.CANONICAL, smoke,
                      "v2_smoke_run.sh must verify /var/cache/ai-control/...")

    def test_dictionary_v2_path_dictionary_default_consistent(self):
        """dictionary_v2.py's _DEFAULT_PATHS must include /var/cache/..."""
        src = _read("ai-control", "daemon", "dictionary_v2.py")
        self.assertIn("_DEFAULT_PATHS", src,
                      "dictionary_v2.py must define _DEFAULT_PATHS")
        self.assertIn(
            "/var/cache/ai-control/dictionary_v2.pkl.zst", src,
            "dictionary_v2.py _DEFAULT_PATHS must include /var/cache/... "
            "so runtime load matches what PKGBUILD wrote",
        )


class EndpointTrustRouteConsistency(unittest.TestCase):
    """Group 2: every ENDPOINT_TRUST entry for metrics/cortex paths must
    be registered by a module; every S82-registered route must be in
    ENDPOINT_TRUST or fall through to fail-secure 600 (which is a bug)."""

    def _load_endpoint_trust(self) -> dict[str, int]:
        src = _read("ai-control", "daemon", "auth.py")
        start = src.index("ENDPOINT_TRUST = {")
        depth = 0
        i = start + len("ENDPOINT_TRUST = ")
        end = i
        while i < len(src):
            ch = src[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
            i += 1
        block = src[start + len("ENDPOINT_TRUST = "):end]
        result: dict[str, int] = {}
        # Extract '"/path": <int>' pairs, stripping // comments
        for raw in re.findall(r'"([^"]+)"\s*:\s*(\d+)', _strip_jsonc(block)):
            result[raw[0]] = int(raw[1])
        return result

    def test_metrics_ecosystem_in_endpoint_trust_and_library_census(self):
        """S75 Agent B library_census registers /metrics/ecosystem — auth.py
        must know about it, or every local probe gets missing_token."""
        trust = self._load_endpoint_trust()
        self.assertIn("/metrics/ecosystem", trust,
                      "auth.ENDPOINT_TRUST is missing /metrics/ecosystem")
        src = _read("ai-control", "daemon", "library_census.py")
        self.assertIn("register_with_daemon", src,
                      "library_census.py must define register_with_daemon")
        self.assertIn("/metrics/ecosystem", src,
                      "library_census.py must register route literal /metrics/ecosystem")

    def test_metrics_depth_in_endpoint_trust_and_depth_observer(self):
        """depth_observer registers /metrics/depth — auth.py must know it."""
        trust = self._load_endpoint_trust()
        self.assertIn("/metrics/depth", trust,
                      "auth.ENDPOINT_TRUST is missing /metrics/depth")
        src = _read("ai-control", "daemon", "depth_observer.py")
        self.assertIn("register_with_daemon", src)
        self.assertIn("/metrics/depth", src)

    def test_metrics_deltas_in_endpoint_trust_and_differential_observer(self):
        """differential_observer registers /metrics/deltas — auth.py must know it."""
        trust = self._load_endpoint_trust()
        self.assertIn("/metrics/deltas", trust,
                      "auth.ENDPOINT_TRUST is missing /metrics/deltas")
        src = _read("ai-control", "daemon", "differential_observer.py")
        self.assertIn("register_with_daemon", src)
        self.assertIn("/metrics/deltas", src)

    def test_cortex_monte_carlo_rollout_in_endpoint_trust_and_module(self):
        """cortex.monte_carlo registers /cortex/monte_carlo/rollout."""
        trust = self._load_endpoint_trust()
        self.assertIn("/cortex/monte_carlo/rollout", trust,
                      "auth.ENDPOINT_TRUST is missing /cortex/monte_carlo/rollout")
        src = _read("ai-control", "cortex", "monte_carlo.py")
        self.assertIn("register_with_daemon", src)
        self.assertIn("/cortex/monte_carlo/rollout", src)

    def test_no_endpoint_in_trust_without_source_route(self):
        """Every /metrics/* and /cortex/* entry in ENDPOINT_TRUST must be
        defined as a route somewhere in ai-control/. Orphans indicate the
        auth gate trusts a path that no module registers (stale entry)."""
        trust = self._load_endpoint_trust()
        prefixes = ("/metrics/", "/cortex/monte_carlo/")
        targets = [p for p in trust if p.startswith(prefixes)]
        self.assertTrue(targets, "no /metrics or /cortex targets to verify")

        # Collect all source text once from daemon + cortex.
        bundles = []
        for sub in (
            os.path.join(ROOT, "ai-control", "daemon"),
            os.path.join(ROOT, "ai-control", "cortex"),
        ):
            if not os.path.isdir(sub):
                continue
            for name in os.listdir(sub):
                if name.endswith(".py"):
                    try:
                        with open(os.path.join(sub, name), "r", encoding="utf-8") as f:
                            bundles.append(f.read())
                    except OSError:
                        pass
        combined = "\n".join(bundles)
        for path in targets:
            self.assertIn(
                path, combined,
                f"ENDPOINT_TRUST entry {path!r} has no matching route literal "
                f"in ai-control/daemon or ai-control/cortex (orphan / stale)",
            )


class BashrcShellSyntax(unittest.TestCase):
    """Group 3: /etc/skel/.bashrc sourced by every interactive shell. A
    syntax error here (S82+C introduced a token-mint block) silently breaks
    every login — bash exits the subshell but the user has no env."""

    PATH_REL = os.path.join("profile", "airootfs", "etc", "skel", ".bashrc")

    def test_bashrc_bash_n_clean(self):
        """bash -n on .bashrc must exit 0 (skipped on Windows without bash)."""
        bash = shutil.which("bash")
        if bash is None or sys.platform.startswith("win"):
            self.skipTest("bash not available on this host")
        abs_path = os.path.join(ROOT, self.PATH_REL)
        result = subprocess.run(
            [bash, "-n", abs_path],
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(
            result.returncode, 0,
            f"bash -n {self.PATH_REL} failed: {result.stderr}",
        )

    def test_bashrc_token_block_present(self):
        """S82+C mint block must exist — guards against an accidental revert."""
        src = _read(self.PATH_REL)
        self.assertIn(
            'if [ -z "${AI_CONTROL_TOKEN:-}" ]', src,
            "bashrc missing the S82+C AI_CONTROL_TOKEN mint guard",
        )

    def test_bashrc_curl_targets_localhost_8420(self):
        """The curl line must POST to http://127.0.0.1:8420/auth/token —
        if someone swaps 127.0.0.1 for 0.0.0.0 or a wrong port, every
        login shell silently fails to mint a token."""
        src = _read(self.PATH_REL)
        self.assertIn(
            "http://127.0.0.1:8420/auth/token", src,
            "bashrc curl must target http://127.0.0.1:8420/auth/token",
        )


class FastfetchConfigValidity(unittest.TestCase):
    """Group 4: config.jsonc must be parseable JSONC. Fastfetch silently
    falls back to default output if the config has a syntax error; the
    user gets no warning."""

    BASELINE_MODULE_COUNT = 22  # current length of "modules" list

    def _load(self) -> dict:
        raw = _read("profile", "airootfs", "etc", "fastfetch", "config.jsonc")
        return json.loads(_strip_jsonc(raw))

    def test_fastfetch_config_is_valid_json(self):
        """config.jsonc (comments stripped) must parse as JSON."""
        try:
            data = self._load()
        except json.JSONDecodeError as e:
            self.fail(f"fastfetch config.jsonc invalid JSON: {e}")
        self.assertIn("modules", data)
        self.assertIsInstance(data["modules"], list)

    def test_fastfetch_modules_count_unchanged(self):
        """Guard against accidental module additions / deletions — if this
        fires, update BASELINE_MODULE_COUNT intentionally."""
        data = self._load()
        self.assertEqual(
            len(data["modules"]), self.BASELINE_MODULE_COUNT,
            f"fastfetch modules count drifted from baseline "
            f"{self.BASELINE_MODULE_COUNT} — update intentionally if you "
            f"added/removed a module",
        )


class BootloaderMenuConsistency(unittest.TestCase):
    """Group 5: GRUB + syslinux + sd-boot must offer the same key entries.
    Users who boot via BIOS (syslinux) vs UEFI (grub/sd-boot) see different
    menus if we drift; the 'pick Safe Mode if default crashes' instruction
    from the motd becomes a lie on one of the three paths."""

    def _grub(self) -> str:
        return _read("profile", "grub", "grub.cfg")

    def _syslinux(self) -> str:
        return _read("profile", "syslinux", "syslinux.cfg")

    def _efiboot_entries(self) -> str:
        base = os.path.join(ROOT, "profile", "efiboot", "loader", "entries")
        parts = []
        for name in sorted(os.listdir(base)):
            if name.endswith(".conf"):
                with open(os.path.join(base, name), "r", encoding="utf-8") as f:
                    parts.append(f.read())
        return "\n".join(parts)

    def _loopback(self) -> str:
        return _read("profile", "grub", "loopback.cfg")

    def test_default_entry_present_in_all_three_bootloaders(self):
        """'try this first' default boot entry in grub + syslinux + sd-boot."""
        self.assertIn("try this first", self._grub())
        self.assertIn("try this first", self._syslinux())
        self.assertIn("try this first", self._efiboot_entries())

    def test_safe_mode_entry_present_in_all_three_bootloaders(self):
        """Safe Mode (nomodeset) entry — required on all paths per motd."""
        self.assertIn("Safe Mode", self._grub())
        self.assertIn("Safe Mode", self._syslinux())
        self.assertIn("Safe Mode", self._efiboot_entries())

    def test_text_console_entry_present_in_all_three_bootloaders(self):
        """Text Console (no X) entry — required on all paths per motd."""
        self.assertIn("Text Console", self._grub())
        self.assertIn("Text Console", self._syslinux())
        self.assertIn("Text Console", self._efiboot_entries())

    def test_nvidia_entry_present_in_all_three_bootloaders(self):
        """NVIDIA (nvidia_drm KMS) explicit entry — required so users with
        NVIDIA hardware have a discoverable entry in every bootloader UI."""
        self.assertIn("NVIDIA", self._grub())
        self.assertIn("NVIDIA", self._syslinux())
        self.assertIn("NVIDIA", self._efiboot_entries())

    def test_loopback_cfg_has_default_entry(self):
        """Chainloaded path (loopback.cfg) also needs the default entry, or
        users who boot the ISO via another OS's GRUB hit a dead menu."""
        src = self._loopback()
        self.assertIn("AI Arch Linux", src)
        self.assertIn("From ISO", src)


class GitignoreDotDRuleSanity(unittest.TestCase):
    """Group 6: S81.5 found that the `*.d` pattern accidentally excluded
    ~20 config directories (xorg.conf.d, modprobe.d, etc). S82 added
    `!*.d/` + per-directory re-includes. These tests guard the re-includes."""

    def _gitignore(self) -> str:
        return _read(".gitignore")

    def test_gitignore_xorg_conf_d_not_ignored(self):
        """`!*.d/` re-include must be present AND xorg.conf.d must have a
        per-dir re-include (otherwise its files get excluded)."""
        gi = self._gitignore()
        self.assertIn("!*.d/", gi,
                      ".gitignore must re-include *.d/ directories")
        self.assertIn("!xorg.conf.d/**", gi,
                      ".gitignore must re-include xorg.conf.d files")

    def test_gitignore_modprobe_d_re_included(self):
        """modprobe.d per-dir re-include required."""
        self.assertIn("!modprobe.d/**", self._gitignore())

    def test_gitignore_sysctl_d_re_included(self):
        """sysctl.d per-dir re-include required."""
        self.assertIn("!sysctl.d/**", self._gitignore())

    def test_gitignore_pacman_d_re_included(self):
        """pacman.d per-dir re-include required."""
        self.assertIn("!pacman.d/**", self._gitignore())


class TrustDkmsPathConsistency(unittest.TestCase):
    """Group 7: the firstboot service's ConditionPathExists must match the
    path that trust-dkms PKGBUILD actually installs. If pkgver bumps and
    the service isn't updated, ConditionPathExists fails silently and
    trust.ko never builds on first boot."""

    def test_dkms_firstboot_path_matches_trust_dkms_install_path(self):
        """Firstboot service expects /usr/src/trust-<ver>/dkms.conf — the
        version in the path must match trust-dkms PKGBUILD pkgver."""
        pkgbuild = _read("packages", "trust-dkms", "PKGBUILD")
        m = re.search(r"^pkgver=([^\s#]+)", pkgbuild, re.MULTILINE)
        self.assertIsNotNone(m, "trust-dkms PKGBUILD missing pkgver")
        pkgver = m.group(1).strip()

        # The PKGBUILD installs to ${pkgdir}/usr/src/${_modname}-${pkgver}
        # with _modname=trust, so the on-disk path is /usr/src/trust-<ver>/
        expected_prefix = f"/usr/src/trust-{pkgver}/"

        svc = _read("profile", "airootfs", "etc", "systemd", "system",
                    "archimation-trust-dkms-firstboot.service")
        m2 = re.search(r"ConditionPathExists=(\S+)", svc)
        self.assertIsNotNone(m2,
                             "firstboot service missing ConditionPathExists")
        cond_path = m2.group(1)
        self.assertTrue(
            cond_path.startswith(expected_prefix),
            f"ConditionPathExists={cond_path} does not start with "
            f"{expected_prefix} — trust-dkms pkgver bumped without "
            f"updating the firstboot service path, module will never "
            f"build on first boot",
        )


if __name__ == "__main__":
    unittest.main()
