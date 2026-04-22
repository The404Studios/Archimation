"""Regression tests for S82 systemd unit changes.

S82 removed silent-skip ``ConditionPathExists=`` gates from seven critical-path
units (five profile units + pe-objectd and scm-daemon in the windows-services
PKGBUILD), added an ``ExecStartPre=`` self-guard to ai-low-ram-services,
introduced a new ``archimation-trust-dkms-firstboot.service`` to build trust.ko
at first boot on real hardware, capped ``TimeoutStopSec`` on
``plymouth-quit-wait`` to 10s, and deleted two lightdm drop-ins (s80/s81) that
caused brick incidents.

Each test in this module pins one of those changes so a silent revert fails
CI.  All parsing is stdlib-only (plain-text line scan) so it runs without a
live systemd.  The PKGBUILD is read as a raw heredoc and the
``[Service]``/``[Unit]`` blocks are sliced out before the Condition checks, so
shell helpers in the PKGBUILD body never confuse the parser.
"""

from __future__ import annotations

import os
import re
import unittest

# Repo root resolves independent of where pytest / unittest is invoked from.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))

ETC_SYSTEMD = os.path.join(REPO_ROOT, "profile", "airootfs", "etc", "systemd", "system")
LIB_SYSTEMD = os.path.join(REPO_ROOT, "profile", "airootfs", "usr", "lib", "systemd", "system")
PKGBUILD_WINSVC = os.path.join(REPO_ROOT, "packages", "windows-services", "PKGBUILD")
SETUP_SERVICES = os.path.join(REPO_ROOT, "profile", "airootfs", "root", "setup-services.sh")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def read_unit(path):
    """Return the text content of a unit file, stripped of CR."""
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read().replace("\r\n", "\n")


def assert_no_condition_path_exists(testcase, unit_text, unit_label):
    """Fail if any uncommented ``ConditionPathExists=`` survives in *unit_text*.

    The new trust-dkms-firstboot unit legitimately carries a
    ``ConditionPathExists=/usr/src/trust-0.1.0/dkms.conf`` gate (that one is
    intentional: skip when the DKMS source is absent).  We therefore exempt
    only that specific unit at the call site — the helper itself is strict.
    """
    for lineno, raw in enumerate(unit_text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("ConditionPathExists="):
            testcase.fail(
                "{label}:{lineno}: unexpected ConditionPathExists= (S82 removed "
                "silent-skip Conditions from critical-path units); line was: {line!r}".format(
                    label=unit_label, lineno=lineno, line=raw
                )
            )


def extract_pkgbuild_unit_block(pkgbuild_text, unit_filename):
    """Extract the heredoc body for a given unit file written by the PKGBUILD.

    The PKGBUILD uses the pattern::

        install -Dm644 /dev/stdin "$pkgdir/usr/lib/systemd/system/NAME" <<'EOF'
        ...unit body...
        EOF

    We locate the ``install`` line, identify its closing delimiter (EOF or
    SERVICE), and return everything in between.
    """
    pattern = re.compile(
        r'install\s+-Dm644\s+/dev/stdin\s+"\$pkgdir/usr/lib/systemd/system/'
        + re.escape(unit_filename)
        + r'"\s+<<\'(?P<delim>[A-Z]+)\'\n(?P<body>.*?)\n(?P=delim)\n',
        re.DOTALL,
    )
    match = pattern.search(pkgbuild_text)
    if match is None:
        raise AssertionError(
            "Could not locate heredoc for {u} in {p}".format(u=unit_filename, p=PKGBUILD_WINSVC)
        )
    return match.group("body")


# ---------------------------------------------------------------------------
# Group 1: Condition removals (seven units)
# ---------------------------------------------------------------------------

class ConditionRemovalTests(unittest.TestCase):
    """S82 removed ConditionPathExists= from seven critical-path units.

    The lightdm drop-in incident taught us that a failed Condition yields a
    *silent* skip with no journal error — impossible to diagnose.  Keeping
    these units Condition-free ensures ExecStart fails loudly instead.
    """

    def test_ai_driver_loader_no_condition_path_exists(self):
        """ai-driver-loader.service must not regress to silent-skip Condition."""
        path = os.path.join(ETC_SYSTEMD, "ai-driver-loader.service")
        assert_no_condition_path_exists(self, read_unit(path), "ai-driver-loader.service")

    def test_ai_game_mode_no_condition_path_exists(self):
        """ai-game-mode.service must not regress to silent-skip Condition."""
        path = os.path.join(ETC_SYSTEMD, "ai-game-mode.service")
        assert_no_condition_path_exists(self, read_unit(path), "ai-game-mode.service")

    def test_ai_power_no_condition_path_exists(self):
        """ai-power.service must not regress to silent-skip Condition."""
        path = os.path.join(ETC_SYSTEMD, "ai-power.service")
        assert_no_condition_path_exists(self, read_unit(path), "ai-power.service")

    def test_ai_low_ram_services_no_condition_path_exists(self):
        """ai-low-ram-services.service must rely on ExecStartPre self-guard, not Condition."""
        path = os.path.join(LIB_SYSTEMD, "ai-low-ram-services.service")
        assert_no_condition_path_exists(self, read_unit(path), "ai-low-ram-services.service")

    def test_coherence_no_condition_path_exists(self):
        """coherence.service must not regress (it runs Before=lightdm; silent skip = catastrophic)."""
        path = os.path.join(ETC_SYSTEMD, "coherence.service")
        assert_no_condition_path_exists(self, read_unit(path), "coherence.service")

    def test_pe_objectd_no_condition_path_exists(self):
        """pe-objectd heredoc in windows-services PKGBUILD must be Condition-free."""
        body = extract_pkgbuild_unit_block(read_unit(PKGBUILD_WINSVC), "pe-objectd.service")
        assert_no_condition_path_exists(self, body, "PKGBUILD:pe-objectd.service")

    def test_scm_daemon_no_condition_path_exists(self):
        """scm-daemon heredoc in windows-services PKGBUILD must be Condition-free."""
        body = extract_pkgbuild_unit_block(read_unit(PKGBUILD_WINSVC), "scm-daemon.service")
        assert_no_condition_path_exists(self, body, "PKGBUILD:scm-daemon.service")


# ---------------------------------------------------------------------------
# Group 2: ai-low-ram-services ExecStartPre replacement
# ---------------------------------------------------------------------------

class AiLowRamExecStartPreTests(unittest.TestCase):
    """S82 replaced the Condition with an ExecStartPre self-guard.

    The self-guard logs to the journal when /run/ai-arch-hw-profile is
    missing, then exits 0 — so the SKIP is visible rather than silent.
    """

    def setUp(self):
        self.text = read_unit(os.path.join(LIB_SYSTEMD, "ai-low-ram-services.service"))

    def test_ai_low_ram_services_has_exec_start_pre(self):
        """ExecStartPre must carry the /run/ai-arch-hw-profile self-guard pattern."""
        self.assertRegex(
            self.text,
            r"ExecStartPre=/bin/sh\s+-c\s+'\[\s*-f\s+/run/ai-arch-hw-profile\s*\]",
            msg="ExecStartPre self-guard for /run/ai-arch-hw-profile is missing — "
            "S82 replaced ConditionPathExists= with this pattern so a missing "
            "hw-profile is visible in the journal rather than silently skipped.",
        )

    def test_ai_low_ram_services_success_exit_status(self):
        """SuccessExitStatus=0 must be present so the no-op exit is not flagged as failure."""
        self.assertRegex(
            self.text,
            r"(?m)^\s*SuccessExitStatus=0\s*$",
            msg="SuccessExitStatus=0 missing — the self-guard exits 0 on skip, "
            "which systemd must treat as success.",
        )


# ---------------------------------------------------------------------------
# Group 3: NEW archimation-trust-dkms-firstboot.service
# ---------------------------------------------------------------------------

class TrustDkmsFirstbootTests(unittest.TestCase):
    """S82 introduced archimation-trust-dkms-firstboot.service to build trust.ko
    on first real-hardware boot, fixing the "Trust kernel module not loaded"
    symptom where the pacstrap-chroot build ran against the wrong kernel."""

    UNIT_PATH = os.path.join(ETC_SYSTEMD, "archimation-trust-dkms-firstboot.service")

    def setUp(self):
        if os.path.exists(self.UNIT_PATH):
            self.text = read_unit(self.UNIT_PATH)
        else:
            self.text = ""

    def test_trust_dkms_firstboot_exists(self):
        """Unit file must exist at profile/.../archimation-trust-dkms-firstboot.service."""
        self.assertTrue(
            os.path.isfile(self.UNIT_PATH),
            "archimation-trust-dkms-firstboot.service missing from profile — "
            "without it, trust.ko is never built on first boot of a real-hardware install.",
        )

    def test_trust_dkms_firstboot_runs_dkms_autoinstall(self):
        """ExecStart must invoke `dkms autoinstall` for the running kernel."""
        self.assertRegex(
            self.text,
            r"ExecStart=.*dkms\s+autoinstall",
            msg="ExecStart does not call `dkms autoinstall` — this is the one "
            "command that builds trust + pe_compat for the running kernel.",
        )

    def test_trust_dkms_firstboot_has_exec_condition_skip(self):
        """ExecCondition must short-circuit when trust.ko already lives in extra/."""
        self.assertRegex(
            self.text,
            r"ExecCondition=.*trust\.ko",
            msg="ExecCondition check for /usr/lib/modules/.../extra/trust.ko is "
            "missing — without it, the unit rebuilds on every boot instead of "
            "being idempotent.",
        )
        self.assertIn(
            "/usr/lib/modules/",
            self.text,
            "ExecCondition should reference /usr/lib/modules/$(uname -r)/extra/.",
        )

    def test_trust_dkms_firstboot_modprobes_after(self):
        """ExecStartPost must modprobe trust so the module is live without a reboot."""
        self.assertRegex(
            self.text,
            r"ExecStartPost=.*modprobe\s+trust",
            msg="ExecStartPost=modprobe trust missing — built module would sit "
            "on disk but never load until next boot.",
        )

    def test_trust_dkms_firstboot_oneshot_remain_after_exit(self):
        """Must be Type=oneshot + RemainAfterExit=yes for correct idempotency."""
        self.assertRegex(self.text, r"(?m)^\s*Type=oneshot\s*$", msg="Type=oneshot expected.")
        self.assertRegex(
            self.text,
            r"(?m)^\s*RemainAfterExit=yes\s*$",
            msg="RemainAfterExit=yes expected so subsequent boots see the unit "
            "as active and the ExecCondition skip is honoured.",
        )

    def test_trust_dkms_firstboot_ordering(self):
        """Before= must list ai-control.service and ai-cortex.service."""
        self.assertRegex(
            self.text,
            r"Before=.*\bai-control\.service\b",
            msg="Before=ai-control.service is the whole point of the ordering — "
            "daemon must start with /dev/trust already registered.",
        )
        self.assertRegex(
            self.text,
            r"Before=.*\bai-cortex\.service\b",
            msg="Before=ai-cortex.service missing — cortex reads /sys/kernel/trust "
            "at startup and would see the absent module.",
        )

    def test_trust_dkms_firstboot_wantedby_multi_user(self):
        """[Install] must WantedBy=multi-user.target so systemctl enable works."""
        self.assertRegex(
            self.text,
            r"(?m)^\s*WantedBy=multi-user\.target\s*$",
            msg="WantedBy=multi-user.target is required for setup-services.sh to "
            "wire the unit into the live ISO / installed systems.",
        )

    def test_trust_dkms_firstboot_enabled_in_setup_services(self):
        """setup-services.sh must create the multi-user.target.wants symlink."""
        script = read_unit(SETUP_SERVICES)
        self.assertIn(
            "archimation-trust-dkms-firstboot.service",
            script,
            "setup-services.sh does not mention archimation-trust-dkms-firstboot.service "
            "— without the symlink into multi-user.target.wants the unit is installed "
            "but never runs.",
        )
        # Stronger: the enable block must actually create a symlink into WANTS_DIR.
        self.assertRegex(
            script,
            r"ln\s+-sf\s+/etc/systemd/system/archimation-trust-dkms-firstboot\.service",
            msg="setup-services.sh is missing the `ln -sf` line that enables "
            "archimation-trust-dkms-firstboot.service.",
        )


# ---------------------------------------------------------------------------
# Group 4: plymouth-quit-wait timeout cap
# ---------------------------------------------------------------------------

class PlymouthQuitWaitTimeoutTests(unittest.TestCase):
    """S82 capped TimeoutStopSec at 10s (previously 15s) on
    plymouth-quit-wait.service.d/timeout.conf to keep lightdm unblocked."""

    def setUp(self):
        self.text = read_unit(
            os.path.join(
                ETC_SYSTEMD, "plymouth-quit-wait.service.d", "timeout.conf"
            )
        )

    def test_plymouth_quit_wait_timeout_stop_capped(self):
        """TimeoutStopSec must be 10 — force-kill plymouthd if it refuses to quit."""
        self.assertRegex(
            self.text,
            r"(?m)^\s*TimeoutStopSec=10\s*$",
            msg="TimeoutStopSec is not 10 — S82 capped this at 10s to prevent "
            "a stuck plymouth from starving lightdm.service boot.",
        )

    def test_plymouth_quit_wait_timeout_start_capped(self):
        """TimeoutStartSec must be 15 — bounded handoff wait."""
        self.assertRegex(
            self.text,
            r"(?m)^\s*TimeoutStartSec=15\s*$",
            msg="TimeoutStartSec is not 15 — S82 picked 15s as the bounded "
            "splash-handoff wait so headless/fbcon boots don't hang.",
        )


# ---------------------------------------------------------------------------
# Group 5: removed S80/S81 lightdm drop-ins (brick cause)
# ---------------------------------------------------------------------------

class LightdmDropinRemovalTests(unittest.TestCase):
    """S80/S81 shipped lightdm drop-ins (s80-preflight.conf and s81-xorg-safety.conf)
    that silently skipped when their ConditionPathExists= failed — bricking the
    graphical session.  S82 removed both files; these tests assert they stay gone."""

    LIGHTDM_DROPIN_DIR = os.path.join(ETC_SYSTEMD, "lightdm.service.d")

    def test_no_s80_preflight_lightdm_dropin(self):
        """lightdm.service.d/s80-preflight.conf must not exist."""
        path = os.path.join(self.LIGHTDM_DROPIN_DIR, "s80-preflight.conf")
        self.assertFalse(
            os.path.exists(path),
            "s80-preflight.conf has reappeared at {p} — this drop-in's silent "
            "Condition skip was the original brick cause that motivated S82. "
            "If you genuinely need a preflight, make it ExecStartPre-based.".format(p=path),
        )

    def test_no_s81_xorg_safety_lightdm_dropin(self):
        """lightdm.service.d/s81-xorg-safety.conf must not exist."""
        path = os.path.join(self.LIGHTDM_DROPIN_DIR, "s81-xorg-safety.conf")
        self.assertFalse(
            os.path.exists(path),
            "s81-xorg-safety.conf has reappeared at {p} — same brick class "
            "as the S80 drop-in.".format(p=path),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
