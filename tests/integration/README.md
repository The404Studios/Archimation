# ai-control-daemon integration tests

These tests boot the real daemon in a subprocess against a temp state
directory and hit its HTTP surface. Nothing is mocked.

## Dependencies

```
python -m pip install pytest requests
```

The daemon itself needs: `python-fastapi`, `uvicorn`, `python-starlette`,
`python-pydantic`, `python-psutil`, `python-evdev`. On WSL/Arch:

```
pacman -S python-fastapi uvicorn python-starlette python-pydantic \
          python-psutil python-evdev
```

Tests set `LLM_DISABLED=1` in the subprocess env so `llama-cpp-python`
is not required.

## Running

From the repo root:

```
python -m pytest tests/integration -v
```

Or a single test:

```
python -m pytest tests/integration/test_auth.py::test_low_trust_blocked_on_system_command -v
```

## What each file covers

| File | Purpose |
|---|---|
| `conftest.py` | Spins up daemon on a random free port with a temp state/log dir, mints admin + low-trust tokens, tears down on session exit. |
| `test_auth.py` | Session 41 regression: trust=0 token cannot hit trust-600 endpoints; tokenless cannot either. |
| `test_emergency.py` | `/var/lib/ai-control/emergency.flag` behavior (current daemon code does NOT consult it for `/system/kill` — that test is `xfail` until the gap closes). |
| `test_ai_decide.py` | `/ai/decide` tier-3 envelope (route does not exist yet — `xfail` to pin the gap). |
| `test_trust_level.py` | Walks a sample of `ENDPOINT_TRUST` mutating routes: token below band must get 401/403; admin token must not be auth-rejected. |

## Expected xfails

1. `test_emergency.py::test_emergency_blocks_kill` — daemon/system.py's
   `kill_process()` does not check `EMERGENCY_FILE`. Flips to passing once
   the daemon shares the latch with the cortex.
2. `test_ai_decide.py::test_ai_decide_returns_verdict_envelope` — no such
   route yet. Flips to passing once a tier-3 decision endpoint lands.

## Known skips

If `/usr/lib/ai-control-daemon/main.py` is missing AND the in-repo
`ai-control/daemon/main.py` is missing, `conftest.py::daemon` skips the
whole suite (can't boot anything).

If port-allocation fails or the daemon crashes during boot, the fixture
emits the last 4 KB of stdout/stderr and skips.

## Cleanup

The session-scope fixture writes state into a `tempfile.mkdtemp()`
directory and runs `shutil.rmtree` on teardown. Daemon process receives
`SIGTERM` with a 10-second grace before `SIGKILL`. No zombie risk.

## Caveats

- Tests require root on systems where the daemon config writes to
  `/var/log/ai-control-daemon/` or binds privileged ports. The conftest
  picks a random ephemeral port (>1024) and redirects logs to the temp
  dir, so most tests run as a normal user.
- `/dev/trust` ioctls degrade gracefully if the device is absent; tests
  do not depend on the kernel module being loaded.
- `test_emergency.py` needs write access to `/var/lib/ai-control/`. If
  that fails (EACCES), the emergency-set tests are skipped, not failed.

## Desktop-integration tests

`test_contusion_live.py` is a **real-desktop** battery for the Contusion
engine. The existing `test_contusion.py` validates the HTTP API contract
— shape, auth, field aliasing — but cannot verify that a "turn up the
volume" phrase actually raises the volume, because the pytest harness
(and the headless QEMU smoke suite) have no audio sink, no backlight, no
compositor. `test_contusion_live.py` closes that gap: every test captures
a BEFORE snapshot of the relevant system state, POSTs a Contusion
phrase, and asserts the AFTER snapshot changed in the expected
direction.

### When it runs

The module-level `pytestmark` skips the entire file if neither `DISPLAY`
nor `WAYLAND_DISPLAY` is set, so it is a no-op in headless CI. Each
individual test additionally skips if the tool it needs (`wpctl`,
`brightnessctl`, `wmctrl`, `xdotool`, `xclip`, `scrot`, `xprop`) is not
installed, or if the relevant hardware does not exist (e.g. no backlight
device on a desktop box — brightness tests skip).

### Requirements

On the test box (normally the installed Arch desktop):

```
pacman -S wmctrl xdotool brightnessctl wireplumber xclip scrot
          xorg-xprop xterm curl
```

The daemon must be running (`systemctl start ai-control`) and reachable
on `127.0.0.1:8420`. Override via:

```
CONTUSION_HOST=127.0.0.1 CONTUSION_PORT=8420 pytest tests/integration/test_contusion_live.py -v
```

### What it verifies

| Test | BEFORE/AFTER source | Assertion |
|---|---|---|
| `test_audio_volume_up` | `wpctl get-volume @DEFAULT_AUDIO_SINK@` | after > before |
| `test_audio_volume_down` | same | after < before |
| `test_audio_mute_toggle` | `wpctl get-volume` MUTED flag | unmuted -> muted |
| `test_brightness_up` | `brightnessctl get` | after > before |
| `test_brightness_down` | same | after < before |
| `test_workspace_switch` | `wmctrl -d` '*' row | workspace id changes |
| `test_window_maximize` | `xprop _NET_WM_STATE` on active window | gains `_NET_WM_STATE_MAXIMIZED_*` |
| `test_window_minimize` | `xdotool search --onlyvisible` count | after < before or `HIDDEN` atom |
| `test_screenshot` | `.png` count under `~/Pictures` | count rose or fresh mtime |
| `test_clipboard_roundtrip` | `xclip -selection clipboard -out` | contains unique token |

The window tests spawn a disposable `xterm` / `xmessage` / `xeyes`
instance titled `ctn-diag-test` so they never touch the operator's real
windows.

### Explicitly skipped

Power actions (`lock_screen`, `suspend`, `reboot`, `shutdown`) are
destructive for whoever is running the suite and are not exercised. Media
playback (`play_pause`, `next_track`) depends on a `playerctl`-compatible
player already running with loaded media; too brittle to run headlessly.

### Manual / operator tool

For the same battery as a one-shot diagnostic script (no pytest
required), use `scripts/contusion-desktop-diag.sh`. It mints tokens via
`/auth/token`, runs the same checks, prints a pass/fail/skip summary
table, and restores original volume + brightness in a trap. Run it as
the `arch` user inside the installed desktop session:

```
./scripts/contusion-desktop-diag.sh --host 127.0.0.1 --port 8420
```

### Restoration / idempotency

Both the script and the pytest fixtures capture the original volume,
mute state, and brightness at setup and restore them on teardown. Tests
that switch workspaces restore the original workspace. The test window
is killed in the fixture finaliser. Re-running the suite does not drift
system state.

## Desktop E2E tests

`test_desktop_e2e.py` + `scripts/test-desktop-e2e.sh` validate the full
user journey that no existing test covers end-to-end:

    boot → LightDM → XFCE auto-login → Super+C → Contusion → real audio change

The existing `test-qemu.sh` is headless and cannot reach any of this.
`test_contusion_live.py` assumes a desktop is already up. The new
harness boots its own VNC-enabled QEMU, then drives the GUI over SSH +
xdotool and cross-checks the outcome via `wpctl`.

### Two modes

1. **Full harness (preferred)** — `scripts/test-desktop-e2e.sh` boots
   a fresh QEMU from `$PROJECT_DIR/output/*.iso` with `-vnc
   127.0.0.1:1` (host port 5901), waits for multi-user +
   xfce4-session, and runs all 7 steps. Exits 77 (SKIP) when QEMU /
   ISO / sshpass are missing, 0 on success, 1 on real failure.

2. **Pytest wrapper** — `test_desktop_e2e.py` runs the same 7-step
   logic against an already-running desktop (installed Arch, an
   attached VM with VNC, or a CI runner with Xvfb). Module-level
   skip if neither `DISPLAY` nor `WAYLAND_DISPLAY` is set.

### Invocation

```
# Full harness — boots its own QEMU
bash scripts/test-desktop-e2e.sh

# Override defaults
ISO_DIR=/path/to/iso \
  VNC_PORT=5902 \
  BOOT_TIMEOUT=600 \
  bash scripts/test-desktop-e2e.sh

# Pytest — against the current desktop session
pytest -v tests/integration/test_desktop_e2e.py

# Pytest — against an already-running QEMU (port-forwarded daemon)
DESKTOP_E2E_HOST=127.0.0.1 DESKTOP_E2E_PORT=8421 \
  pytest -v tests/integration/test_desktop_e2e.py
```

Attach a VNC viewer to `127.0.0.1:5901` while the shell script runs to
watch the UI in real time.

### Test battery

| # | Step | Expected evidence |
|---|---|---|
| 1 | LightDM greeter up | `systemctl is-active lightdm` == `active` within 90s |
| 2 | XFCE auto-login | `pgrep -u arch xfce4-session` within 30s |
| 3 | Super+C → Contusion | `xdotool key super+c` makes `pgrep contusion` succeed within 10s; if it fails, a direct `/usr/bin/contusion` launch is attempted to isolate keybinding vs binary regression |
| 4 | Close Contusion | `xdotool search --name 'Contusion' windowkill`; Alt+F4 fallback; SIGTERM as last resort |
| 5 | Token round-trip | `POST /auth/token` → `GET /health` with bearer → JSON with `"status"` |
| 6 | Real audio change | `wpctl get-volume @DEFAULT_AUDIO_SINK@` BEFORE, `POST /contusion/context {"request":"turn up the volume"}`, AFTER > BEFORE |
| 7 | Screenshot | `scrot -o /tmp/desktop-e2e.png` in-guest then scp back; VNC capture (`vncdotool` / `vncsnapshot`) fallback |

### Skip conditions

Whole-suite exit 77 (CI-SKIP):

* `qemu-system-x86_64`, `ssh`, `sshpass`, or `bsdtar` not installed
* no ISO under `$ISO_DIR` (default `$PROJECT_DIR/output`)

Per-step SKIP (run continues, result WARN not FAIL):

* step 2 — xfce4-session not running (common under pure-TCG with slow VGA bring-up)
* step 3 — `xdotool` missing in guest
* step 6 — `wpctl` missing OR `@DEFAULT_AUDIO_SINK@` has no sink (headless QEMU has no `-audiodev` by default)
* step 7 — `scrot`, `vncdotool`, and `vncsnapshot` all absent

Pytest module skip:

* neither `DISPLAY` nor `WAYLAND_DISPLAY` is set

### Boot budget

KVM-enabled: ~60-90s to multi-user + ~30s to XFCE autologin.
TCG (no KVM, e.g. WSL2): `BOOT_TIMEOUT=300` default, bump to 600 if the
runner is under load. The script polls at 2s intervals so it returns as
soon as the boot target is reached — it does not sleep the full budget.

### Artefacts

* `/tmp/qemu-e2e-serial.log` — guest serial console
* `/tmp/qemu-e2e-stdout.log` — QEMU's own stdout/stderr
* `/tmp/desktop-e2e-<timestamp>.png` — final screenshot (scrot or VNC)

### Cleanup

EXIT trap sends SIGTERM to QEMU, waits 5s, then SIGKILL. The extract
dir (`/tmp/iso-extract-e2e`) is recreated per run. Re-running the
harness does not leave orphan QEMU processes or stray port bindings.

## Disk-installer end-to-end test

`test_installer.py` validates the disk installer shipped in
`packages/ai-desktop-config` (`/usr/bin/ai-installer`, embedded at
PKGBUILD:10672) by running it inside a live ISO, power-cycling, and
verifying the installed system boots and passes a smoke battery.

The bash harness (`scripts/test-install-to-disk.sh`) is the source of
truth; the pytest wrapper streams its output and converts exit codes
into pytest outcomes.

### Requirements

| Item | Notes |
|---|---|
| Disk space | ~25 GB free on the host (ISO + 20 GB qcow2 + kernel extract) |
| RAM | 4 GB for phase 1 (pacstrap), 2 GB for phase 2 (smoke) |
| Runtime | ~15 min with KVM, **60-80 min under TCG** (no KVM) — `slow` marker |
| Tools | `qemu-system-x86_64`, `qemu-img`, `sshpass`, `ssh`, `scp`, `bsdtar` or `7z`, `isoinfo` |
| Optional | OVMF firmware (`edk2-ovmf`) — required for `bootloader=systemd-boot` |
| KVM | **Not required.** Script works under TCG; it just takes longer. |

### Running

```bash
# Bash direct (recommended — live progress on terminal)
bash scripts/test-install-to-disk.sh --preset=minimal

# Pytest wrapper
pytest tests/integration/test_installer.py -v -m slow

# Run the (much slower) full preset too
AI_ARCH_RUN_FULL_INSTALL=1 pytest tests/integration/test_installer.py -v -m slow
```

`--keep-disk` preserves `output/test-install-target.qcow2` for
post-mortem inspection with
`qemu-nbd -c /dev/nbd0 output/test-install-target.qcow2`.

### Answer file

`scripts/install-answers.txt` is the pre-baked input.  One `KEY=VALUE`
per line; unknown keys are silently ignored.  Key fields:

```
disk=/dev/vda          # virtio disk inside QEMU
hostname=archtest
username=arch
password=arch
timezone=UTC
keymap=us
bootloader=systemd-boot  # or 'grub'
preset=minimal           # or 'full'
```

### Port 2223

Coexists with `scripts/test-qemu.sh` (which uses 2222), so both can run
on the same host without collision.

### Exit codes

The bash harness exits with:

| Code | Meaning | pytest outcome |
|---|---|---|
| 0 | All verifications passed | PASS |
| 1 | A verification failed | FAIL |
| 2 | Environment problem (no ISO, missing tool, QEMU refused to boot) | FAIL |
| 77 | Installer binary not present on the ISO | SKIP |

The pytest wrapper also SKIPs when the ISO file or required binaries
are missing, so a fresh clone of the repo skips cleanly.

### Phase-3 verifications

After rebooting from the installed disk, the harness asserts over SSH:

1. `hostname == archtest`
2. User `arch` exists
3. `ai-control` service is active (or at least enabled)
4. `/etc/fstab` contains UUID= entries (no raw `/dev/sdX`)
5. `/etc/mkinitcpio.conf` has a `HOOKS=` line
6. `/var/log/ai-install.log` present (install-metadata file)
7. `/var/log/ai-install-boots.count` >= 1 (persistent boot-counter unit)
8. Bootloader config references `vmlinuz-linux`
9. *conditional* — `mkinitcpio.conf` has `nvidia` hook when GPU detected
10. *conditional* — `/dev/trust` present when `trust.ko` is loaded

### Why a headless runner instead of `expect`?

The installer is a GTK4 Adwaita wizard with no answer-file or
`--headless` mode, so `expect` cannot drive it without an X display.
Rather than modify the installer (out of scope), the harness uploads a
small Python script that runs the same subprocess sequence the GUI
installer calls (`pacstrap`, `genfstab`, `bootctl`, etc.).  If the
installer's command sequence drifts from the runner, the verifier
catches the drift immediately — a feature, forcing test + installer
to evolve together.
