# Archimation User Manual

Welcome. This manual is for end users -- people booting the Archimation ISO on
a laptop or VM, not developers hacking on the distro. If you want build
instructions, start at [`build.md`](build.md) instead.

Keep this open in a browser tab while you explore. Everything here is honest
about what works today and what doesn't.

---

## 1. What is Archimation?

Archimation is a custom Arch Linux distribution with three unusual features:

- **Native `.exe` execution.** A built-in PE loader runs many Windows
  executables directly, without Wine. Double-click a `.exe` in the file
  manager, or type `./notepad.exe` in a terminal.
- **A biologically-inspired trust kernel.** Every privileged operation
  (launching a game, loading a driver, opening a raw socket) is mediated by
  a token-economy kernel module. Trusted processes accumulate tokens; badly
  behaved ones get throttled and eventually kicked.
- **An AI control daemon.** A FastAPI service on port 8420 accepts
  natural-language commands (`ai play music`, `ai lock the screen`) and
  routes them to the right system call.

Archimation **does not**:

- run Photoshop, Microsoft Office, or Adobe Premiere. They use Windows APIs
  we haven't implemented, and anyway you can run them under Wine/Proton on
  any regular Linux distro.
- run competitive games with kernel-level anti-cheat. Valorant, Fortnite,
  PUBG, Genshin Impact, and similar titles detect our execution
  environment and refuse to launch. You can opt into a shim that tries to
  fool them, but **the developers will ban your account** if detected.
  Don't.
- replace your daily-driver OS if you depend on commercial Windows
  software. It is a research distro that is becoming more and more
  production-capable with each release, but you have been warned.

It **does** aim to run:

- Many modern Windows games via DXVK/VKD3D-Proton (DirectX 9/10/11/12 ->
  Vulkan).
- Windows console utilities (`.exe` tools with no GUI).
- Simple .NET Framework 4.x applications, via the Mono CLR bridge.
- Most native Linux software -- this is still Arch Linux under the hood.

If something doesn't work, `ai-health` is the first place to look.

---

## 2. First boot

Insert the USB stick or attach the ISO, then pick a boot entry from the
GRUB menu (or systemd-boot, if your firmware prefers it):

- **AI Arch Linux - Boot (UEFI)** -- the default. Picks this after 2
  seconds if you don't press a key.
- **AI Arch Linux - Boot with Persistence** -- same, but writes changes
  back to the USB stick so they survive a reboot.
- **AI Arch Linux - Boot (safe mode - no AI daemon)** -- boots into a
  normal graphical session with `ai-control.service` and
  `ai-cortex.service` masked. Use this if the AI daemon is crashing the
  system at startup.
- **Install Archimation to Disk** -- triggers the disk installer flow (see
  section 6).
- **AI Arch Linux - Safe Mode (nomodeset, no splash)** -- for graphics
  card trouble, not AI-daemon trouble. This is a *different* safe mode.

During boot you'll see the Plymouth splash for 3-8 seconds, then a graphical
login screen logs the `arch` user in automatically (password: `arch`).

**If you need a raw TTY**, press `Ctrl+Alt+F2` (then `F3`, `F4` for more
virtual consoles). Log in as `arch` or `root` (password for both: `arch`).
`Ctrl+Alt+F1` returns you to the graphical session.

**Your first command:**

```bash
ai-health
```

This prints a human-readable health summary. If everything is green, you're
good to go. If something is red, scroll to section 7 for the troubleshooting
tree.

---

## 3. Running a Windows `.exe`

There are three ways to launch a Windows binary:

### Double-click in the file manager

Open Thunar (the XFCE file manager) and double-click any `.exe`. The file is
detected by MIME type and handed to the PE loader, which parses it, maps it
into memory, and starts it.

### Run it directly in a terminal

```bash
cd ~/Downloads
./putty.exe
```

`binfmt_misc` recognizes the `MZ` header and invokes the PE loader
transparently. You don't have to say `peloader ./putty.exe` by hand
(though that also works if `binfmt_misc` isn't registered).

### Drag and drop onto a terminal

Drop a `.exe` icon onto an open terminal window; the filename appears. Hit
Enter to launch.

### What works today

- **Console utilities** (single-binary `.exe` with no GUI): PuTTY, 7zip
  command line, FFmpeg Windows builds, old `notepad.exe`, many crypto
  miners, simple game servers.
- **Modern games with DX9/10/11/12** that use bundled dependencies:
  Skyrim SE, Portal 2, most indie titles that ship with their own CRT.
  DXVK/VKD3D-Proton translate graphics calls to Vulkan.
- **Simple .NET Framework apps**: the Mono CLR bridge runs `mscoree.dll`
  entrypoints and frees most small utility tools built with VS.
- **Windows services** declared in the registry: the service control
  manager daemon (`scm-daemon`) mimics the Windows SCM and can start
  them.

### What fails and why

- **32-bit PE32 binaries**. The loader only supports 64-bit PE32+ today.
  Error: `unsupported machine 0x14c`. Workaround: find a 64-bit build or
  run under Wine.
- **Apps with DRM.** Denuvo, Arxan, Vanguard, BattleEye. We don't (and
  won't) defeat these. Expected error: the app crashes on startup or
  refuses to run. No workaround in Archimation.
- **DirectX 12 Ultimate / mesh shaders.** VKD3D-Proton covers most but
  not all DX12 features. If a game refuses to launch, try the DX11
  renderer in its graphics settings.
- **Apps that need Windows COM servers we haven't implemented.**
  PowerShell scripts that call `New-Object System.Speech.Synthesizer`.
  Excel automation. Any code that talks to Explorer's shell namespace
  deeply. You'll see `CoCreateInstance: 0x80040154` (class not
  registered).
- **Apps that expect Defender, Event Viewer, or the Windows Registry in
  full fidelity.** We have a registry implementation but it's thin.

### Check what went wrong

```bash
# PE loader diagnostics:
peloader --verbose ./that-broken.exe

# binfmt_misc state:
ls /proc/sys/fs/binfmt_misc/

# recent PE-loader failures from the journal:
journalctl -u systemd-binfmt -n 50
```

---

## 4. The AI control daemon

Archimation ships with an AI system-control service on TCP port 8420
(`ai-control.service`) and a decision engine on 8421
(`ai-cortex.service`). These speak JSON over HTTP and accept both
structured commands and natural-language phrases.

### What it does

- Routes natural-language commands to system actions:
  `ai play music`, `ai turn brightness up`, `ai lock screen`,
  `ai list running games`, `ai install claude`.
- Tracks trust scores for every process launched under its control.
- Logs every command to `/var/log/ai-control/` for audit.
- Exposes a `/health` endpoint for diagnostics.

### Why it's there

Because this is a research distro exploring "trust-mediated Windows
execution under AI control." The daemon is the control plane; it decides
what gets to run, what priority it runs at, and whether the trust kernel
lets a given operation through.

You can use Archimation without ever typing `ai <anything>`, but the
daemon is still running in the background, observing. If you don't want
that, use safe mode at boot (section 2) or mask the services once
installed:

```bash
sudo systemctl disable --now ai-control.service ai-cortex.service
```

### Check that it's alive

```bash
ai-health                # human-readable summary
ai-health --brief        # one-line [OK]/[WARN]/[FAIL]
ai-health --json         # machine-readable for scripts
curl http://127.0.0.1:8420/health
```

### Talk to it

```bash
ai "what time is it"
ai "play some lofi"
ai "list running games"
ai "open firefox"
ai --help
```

The `ai` CLI lives at `/usr/bin/ai`; it's a thin Python shim that POSTs
to `/contusion/context` on 8420.

---

## 5. Trust scores explained

Every process on Archimation is a "trust subject" in the kernel. Subjects
have a trust score (0 to 1000) and a token balance. Here is what happens:

1. When a process launches, the kernel creates a `trust_subject_t` for
   it. New processes start with a low score (typically 100-200) and a
   small token budget.
2. Every privileged operation (open a raw socket, load a kernel module,
   mount a filesystem, start a child as root) costs tokens. If the
   subject's balance is too low, the operation is **refused at the
   syscall layer** -- the subject never sees a chance to run that code.
3. Well-behaved processes accumulate tokens over time. Misbehaving ones
   (segfaulting, leaking, trying forbidden syscalls, failing
   Authenticode checks on loaded binaries) lose them.
4. If a subject hits zero tokens or crosses other red lines, it's
   **kicked**: the kernel sends SIGKILL and logs the event to the
   trust event journal.

Trust scores are visible via the daemon:

```bash
curl http://127.0.0.1:8420/trust/subject/self | jq
```

You as the interactive user can spend tokens on demand by typing
`ai grant N tokens to <process>` at the CLI, but only if you already have
enough authority tokens yourself. This mostly matters when debugging a
process that keeps getting throttled.

You do not need to understand the token economics to use Archimation
day-to-day. The defaults are tuned so that typical desktop use never
trips trust gates. The system quietly keeps logs, and if something gets
killed unexpectedly `journalctl -u ai-control` will tell you why.

---

## 6. Installing to disk

Booting the ISO repeatedly is fine for evaluation. To install
Archimation permanently, use the disk installer. From a terminal:

```bash
sudo ai-install-to-disk
```

Or pick **Install Archimation to Disk** from the GRUB menu, which
triggers the same installer. There's also a desktop entry named
*Install Archimation* in the Applications menu.

The installer asks for:

- a target disk (will be **wiped**),
- a hostname,
- a user account name + password,
- whether to enable disk encryption (LUKS).

It lays down the same layout as the live ISO and sets up a GRUB/systemd-boot
entry for the new install. Expect ~5 minutes on NVMe. Reboot into the
installed system and `ai-health` should come up all green.

This tool is shipped as `/usr/bin/ai-install-to-disk`. The installer
itself is maintained separately (see the disk installer section in the
release notes); report installer bugs against that component.

---

## 7. Troubleshooting tree

Start at `ai-health` and follow the first red line.

### "AI daemon won't start"

```bash
ai-health
# -> AI daemon: status=failed, port 8420: no

systemctl status ai-control.service
journalctl -u ai-control -n 100 --no-pager
```

Common causes:

- Port 8420 is in use. `ss -tln | grep 8420`. Kill the squatter.
- Python dependency missing. Reinstall the package:
  `sudo pacman -Syu ai-control-daemon`.
- Config file corrupted. Restore defaults:
  `sudo cp /usr/share/ai-control/config.default.toml /etc/ai-control/config.toml`.

If none of that works, boot into "safe mode - no AI daemon" from GRUB
so you can log in and file a bug.

### "peloader fails on .exe"

```bash
journalctl -u systemd-binfmt -n 50
peloader --verbose ./that-broken.exe 2>&1 | head -30
```

Common causes:

- `binfmt_misc` not registered:
  `sudo systemctl restart systemd-binfmt.service`.
- 32-bit PE32 binary (unsupported). Find a 64-bit build.
- Missing DLL the app needs. `peloader --verbose` prints the missing
  name; check `/usr/lib/pe-compat/` for a stub, or see
  [pe-dll-coverage.md](pe-dll-coverage.md).
- Anti-cheat DRM. See section 3 for which games this affects.

### "Game has no gamepad"

```bash
ls /dev/input/js0                # should exist
jstest /dev/input/js0            # should print axis values when you wiggle
```

- If `/dev/input/js0` is missing, your controller's kernel driver isn't
  loaded. Try another USB port, or `sudo modprobe xpad` for Xbox
  controllers.
- If the device exists but the game can't see it, the game is probably
  polling Windows XInput. Check that `xinput1_3.dll` is visible:
  `ls /usr/lib/pe-compat/ | grep -i xinput`.

### "Trust kernel says `/dev/trust` missing"

```bash
lsmod | grep trust
dmesg | grep -i trust | tail -20
```

- The trust module is missing. Reinstall:
  `sudo pacman -Syu trust-dkms`.
- DKMS couldn't build it. Install kernel headers:
  `sudo pacman -S linux-headers && sudo dkms autoinstall`.
- Still failing? You can boot without it -- Archimation degrades
  cleanly to plain Arch Linux with a PE loader and nothing trust-gated.
  Mask the module at boot: add `trust.disabled=1` to the kernel cmdline.

### "The system feels slow"

```bash
ai-health
top     # or htop, if installed
iotop   # if installed
```

Common causes:

- AI cortex running an LLM against your CPU. `systemctl status ai-cortex`.
- PE loader mapping a huge `.exe` (RE tools do this). That's normal;
  just wait.
- Swap pressure. Check `free -h`. If swap is >50% used, close something.

### "Something I don't recognize is happening"

```bash
journalctl -xb                 # everything since last boot, with reasons
dmesg | tail -100
ai-health --json | jq         # scriptable health summary
```

If you're truly stuck, boot to safe mode (section 2), then run:

```bash
sudo journalctl -xb > /tmp/boot.log
```

Attach that file to a bug report.

---

## 8. Where to report bugs

**Primary channel:** <https://github.com/ai-arch-linux/issues>

> Note: that URL is aspirational -- at the time of writing, this project
> is private and the issue tracker may not exist yet. Look at
> `docs/release-process.md` for the currently active reporting channel.

When filing a bug, please include:

- Output of `ai-health --json`.
- The exact command you ran, and what you expected.
- `journalctl -xb | tail -200` piped to a pastebin.
- The build of the distro: `cat /etc/os-release` and
  `pacman -Q ai-control-daemon pe-loader trust-dkms`.
- The model of hardware (CPU, GPU, chipset) -- relevant especially for
  the PE loader and any DirectX game.

Don't include:

- Files you don't want public -- check the log for paths.
- Credentials. The daemon log scrubs the obvious ones, but eyeball it.

---

## 9. License + credits

Archimation is distributed under the terms of its component licenses:

- **Linux kernel**: GPLv2. See `/usr/src/linux-*/COPYING`.
- **Trust kernel module** (`trust.ko`): GPLv2, in-tree with the kernel
  module licensing conventions.
- **PE loader, DLL stubs, SCM daemon**: MIT License, see
  `/usr/share/licenses/*`.
- **AI control daemon**: Apache License 2.0.
- **XFCE, Plymouth, GRUB, systemd, Python**: as shipped by Arch Linux,
  mostly GPL/LGPL/BSD variants. See `/usr/share/licenses/` for per-
  package licensing.
- **DXVK, VKD3D-Proton**: zlib License. Upstream at
  <https://github.com/doitsujin/dxvk> and
  <https://github.com/HansKristian-Work/vkd3d-proton>.
- **Mono CLR**: MIT License.
- **FreeType**: FreeType License (BSD-like).

This distribution is not affiliated with or endorsed by Microsoft,
Valve, or the Arch Linux project. "Windows" is a trademark of Microsoft
Corporation; we use the name descriptively to refer to PE binary
compatibility, not to imply a licensing relationship.

The biologically-inspired trust model, the PE loader, and the AI cortex
are original work by this project's maintainers. See
`docs/architecture.md` for design notes and `PLAN/` for the early
vision documents.

---

## 10. Example phrases

The AI daemon recognizes natural-language commands in five broad groups.
These are a representative sampling -- the compiled phrase dictionary
ships with ~45,000 templated forms, so you rarely have to match the wording
exactly. Try your own variations.

### ONE-WORD commands

Terse. Fastest path through the AI. Use these when you know what you want.

| Phrase        | Does                                  |
|---------------|---------------------------------------|
| `mute`        | Toggle system audio mute              |
| `unmute`      | Toggle system audio mute              |
| `louder`      | Raise volume                          |
| `quieter`     | Lower volume                          |
| `brighter`    | Raise display brightness              |
| `dimmer`      | Lower display brightness              |
| `lock`        | Lock the screen                       |
| `suspend`     | Suspend the machine to RAM            |
| `screenshot`  | Take a full-screen screenshot         |
| `silence`     | Mute (colloquial)                     |
| `f11`         | Toggle fullscreen on the focused window |
| `lsmod`       | List loaded kernel drivers             |
| `overview`    | Show workspaces / expose desktops     |

### COMPOUND intents

One phrase, two or more actions. The daemon splits on `and` / `then` /
commas and routes each clause separately, returning an `actions` array.

| Phrase                                                | Expands to                                  |
|-------------------------------------------------------|---------------------------------------------|
| `mute and lock screen`                                | `audio.mute_toggle` + `power.lock_screen`  |
| `take a screenshot and copy it to clipboard`          | `system.screenshot_full` + `clipboard.set` |
| `volume up then pause music`                          | `audio.volume_up` + `media.pause`          |
| `check disk space and show my ip`                     | `query.disk_space` + `query.ip_address`    |
| `lock screen and suspend`                             | `power.lock_screen` + `power.suspend`      |
| `mute then brightness down`                           | `audio.mute_toggle` + `brightness.down`    |
| `take a screenshot and lock`                          | `system.screenshot_full` + `power.lock_screen` |
| `pause music and turn off display`                    | `media.pause` + `power.screen_off`         |
| `volume up, brightness down, lock`                    | three-way split                             |
| `good night`                                          | multi-action shutdown routine (lock + mute + screen_off) |

### SOFTWARE-INSTALL (Windows catalog)

A built-in catalog of ~25 popular Windows applications. Pulls the right
installer, runs it through the PE loader, and registers any entry points
with the system launcher.

| Phrase                                  | Package            |
|-----------------------------------------|--------------------|
| `install visual studio community`       | Visual Studio 2022 Community |
| `install 7-zip`                         | 7-Zip              |
| `get firefox`                           | Firefox            |
| `download vscode`                       | Visual Studio Code |
| `install obs`                           | OBS Studio         |
| `install blender`                       | Blender            |
| `install cmake`                         | CMake              |
| `install discord`                       | Discord            |
| `install notepad++`                     | Notepad++          |
| `install git for windows`               | Git (Win)          |
| `install nodejs`                        | Node.js            |
| `install python`                        | Python (Windows)   |
| `install putty`                         | PuTTY              |
| `install chrome`                        | Google Chrome      |

All resolve to `app.install_windows` with an `APP_WIN_NAME` slot filled.
The handler downloads (or uses a cached) Windows installer, runs it
under the PE loader, and logs the operation to
`/var/log/ai-control/win-install.log`.

### QUERIES (non-destructive read-only)

Read-only system introspection. No prompt. No confirmation. Safe to run
in a tight loop.

| Phrase                              | Handler                  |
|-------------------------------------|--------------------------|
| `how much disk space`               | `query.disk_space`       |
| `what is my ip`                     | `query.ip_address`       |
| `uptime`                            | `query.uptime`           |
| `cpu temperature`                   | `query.cpu_temp`         |
| `what is using the most memory`     | `query.memory_top`       |
| `who is on my wifi`                 | `query.wifi_peers`       |
| `kernel version`                    | `query.kernel_version`   |
| `distro version`                    | `query.distro_version`   |
| `load average`                      | `query.loadavg`          |
| `who is logged in`                  | `query.logged_in_users`  |
| `what time is it`                   | `query.uptime` (reuses)  |
| `free ram`                          | `query.memory_top`       |
| `disk free`                         | `query.disk_space`       |

### PE-LOADER invocation

Direct control of the Windows PE execution path. Use these to probe /
debug the loader or manage its run history.

| Phrase                       | Handler               |
|------------------------------|-----------------------|
| `run this exe`               | `pe.run`              |
| `run the exe`                | `pe.run`              |
| `analyze this pe file`       | `pe.analyze`          |
| `list recent pe runs`        | `pe.list_recent`      |
| `install this msi`           | `pe.install_msi`      |
| `clear pe cache`             | `pe.clear_cache`      |
| `show pe loader status`      | (routes to system.info) |

Any `pe.run` / `pe.analyze` phrase expects the binary path as a `PE_TARGET`
slot. If you don't pass one, the handler returns
`success=false, error="PE_TARGET missing"` -- it does NOT prompt.

### FILE-OPS

Convenience wrappers around common file chores. Everything is dry-run by
default if the handler can guess the destructive intent; `file.delete_*`
in particular asks the trust kernel for `TRUST_ACTION_FILE_DELETE` tokens
before it actually removes anything.

| Phrase                                         | Handler                  |
|------------------------------------------------|--------------------------|
| `delete empty folders in downloads`            | `file.delete_empty_dirs` |
| `find the 10 largest files in my home`         | `file.find_largest`      |
| `list recent files in documents`               | `file.list_recent`       |
| `zip my downloads`                             | `file.zip_folder`        |
| `move all *.jpg to pictures`                   | `file.move_by_pattern`   |
| `backup downloads to usb`                      | `file.backup_to`         |
| `open ~/.config`                               | `file.open_path`         |
| `what has changed recently`                    | `file.list_recent`       |

---

## 11. When the AI doesn't understand

If you type something short or ambiguous like `up`, `volume`, or
`brightness`, the daemon no longer silently picks one meaning. It returns
a **clarification envelope** instead.

Example:

```
ai "up"

-> The AI isn't sure. Asking:
   Did you mean volume up (audio), brightness up (display), or
   scroll up (window)?
```

Technically, the daemon response has this shape:

```json
{
  "success": false,
  "handler_type": "contusion.clarify",
  "source": "clarification",
  "original_phrase": "up",
  "candidates": [
    {"handler_type": "audio.volume_up",      "confidence": 0.62,
     "example_phrase": "volume up"},
    {"handler_type": "brightness.up",        "confidence": 0.59,
     "example_phrase": "brightness up"},
    {"handler_type": "window.scroll_up",     "confidence": 0.55,
     "example_phrase": "scroll up"}
  ],
  "asking": "Did you mean volume up (audio), brightness up (display), or scroll up (window)?",
  "actions": [],
  "results": []
}
```

No handler was dispatched. The `actions` array is empty; nothing
happened. You have three choices:

1. **Re-ask with more context**: `ai volume up`, `ai brightness up`, etc.
   This will take the confident path directly.
2. **Pick a candidate by name**: `ai yes audio.volume_up`.
3. **Silence the clarifier**: set
   `AICONTROL_CLARIFY_CONFIDENT=0.0` in the daemon environment and
   the daemon will always pick the top candidate. Not recommended on a
   shared machine.

Thresholds are tunable via env vars at daemon startup:

| Variable                       | Default | Meaning                                    |
|--------------------------------|---------|--------------------------------------------|
| `AICONTROL_CLARIFY_CONFIDENT`  | `0.85`  | If top1 >= this, dispatch without asking.  |
| `AICONTROL_CLARIFY_GAP`        | `0.15`  | If top1 - top2 >= this, top1 is confident. |
| `AICONTROL_CLARIFY_WINDOW`     | `0.10`  | Candidates within this of top1 are "near-tied" and shown in the asking. |
| `AICONTROL_CLARIFY_TOP_K`      | `5`     | Max candidates fetched; the asking text trims to 2-3 in most cases. |

The clarification path costs about 0.5 ms on top of a normal phrase
lookup (single extra `lookup_multi()` call) so it's cheap enough to
have on by default.

---

*Manual version: Session 70. If this document is out of date with the
running system, trust the system and file a bug.*
