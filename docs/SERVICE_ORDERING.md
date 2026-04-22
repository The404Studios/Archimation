# First-Boot Service Ordering Matrix (S82+G audit)

Read-only audit of systemd ordering for ai-*, display, and boot-critical
services after S77-S82 touched the graph. Sources: `profile/airootfs/etc/`
and `profile/airootfs/usr/lib/` plus package-shipped units baked into
the ISO via `profile/airootfs/root/setup-services.sh`.

Directives captured per unit: `After=`, `Before=`, `Requires=`, `Wants=`,
`Conflicts=`, `Condition*=`, `Type=`, `WantedBy=`.

## Ordering matrix

Columns: After / Before / Requires / Wants / Conflicts / Conditions / Type.
Dashes mean "none". `mu` = `multi-user.target`, `gfx` = `graphical.target`.

### Boot / HW detection

| Unit | After | Before | Req | Wants | Cond | Type |
|---|---|---|---|---|---|---|
| `ai-hw-detect.service` (profile/airootfs/usr/lib/systemd/system/ai-hw-detect.service:8-19) | systemd-modules-load, local-fs, swap | display-manager, ai-control, lightdm, ai-low-ram-services | - | - | (none) | oneshot+RemainAfterExit |
| `ai-low-ram-services.service` (profile/airootfs/usr/lib/systemd/system/ai-low-ram-services.service:3-5) | ai-hw-detect | display-manager, lightdm | - | ai-hw-detect | (ExecStartPre self-guard) | oneshot+RemainAfterExit |
| `ai-irq-balance.service` (profile/airootfs/usr/lib/systemd/system/ai-irq-balance.service:7-12) | ai-hw-detect, local-fs | ai-control, display-manager, lightdm | **ai-hw-detect** | - | - | oneshot+RemainAfterExit |
| `ai-driver-loader.service` (profile/airootfs/etc/systemd/system/ai-driver-loader.service:8-10) | systemd-modules-load | ai-control, ai-cortex | - | - | (none; S82+A removed PathExists) | oneshot+RemainAfterExit |
| `ai-power.service` (profile/airootfs/etc/systemd/system/ai-power.service:7-11) | ai-hw-detect, systemd-modules-load | ai-control, display-manager, lightdm | - | ai-hw-detect | - | oneshot+RemainAfterExit |
| `ai-setup-users.service` (profile/airootfs/etc/systemd/system/ai-setup-users.service:14-16) | systemd-sysusers, local-fs | ai-control, display-manager | - | - | - | oneshot+RemainAfterExit |
| `archimation-trust-dkms-firstboot.service` (profile/airootfs/etc/systemd/system/archimation-trust-dkms-firstboot.service:53-57) | systemd-modules-load, local-fs | **ai-control, ai-cortex** | - | - | `ConditionPathExists=/usr/src/trust-0.1.0/dkms.conf`; `ExecCondition` skips if module already present | oneshot+RemainAfterExit |
| `coherence.service` (profile/airootfs/etc/systemd/system/coherence.service:9-14) | ai-hw-detect, systemd-modules-load | graphical.target, display-manager, lightdm | - | ai-hw-detect | (none; S82+A removed /sys/.../cpu) | simple |
| `ai-install-pwsh.service` (profile/airootfs/etc/systemd/system/ai-install-pwsh.service:10-11) | network-online | - | - | network-online | - | oneshot |

### PE fabric (package-shipped via windows-services, ai-control-daemon, ai-firewall)

| Unit | After | Before | Req | Wants | Cond | Type |
|---|---|---|---|---|---|---|
| `pe-objectd.service` (packages/windows-services/PKGBUILD:66-71) | network, local-fs, systemd-modules-load | ai-cortex, scm-daemon | - | - | `ConditionPathExists=/usr/bin/pe-objectd` | notify |
| `pe-compat-firewall.service` (firewall/config/firewall.service:4-10) | network, nftables, local-fs | **pe-objectd** | - | nftables | `ConditionPathExists=/usr/sbin/nft`; `Conflicts=ufw, firewalld` | notify |
| `scm-daemon.service` (packages/windows-services/PKGBUILD:113-116) | network, pe-objectd, local-fs | - | - | pe-objectd | `ConditionPathExists=/usr/bin/scm_daemon` | notify |
| `ai-control.service` (ai-control/config/ai-control.service:8-15) | network, local-fs, ai-hw-detect | - | - | ai-hw-detect | - | notify |
| `ai-cortex.service` (packages/ai-control-daemon/PKGBUILD:160-165) | pe-objectd, systemd-modules-load, ai-control | - | **ai-control** | pe-objectd | - | notify |
| `ai-game-mode.service` (profile/airootfs/etc/systemd/system/ai-game-mode.service:8-9) | ai-cortex, ai-control | - | - | ai-cortex | - | notify |

### Display / fallback

| Unit | After | Before | Req | Wants | Cond | Type |
|---|---|---|---|---|---|---|
| `lightdm.service` base + drop-ins (etc/.../lightdm.service.d/ensure-gpu.conf:11-12, runtime-dir.conf:17-18, fallback.conf:16) | systemd-modules-load, systemd-udev-settle, ai-hw-detect, plymouth-quit-wait, systemd-user-sessions, local-fs | - | - | systemd-modules-load, ai-hw-detect, systemd-user-sessions | (none — S82 removed s80-preflight + s81-xorg-safety); `OnFailure=ai-fbcon-fallback.service` | simple (upstream) |
| `ai-fbcon-fallback.service` (profile/airootfs/etc/systemd/system/ai-fbcon-fallback.service:10-12) | getty@tty2, plymouth-quit-wait | - | - | - | `Conflicts=getty@tty2`; triggered via lightdm OnFailure | simple |

## systemd-analyze verify summary

Ran `systemd-analyze verify --man=no --generators=false --recursive-errors=no`
from WSL2 Arch against every ISO-shipped unit (see PowerShell transcript —
temp script staged then removed).

- All noisy output was NTFS-permission warnings ("marked executable",
  "marked world-writable") — benign; ISO pacstrap places these files under
  their real modes.
- All "Command X is not executable" messages (e.g. `/usr/bin/coherenced`,
  `/usr/lib/ai-arch/hw-detect.sh`) are expected on the build host: those
  binaries only exist inside the ISO airootfs, not on the host.
- **No ordering-cycle warnings.** No "Failed to resolve" / unknown unit
  errors. No deprecation warnings on `StartLimit*` placement.
- Drop-in parsing clean for all `*.service.d/*.conf` files.

## LightDM boot path (S82 baseline — preflight drop-ins removed)

The chain that has to complete before lightdm activates, in dependency
order (After= edges consolidated across base + drop-ins):

1. `systemd-modules-load.service`
2. `systemd-udev-settle.service` (ensures DRM nodes)
3. `local-fs.target` / `swap.target`
4. `ai-hw-detect.service` — writes `/run/ai-arch-hw-profile`
5. `ai-power.service`, `ai-irq-balance.service`, `ai-low-ram-services.service`
   (parallel, all After=ai-hw-detect, all Before=lightdm)
6. `ai-driver-loader.service` — loads cortex-chosen kmods before ai-control
7. `ai-setup-users.service` — trust/pe-compat/wheel group memberships
8. `plymouth-quit-wait.service`, `systemd-user-sessions.service`
9. `archimation-trust-dkms-firstboot.service` (first boot only; ExecCondition
   short-circuits on subsequent boots) → unblocks ai-control/ai-cortex
10. `ai-control.service` (Type=notify, blocks downstream until READY=1)
11. `lightdm.service`

Parallel with 9-10, the PE fabric warms: `pe-compat-firewall` → `pe-objectd`
→ `scm-daemon` + `ai-cortex` (the latter `Requires=ai-control`).

No cycles detected (systemd-analyze verify clean). Hard `Requires=` edges
that could cascade a failure:

- `ai-irq-balance` **Requires** `ai-hw-detect` (acceptable; hw-detect has
  `SuccessExitStatus=0 1 2` so a classifier miss still exits 0)
- `ai-cortex` **Requires** `ai-control` (intentional — cortex has nothing
  to talk to if daemon is dead)

## Risks identified

1. **Silent-skip risk already mitigated.** S82+A removed `ConditionPathExists`
   from `coherence.service`, `ai-low-ram-services.service`, and
   `ai-driver-loader.service`. Nothing currently on the critical path
   (lightdm ancestors) depends on `/run/ai-arch-hw-profile` via a Condition;
   the only remaining Conditions are:
   - `archimation-trust-dkms-firstboot.service`: ConditionPathExists on
     `/usr/src/trust-0.1.0/dkms.conf` + ExecCondition on kmod presence —
     correctly gates a first-boot-only side-effect.
   - `pe-objectd`, `scm-daemon`, `pe-compat-firewall`: ConditionPathExists
     on their binaries — standard "skip if package not installed" pattern.
   Sister agent A has the broad Conditions audit.

2. **S80 `Before=basic.target` removal** (profile/airootfs/usr/lib/systemd/system/ai-hw-detect.service:9-17):
   comment confirms this fixed a cycle (swap.target → sysinit → basic →
   local-fs → ai-low-ram/ai-irq-balance). Downstream units all carry
   explicit `After=ai-hw-detect.service`, so the removal is safe. No
   unit was relying on the transitive basic.target edge.

3. **S82 drop-in deletion fallout.** `docs/S80_REVERT.md:27,31,102`
   still mentions `s80-preflight.conf`. Harmless (docs/runbook text), but
   worth a follow-up scrub the next time anyone touches that file. Not
   fixing here per "read-only round".

4. **`archimation-trust-dkms-firstboot` concurrency with S82+G.** The new
   unit runs `After=systemd-modules-load, local-fs` and
   `Before=ai-control, ai-cortex`. It does **not** declare any relation
   to `ai-hw-detect`, `ai-power`, `ai-irq-balance`, or `lightdm`, so it
   is free to run in parallel with those. ai-control's `TimeoutStartSec=90`
   is generous enough that a slow DKMS build (up to 300 s by its own
   TimeoutStartSec) won't drag ai-control into a StartLimit burst. No
   cycle; no new risk.

5. **No unit currently reads hw-profile as a hard condition.** The paths
   most likely to regress if `/run/ai-arch-hw-profile` went missing are
   `ai-low-ram-services.sh`, `ai-power.sh`, `ai-irq-balance.sh`,
   `coherence.service`, `ai-control` (reads it at daemon startup per
   ai-control/config/ai-control.service:11-15 comment). All handle
   absence gracefully — either via `ExecStartPre` self-guard
   (ai-low-ram-services) or fall-back-to-DEFAULT in the script body.
   The Condition-gated silent-skip footgun is closed.

## Not done (out of scope)

- Did not modify any unit file. No Conditions added or removed.
- Did not scrub `docs/S80_REVERT.md` historical references.
- Did not reorder or add Requires/Wants edges.
