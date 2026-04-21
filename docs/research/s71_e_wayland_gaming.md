# S71 Research E — Wayland, Gaming, and the X11 Transition

Research Agent E, Session 71 (2026-04-20)
Project: ARCHWINDOWS (Arch Linux + pe-loader + XFCE for Windows apps/games)
Angle: How ARCHWINDOWS survives the 2024-2026 X11 → Wayland window on both ends of the hardware spectrum.

---

## 400-Word Executive Summary

X11's upstream maintenance has effectively ended. KDE Plasma 6.0 (2024-02-28) made Wayland the default; KDE is committing to Wayland-only in the near future. GNOME 48 (2025-03-19) disabled the X11 session by default from GNOME 49 onward, and GNOME 50 (March 2026) ships with zero X11 code in Mutter — the Wayland backend merge that removed X11 landed 2025-11-05. XFCE, which ARCHWINDOWS currently ships, is still X11-primary: Xfce 4.20 (2024-12) has only experimental Wayland support via labwc or wayfire (both wlroots-based), xfwm4 remains X11-only, and a brand-new xfwl4 compositor is planned rather than a port. Ubuntu 24.04, Fedora 43, and KDE-based distros are Wayland-default. Hyprland 0.50 (2025-07), 0.53 (2025-12) are production-stable for daily gaming; Niri graduated past 0.1 in 2025-01 (25.01) as a scrollable-tiling daily driver; Sway 1.11 and labwc 0.8.x are mature wlroots compositors.

Gaming on Wayland is finally first-class in 2025-2026. KDE Plasma 6.2 made the Wayland color-management protocol the default for HDR displays; Plasma 6.3 overhauled fractional scaling; Plasma 6.5.3 (2025-11) fixed multi-monitor VRR smoothness. The DRM Color Pipeline API merged to drm-misc-next 2025-11-26, in Linux 6.19-rc1 — AMD is first landing with DCN 3.0+ HDR; NVIDIA announced preview. VRR under KDE Wayland works end-to-end in windowed mode; under Hyprland it works fullscreen-gated via `vrr=2`. GameScope (Valve's micro-compositor) is the de-facto gaming isolation layer: FSR/NIS upscaling (`-F fsr`/`-F nis`), resolution spoofing (`-h`/`-H`), frame limit (`-r`), HDR10 via `--hdr-enabled`, VRR only in embedded/DRM-KMS mode (not nested). XWayland for DXVK games shows measurable performance loss (one report: >60% DXVK drop, 15% native GL drop) vs X11 in 2024; the gap has narrowed but not closed.

**Recommendation for ARCHWINDOWS**: keep X11 as the primary desktop through 2026 (XFCE's Wayland story is 2+ years away), ship GameScope as the gaming compositor of choice in BOTH sessions (it works under X11 and Wayland), preserve `ai.display=x11` as a boot mode for pre-2013 hardware (Ivy Bridge, GMA 3150), and **begin a libwayland backend in pe-loader now as a sibling to `gfx_x11.c` / `gfx_wayland.c` stub** — the abstraction already exists (`gfx_backend_t` in `pe-loader/graphics/gfx_backend.h`), only the implementation is stubbed. Estimated 1,400-1,800 LOC to reach feature parity with the X11 backend (952 LOC today), feature-gated by `GFX_BACKEND=wayland` env var. This is the single piece of engineering that unlocks HDR, VRR, and fractional scaling for Win32 games run under pe-loader.

---

## 1. Wayland Stack 2024-2026 — Compositors & Maturity

### Desktop Environments

| DE | Version | Release Date | Wayland Status |
|---|---|---|---|
| **KDE Plasma** | 6.0 | 2024-02-28 | Wayland became **default** session; X11 preserved ([KDE MegaRelease 6](https://kde.org/announcements/megarelease/6/)) |
| KDE Plasma | 6.1 | 2024-06 | Explicit sync, smarter buffering |
| KDE Plasma | 6.2 | 2024-10 | **Wayland color-management protocol default; HDR tone mapping** |
| KDE Plasma | 6.3 | 2025-02 | Fractional-scaling overhaul |
| KDE Plasma | 6.5.3 | 2025-11 | Multi-monitor VRR smoothness; MHC2 ICC tag |
| KDE Plasma | 6.6 | 2025-12 | HDR+Wayland stability polish |
| **GNOME** | 47 | 2024-09 | Wayland-only build **option** added |
| GNOME | 48 | 2025-03-19 | Dynamic triple buffering; wayland color-mgmt; X11 session disabled-by-default going forward |
| GNOME | 49 | 2025-09 | X11 session requires explicit build flag |
| GNOME | 50 | 2026-03 (planned) | **Zero X11 code in Mutter** (merged 2025-11-05) |
| **XFCE** | 4.20 | 2024-12 | **Experimental** Wayland via labwc/wayfire only; xfwm4 stays X11-only; xfwl4 planned ([Xfce Wayland roadmap](https://wiki.xfce.org/releng/wayland_roadmap)) |

### Compositors (standalone)

| Compositor | Latest | Stability | Gaming Notes |
|---|---|---|---|
| **Hyprland** | 0.53 (2025-12) | Production-stable; crash-recovery launcher in 0.53 | `vrr=1` always, `vrr=2` fullscreen. Use GameScope nested for problem games ([Hyprland 0.53](https://hypr.land/news/update53/)) |
| **Sway** | 1.11-rc1 (2025) | i3-style tiling, mature wlroots | Solid for native Wayland games; XWayland for Win32 |
| **labwc** | 0.8.4 (2025) | Stable stacking compositor (wlroots) | Default for Xfce-Wayland experiments |
| **Niri** | 25.01 (Jan 2025) | "Sufficiently featureful to graduate from v0.1"; daily-drivable; NVIDIA support added | Rust-written; scrollable tiling; window rules + screen-capture portals ([niri-wm/niri](https://github.com/niri-wm/niri)) |
| **River** | - | Dynamic tiling, supported in archinstall 3.0.5 | Niche |
| **KWin** (KDE) | 6.x | Most feature-complete Wayland compositor for gaming | HDR, VRR, color-mgmt all first-class |
| **Mutter** (GNOME) | 46+ | VRR and fractional scale solid; X11 backend dropped 2025-11 | Works well for non-competitive games |
| **GameScope** | 3.14+ (Valve) | Micro-compositor purpose-built for games | Isolates game from desktop; HDR10; VRR in embedded mode only |

### Takeaway

**2026 is the last year X11 is a credible default**. Rolling distros (Arch, Fedora) ship Wayland-first KDE/GNOME. XFCE is the last holdout among major DEs and its Wayland story is *years* from feature parity. ARCHWINDOWS is currently on the XFCE+X11 path — that's fine for another 12-18 months but needs planning.

---

## 2. Game-Compositor Specifics

### 2.1 GameScope (Valve)

**What it is**: A Wayland micro-compositor that runs ONE application (the game) in its own sandboxed compositor. Runs either **embedded** (owns the DRM/KMS device, e.g. Steam Deck's Gaming Mode; ARCH Linux `--steamos3` session) or **nested** (runs inside another compositor, treated as a window).

**Why it matters for ARCHWINDOWS**:
- Resolution/refresh spoofing lets a game see only a single virtual display — isolates it from the user's multi-monitor reality. Critical for pe-loader correctness when Win32 enumerates monitors.
- Direct-scanout bypass: captures frames via Wayland/Xwayland without intermediate copies, flips via DRM/KMS. Lower latency than the normal desktop path.
- FSR/NIS upscaling for free, regardless of game support. 720p→1440p via `gamescope -h 720 -H 1440 -F fsr -- %command%`.
- HDR10 requires `--hdr-enabled`. Only works in embedded mode or with compositor cooperation.
- VRR via `--adaptive-sync` works only in embedded/DRM-KMS mode; nested mode under Hyprland is broken as of [gamescope#1957](https://github.com/ValveSoftware/gamescope/issues/1957) (blocking direct scanout).
- [Arch Wiki: Gamescope](https://wiki.archlinux.org/title/Gamescope), [ValveSoftware/gamescope](https://github.com/ValveSoftware/gamescope)

**Installation note for ARCHWINDOWS**: already in `profile/packages.x86_64:71` as of Session 33 Agent 8. Session 34's compositor-bypass work added `ai.gamescope_owns_present_loop` — that was the right call.

**Integration pattern** (recommended for ARCHWINDOWS):
```bash
# Nested launch in any session (desktop mode):
gamescope -w 1920 -h 1080 -W 2560 -H 1440 -F fsr -f -- \
    pe-loader /path/to/game.exe

# Embedded launch (TTY, SteamOS-style, for serious gaming):
gamescope --steamos3 --hdr-enabled --adaptive-sync -- steam
```

### 2.2 VRR / FreeSync / Adaptive-Sync on Wayland

| Compositor | VRR Support | Windowed? | Gamescope-compat |
|---|---|---|---|
| KWin Wayland 6.5+ | Full | **YES** (windowed + fullscreen) | Works nested |
| Hyprland 0.50+ | `vrr=2` gate | Fullscreen only | Embedded only |
| Sway | Fullscreen | Fullscreen only | Embedded only |
| Mutter (GNOME) | Since 46 | Fullscreen only | Works nested |
| X11 | Native for AMD/NV fullscreen; broken windowed | - | Works under X11 session |

See [Arch Wiki: Variable refresh rate](https://wiki.archlinux.org/title/Variable_refresh_rate) for the current compatibility matrix.

### 2.3 HDR10 on Linux in 2025-2026

- Kernel 6.8 (2024-03) landed AMD DCN 3.0+ HDR plane programming ([Maíra Canal on 6.8 HDR](https://mairacanal.github.io/linux-6-8-AMD-HDR-and-raspberry-pi-5/)).
- **DRM Color Pipeline API** merged to drm-misc-next 2025-11-26, in Linux 6.19-rc1 ([Phoronix — NVIDIA Preview](https://www.gamingonlinux.com/2026/04/nvidia-announce-a-preview-of-drm-per-plane-color-pipeline-api-support-on-linux-good-for-hdr/)).
- KDE Plasma 6.2 exposed `wp_color_management_v1` by default; 6.5.x polished multi-monitor VRR+HDR together.
- GameScope: `--hdr-enabled` end-to-end.
- [ArchWiki HDR monitor support](https://wiki.archlinux.org/title/HDR_monitor_support) documents per-compositor state.

**For ARCHWINDOWS**: HDR is now a concrete feature, not a promise. GameScope is the path to expose it to Win32 games under pe-loader.

### 2.4 XWayland Performance for pe-loader

Because pe-loader's `gfx_x11.c` uses Xlib, a Wayland user sees pe-loader Win32 windows through **XWayland** (X11 compatibility layer). This works — the user32 message pump and Win32 HWND→Window mapping still function. But:

- One cited 2024 benchmark showed **>60% DXVK performance drop** and **15% native GL drop** under Wayland vs X11 ([Wayland vs X11 performance — dedoimedo](https://www.dedoimedo.com/computers/wayland-vs-x11-performance-amd-graphics.html); see also [XDA Wayland reasons](https://www.xda-developers.com/reasons-wayland-better-than-x11/)). Numbers have narrowed through 2025 but XWayland still costs non-zero frame time and blocks HDR/VRR/fractional-scale by design.
- XWayland scales fractionally-scaled surfaces by blurry bilinear unless the compositor supports per-window integer-then-scale (KDE 6.3+).
- **Input latency**: XWayland adds a protocol roundtrip vs native Wayland clients.

**Bottom line**: pe-loader under XWayland is *functional* but surrenders most Wayland advantages. A native Wayland backend is the correct long-term answer.

---

## 3. Old-Hardware Fallback — Keep X11 as Opt-In Boot Mode

**The constraint**: Wayland compositors all assume GL or GLES acceleration. Software rendering (`vulkan-swrast` + `llvmpipe`) works but is slow (10-20 fps for desktop compositing on an Atom).

**Hardware ARCHWINDOWS should support**:
- Intel GMA 3150 (Pineview, ~2009 netbooks) — no GL2 support, Wayland compositors run in software rendering only.
- Intel Ivy Bridge HD 4000 (~2012) — GL3.3 works, Wayland in GNOME/KDE fine with a modest performance hit.
- ThinkPad T61 (GM965, 2007-2008) — KMS works, but no GLES2 — Wayland compositors essentially unusable. [archlinux forum #310154](https://bbs.archlinux.org/viewtopic.php?id=310154)
- Any pre-2013 Intel IGP — X11 remains genuinely the right choice.

**Arch Linux 2025 stance**: [Arch Wiki: Wayland](https://wiki.archlinux.org/title/Wayland) says unsetting `WAYLAND_DISPLAY` falls back to X11 via `DISPLAY`. For very old hardware, X11 is still recommended.

### Concrete recommendation

Expose a GRUB boot entry:
```
GRUB_ENTRY_Arch_X11:    "ARCHWINDOWS (X11 session, compat)"   → ai.display=x11
GRUB_ENTRY_Arch_Wayland:"ARCHWINDOWS (Wayland session)"       → ai.display=wayland
```

Back this with a kernel-cmdline-driven session selector:
- `ai.display=x11` (default through 2026) → current XFCE+Xorg
- `ai.display=wayland` → XFCE-Wayland via labwc (or KWin on opt-in KDE spin)
- `ai.display=gamescope-embedded` → pure Gaming-Mode boot, no desktop

The AI daemon's `systemd-generator` or `ai-control.service` `ExecStartPre` can read `/proc/cmdline` and export `GFX_BACKEND=x11|wayland` for pe-loader.

---

## 4. Pe-loader Backend Evolution — XCB → Abstract → Native Wayland

### 4.1 Current State (audited 2026-04-20)

| File | LOC | Status |
|---|---|---|
| `pe-loader/graphics/gfx_backend.h` | 229 | Abstract interface **already exists** (lifecycle, windows, DCs, paint, events, screen-size) |
| `pe-loader/graphics/gfx_x11.c` | 952 | Full Xlib backend — keysym→VK mapping, GC/Pixmap double-buffer, WM_DELETE_WINDOW |
| `pe-loader/graphics/gfx_wayland.c` | 580 | **Skeleton with dlsym'd libwayland-client**; `WAYLAND_DISPLAY` probe; `init`/`cleanup` real; window/surface/buffer creation/event-dispatch **all stubbed** — prints `- stub` |
| `pe-loader/graphics/gfx_drawing.c` | 74 | Shared drawing helpers |
| `pe-loader/dlls/user32/user32_window.c` | 2,996 | Uses `gfx_get_backend()` abstraction exclusively — **no X11 leakage** into user32 logic except one comment at line 434 referring to the X11 Window handle |

**The abstraction is already clean.** This is a Session-65-era decision that pays off now. Files named `user32_window.c`, `user32_message.c`, `user32_input.c`, `user32_display.c` all talk only through `gfx_backend_t *backend`.

### 4.2 What the Wayland backend needs to implement

To reach parity with `gfx_x11.c`:

| Feature | X11 approach | Wayland approach | LOC est. |
|---|---|---|---|
| Connect | `XOpenDisplay()` | `wl_display_connect()` + registry globals bind | ~120 |
| Create window | `XCreateSimpleWindow` + `XStoreName` | `wl_compositor_create_surface` + `xdg_wm_base_get_xdg_surface` + `xdg_surface_get_toplevel` + `xdg_toplevel_set_title` | ~180 |
| Framebuffer | `XCreatePixmap` + XShm | `wl_shm_pool` + `memfd_create` + `wl_shm_pool_create_buffer` ([libwayland in-depth](https://wayland-book.com/libwayland.html)) | ~220 |
| Paint | `XFillRectangle` + `XPutImage` | Write to shm pool + `wl_surface_damage_buffer` + `wl_surface_commit` | ~180 |
| Events | `XNextEvent` | `wl_display_dispatch` + `wl_keyboard`/`wl_pointer` listeners + xkbcommon keymap | ~320 |
| Keymap | X11 keysym→VK table | `wl_keyboard.keymap` (xkb_keymap_new_from_fd) + keysym lookup | ~120 |
| Text input | (libX11 compose via Xutf8LookupString) | `wl_keyboard.key` + xkbcommon `xkb_state_key_get_utf8` | ~80 |
| Close | `WM_DELETE_WINDOW` | `xdg_toplevel.close` callback | ~20 |
| Resize | `ConfigureNotify` | `xdg_toplevel.configure` + `xdg_surface.configure` ack | ~80 |
| Screen size | `XDefaultScreenOfDisplay` | `wl_output.geometry` + `wl_output.mode` | ~40 |
| Fractional scale | N/A | `wp_fractional_scale_manager_v1` + `wp_fractional_scale_v1.preferred_scale` ([wayland-protocols: fractional-scale-v1](https://wayland.app/protocols/fractional-scale-v1)) | ~80 |
| HDR / color mgmt | N/A | `wp_color_management_v1` (optional, KDE 6.2+) | ~120 |
| Native-window handle | `gfx_get_native_window()` returns `Window` | Returns `struct wl_surface *` or 0 | ~20 |

**Total LOC estimate: ~1,400-1,800** for a production-quality port (matching `gfx_x11.c`'s 952 + fractional scale + HDR). `gfx_wayland.c` today is 580 LOC of scaffolding — maybe 400 of that survives; figure **~1,000 new LOC** to write.

### 4.3 Effort phases

Phase 1 (~500 LOC, 1 session): fill the stubs — registry binding, `wl_shm` framebuffer, `xdg_wm_base` surface, keyboard events via xkbcommon, commit/damage. A simple hello-window draws and responds to keys. Gated by env var `GFX_BACKEND=wayland`.

Phase 2 (~400 LOC, 1 session): `wl_pointer`, focus events, resize via `xdg_toplevel.configure`, close via `xdg_toplevel.close`, cursor. `notepad.exe` equivalent works.

Phase 3 (~300 LOC, 1 session): fractional scale, text input + xkbcommon compose, multi-monitor output tracking.

Phase 4 (~300 LOC, future): color management, HDR surface metadata, per-monitor DPI propagation to `gdi32`'s DPI-per-CRTC cache (Session 67 A6 already landed per-monitor DPI via XRandR; mirror it via `wl_output.geometry`).

---

## 5. Priority Features on Wayland for Gamers

Ordered by user-visible payoff for a gaming-focused distro:

1. **GameScope integration path** — ship `gamescope` (already done), add AI-daemon handler `game.launch_gamescope(exe, args, flags)` that composes correct `-w`/`-H`/`-F`/`--hdr-enabled`/`--adaptive-sync` per game profile. Biggest win per engineering hour.
2. **VRR under KDE/Hyprland Wayland** — AI daemon `display.set_vrr(mode)` wrapping `kwriteconfig6 --file kwinrc --group Wayland --key EnablePrimarySelection...` or Hyprland IPC `hyprctl keyword misc:vrr 2`.
3. **HDR via GameScope `--hdr-enabled`** — supported end-to-end for AMD DCN3+ and (preview) NVIDIA. Gate on `display.hdr_supported()` probe (read `/sys/class/drm/.../hdr_sink_metadata`).
4. **Fractional scaling for pe-loader windows** — native Wayland backend Phase 3 above; WM_DPICHANGED already stubbed (Session 67 A6).
5. **Direct scanout / tear-free** — GameScope owns. Do NOT reinvent.
6. **libinput game controller** — pe-loader's XInput DLLs should be audited to talk libinput directly, not depend on X11.

---

## 6. Files Reviewed

All paths absolute as of this session:
- `C:/Users/wilde/Downloads/arch-linux-with-full-ai-control/pe-loader/graphics/gfx_backend.h` (229 LOC — the abstract interface)
- `C:/Users/wilde/Downloads/arch-linux-with-full-ai-control/pe-loader/graphics/gfx_x11.c` (952 LOC — Xlib backend)
- `C:/Users/wilde/Downloads/arch-linux-with-full-ai-control/pe-loader/graphics/gfx_wayland.c` (580 LOC — stubs + dlsym scaffolding)
- `C:/Users/wilde/Downloads/arch-linux-with-full-ai-control/pe-loader/dlls/user32/user32_window.c` (2,996 LOC — uses `gfx_backend_t` cleanly)
- `C:/Users/wilde/Downloads/arch-linux-with-full-ai-control/pe-loader/dlls/user32/user32_message.c` (1,159 LOC — no X11 leakage)
- `C:/Users/wilde/Downloads/arch-linux-with-full-ai-control/pe-loader/dlls/user32/user32_input.c` (696 LOC — one X11 include for X11-only path)
- `C:/Users/wilde/Downloads/arch-linux-with-full-ai-control/pe-loader/dlls/user32/user32_display.c` (344 LOC — screen info via backend)
- `C:/Users/wilde/Downloads/arch-linux-with-full-ai-control/profile/packages.x86_64` (lines 16-72 — XFCE + xorg + gamescope + egl-wayland already present)

---

## 7. Recommendation — Next 1-2 Sessions

**Do now (Session 72-73)**:

1. **Start `gfx_wayland.c` Phase 1 (~500 LOC)**. Fill the stubs in priority order: registry bind → shm buffer → xdg_toplevel surface → keyboard events. Gate activation by env var:
   ```c
   // pe-loader/graphics/gfx_core.c (or wherever gfx_init() lives)
   const char *prefer = getenv("GFX_BACKEND");
   if (prefer && !strcmp(prefer, "wayland") && gfx_wayland_available()) {
       backend = gfx_wayland_create();
   } else {
       backend = gfx_x11_create();  // default — unchanged
   }
   ```
2. **Add GRUB entry `ai.display=x11|wayland|gamescope-embedded`** and a tiny systemd generator that writes `/etc/ai-control/gfx.conf` consumed by pe-loader.
3. **Keep X11 as the default for 2026**. XFCE Wayland is not ready, and we don't want to break users who boot on a 2010 ThinkPad.
4. **Ship a `game.launch_gamescope(exe, flags)` handler** in `ai-control/daemon/contusion_handlers.py`. The building blocks are already there — GameScope is installed and mature.

**Defer to Session 74+**:
- Phase 2 Wayland (pointer + resize)
- xfce4-wayland (labwc) as optional DE spin
- `gfx_wayland_fractional_scale()` when a real 2026 high-DPI laptop is tested

**Don't do**:
- Rip X11 out. Not yet. Probably not through 2027.
- Rewrite pe-loader to libwayland-only. The abstraction is correct.
- Ship a KDE-Wayland default. KWin is huge and will dominate the image; XFCE stays the ARCHWINDOWS look-and-feel.

---

## Sources (2024-2026)

- [KDE MegaRelease 6 (2024-02-28)](https://kde.org/announcements/megarelease/6/)
- [KDE Plasma 6 — Wikipedia](https://en.wikipedia.org/wiki/KDE_Plasma_6)
- [Plasma 6.2 announcement (HDR color mgmt default)](https://kde.org/announcements/plasma/6/6.2.0/)
- [KDE Plasma 6.5.3 multi-monitor VRR (9to5Linux, 2025-11)](https://9to5linux.com/kde-plasma-6-5-3-improves-visual-smoothness-on-multi-monitor-vrr-setups)
- [KDE is going Wayland-only (gHacks, 2025-11-28)](https://www.ghacks.net/2025/11/28/kde-is-going-wayland-only-in-the-future/)
- [GNOME 48 Release Notes (March 2025)](https://release.gnome.org/48/)
- [GNOME 48 RC — dynamic triple buffering + Wayland color mgmt (9to5Linux)](https://9to5linux.com/gnome-48-rc-adds-dynamic-triple-buffering-wayland-color-management-protocol)
- [GNOME X11 Session Removal FAQ (2025-06-23)](https://blogs.gnome.org/alatiera/2025/06/23/x11-session-removal-faq/)
- [GNOME 50 goes Wayland-only — XDA](https://www.xda-developers.com/gnome-50-goes-wayland-only-alpha-build-scraps-x11-backend/)
- [Fedora 43 drops GNOME X11 (Fedora Magazine / LWN)](https://lwn.net/Articles/1043785/)
- [Xfce 4.20 Release Tour](https://www.xfce.org/about/tour420)
- [Xfce Wayland Roadmap (wiki)](https://wiki.xfce.org/releng/wayland_roadmap)
- [Xfce 4.20 Experimental Wayland (9to5Linux)](https://9to5linux.com/xfce-4-20-desktop-environment-released-with-experimental-wayland-support)
- [Hyprland 0.50 release (2025-07)](https://hypr.land/news/update50/)
- [Hyprland 0.53 release (2025-12)](https://hypr.land/news/update53/)
- [Hyprland Performance wiki](https://wiki.hypr.land/Configuring/Performance/)
- [niri (scrollable-tiling Wayland compositor)](https://github.com/niri-wm/niri)
- [Archinstall adds labwc/niri/river (2025-05)](https://9to5linux.com/arch-linux-installer-now-supports-labwc-niri-and-river-wayland-compositors)
- [Arch Wiki — Wayland](https://wiki.archlinux.org/title/Wayland)
- [Arch Wiki — Gamescope](https://wiki.archlinux.org/title/Gamescope)
- [Arch Wiki — Variable refresh rate](https://wiki.archlinux.org/title/Variable_refresh_rate)
- [Arch Wiki — HDR monitor support](https://wiki.archlinux.org/title/HDR_monitor_support)
- [ValveSoftware/gamescope repo](https://github.com/ValveSoftware/gamescope)
- [gamescope#1957 — Nested VRR broken on Hyprland](https://github.com/ValveSoftware/gamescope/issues/1957)
- [Linux 6.8 — AMD HDR & Raspberry Pi 5 (Maíra Canal)](https://mairacanal.github.io/linux-6-8-AMD-HDR-and-raspberry-pi-5/)
- [DRM Color Pipeline API merged to drm-misc-next (Medium, Can Artuc)](https://canartuc.medium.com/drm-color-pipeline-api-and-hdr-on-linux-the-long-road-to-proper-display-color-management-539d56acaa33)
- [NVIDIA DRM Per-Plane Color Pipeline preview (GamingOnLinux, 2026-04)](https://www.gamingonlinux.com/2026/04/nvidia-announce-a-preview-of-drm-per-plane-color-pipeline-api-support-on-linux-good-for-hdr/)
- [Linux 6.19 Kernel: HDR, Gaming Handhelds (Can Artuc)](https://canartuc.medium.com/linux-6-19-kernel-hdr-gaming-handhelds-and-why-hardware-finally-gets-serious-support-dfd1ac36718d)
- [Wayland protocol — wp_fractional_scale_v1](https://wayland.app/protocols/fractional-scale-v1)
- [Wayland protocol — xdg_shell](https://wayland.app/protocols/xdg-shell)
- [libwayland in depth (wayland-book.com)](https://wayland-book.com/libwayland.html)
- [Wayland vs X11 AMD (dedoimedo, benchmarks)](https://www.dedoimedo.com/computers/wayland-vs-x11-performance-amd-graphics.html)
- [4 reasons I switched from X11 to Wayland — XDA](https://www.xda-developers.com/reasons-wayland-better-than-x11/)
- [ArchLinux forums — Intel GMA 3150 driver](https://bbs.archlinux.org/viewtopic.php?id=131421)
- [ArchLinux forums — ThinkPad T61 reviving with Arch](https://bbs.archlinux.org/viewtopic.php?id=310154)
- [ArchLinux forums — Moving on from X11](https://bbs.archlinux.org/viewtopic.php?id=307134)
- [Fedora Changes/WaylandOnlyGNOME](https://fedoraproject.org/wiki/Changes/WaylandOnlyGNOME)
- [Hyprland gamescope features discussion #10557](https://github.com/hyprwm/Hyprland/discussions/10557)
