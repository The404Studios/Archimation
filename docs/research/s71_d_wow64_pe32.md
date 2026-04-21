# S71 Research Report D — WoW64 / PE32 Support for ARCHWINDOWS

**Agent:** Research Agent D
**Date:** 2026-04-20
**Session:** 71
**Angle:** What it would take to add WoW64 / 32-bit PE32 support to the pe-loader.

---

## 400-word Executive Summary

ARCHWINDOWS's `pe-loader` is x86_64-only today. `pe-loader/loader/main.c:336-343` rejects any PE with `optional_magic == 0x010B` (PE32 / i386) and prints "Try running this through Wine." The rejection is architecturally correct — our 64-bit process cannot directly execute 32-bit x86 code without mode-switching — but it cuts off a meaningful segment of the Windows software corpus: every VB6 binary (no 64-bit IDE ever existed), every pre-2010 commercial game built for 32-bit Windows, a large slice of Delphi/Builder applications, and most retro titles. Whether this is "big" depends on how you measure. Steam Hardware Survey 2025 shows only **0.01% of players on 32-bit Windows 10** and Valve is ending 32-bit Steam support in January 2026 — so 32-bit *operating systems* are dead. But 32-bit *applications* running under 64-bit WoW64 are still shipped constantly; PCGamingWiki maintains a page of 32-bit Windows games covering Win95 through Win10, and anything built before about 2008 is commonly 32-bit-only.

Microsoft's native WoW64 runs `wow64.dll` + `wow64cpu.dll` + `wow64win.dll` in every 32-bit-on-64-bit process: 32-bit `ntdll` stubs jump through the "Heaven's Gate" far-jmp to CS=0x33 to switch the CPU to long mode, the thunks in `wow64.dll` extend 32-bit parameters to 64-bit and issue the real syscall, then the CPU returns to CS=0x23 for 32-bit execution. Wine 9.0 (Jan 2024) shipped the first "new WoW64" Unix equivalent; Wine 11.0 (Jan 2026) made it feature-complete and the default, dropping the separate `wine64` binary. Wine's approach: 32-bit PE modules call into a set of generated WoW64 thunks that convert 32→64-bit arguments before invoking the single 64-bit `ntdll.so` Unix library. Performance is reduced for 32-bit OpenGL workloads but most applications run.

For ARCHWINDOWS, three options present. **(a)** Full native PE32 with our own Heaven's-Gate and thunks is 8-12 sessions (~15,000 LOC), duplicates Wine's core work, and primarily exists to say we did it. **(b)** A PE32→Wine handoff shim that detects `magic==0x010B` and execs `wine` with trust-gating via `libtrust_wine_shim.so LD_PRELOAD` is ~1-2 sessions (~400 LOC) and inherits Wine's 25-year compatibility corpus. **(c)** Continue refusing and document it. **Recommendation: option (b).** It matches S64/S65's "no-Wine-for-native-paths but Wine-for-compatibility" hybrid and respects the user's "don't want Wine" boundary by keeping Wine strictly as a PE32 *fallback* (not the default path for 64-bit binaries).

---

## 1. Why 32-bit Still Matters in 2026

**The operating-system question (dead):** Steam Hardware Survey 2025 shows 32-bit Windows 10 at 0.01% of users. Microsoft ended Windows 10 32-bit support on 2024-09-30. Windows 11 is 64-bit-only. Valve is removing Steam client support for 32-bit Windows on 2026-01-01.

**The application question (very much alive):**
- **Visual Basic 6:** No 64-bit VB6 IDE ever shipped. Every VB6 program ever compiled is 32-bit PE. Microsoft's support statement explicitly acknowledges VB6 binaries still run under WoW64 on modern Windows. (Extended runtime support continues indefinitely on Windows 10/11 via WoW64.)
- **Delphi (pre-XE2, 2011):** Every Delphi binary compiled before XE2 is 32-bit-only. This covers a huge historical corpus of business software, shareware, and games (including everything built with Game Maker 5.3 and earlier, which was written in Delphi).
- **Games built before ~2008:** Broadly 32-bit-only. PCGamingWiki's "List of Windows 32-bit only games" enumerates hundreds of titles (Half-Life 2 original, Doom 3 original, Metro 2033, Left 4 Dead 2, BioShock 1, entire GOG.com retro catalog). The Steam Curator "32-bit gamers" page exists specifically to track games playable on 32-bit-capable binaries.
- **Industrial/scientific software:** Custom lab tools, SCADA interfaces, device driver utility apps, and old IDE/debugger toolchains are overwhelmingly 32-bit.

**The user audit said "every pre-2010 game, Delphi/VB6 apps, ~half of retro titles."** That matches the evidence. Estimating a percentage: probably 0% of *new* commercial Windows software in 2026 is 32-bit-only, but roughly 30-50% of the pre-2015 Windows software corpus is 32-bit-only — and that corpus is what "Windows compatibility" actually means to most users who need Windows compatibility at all.

## 2. How Windows Itself Does WoW64

Source: Microsoft Learn, "WOW64 Implementation Details" (2025-04-15 revision).

### DLL composition
Every 32-bit process on 64-bit Windows has exactly four 64-bit modules loaded above the 32-bit limit:
- **`ntdll.dll` (64-bit)** — the real kernel gate.
- **`wow64.dll`** — core emulation infrastructure; thunks for `ntoskrnl` entry points.
- **`wow64win.dll`** — thunks for `win32k.sys` (GDI/USER entry points).
- **`wow64cpu.dll`** (x64 only) — mode-switching primitives (the Heaven's Gate jumps).

Plus the entire 32-bit DLL set (`C:\Windows\SysWOW64\*.dll` — confusingly named, these are the **32-bit** system DLLs; `C:\Windows\System32` is 64-bit). 32-bit DLLs are unmodified copies of 32-bit Windows binaries, except a handful that are CHPE (Compiled Hybrid PE) on ARM64.

### Heaven's Gate mechanism (x86_64)
1. 32-bit code runs with CS=0x23 (compatibility-mode segment).
2. 32-bit `ntdll` does **not** issue `int 2e` / `syscall` directly. Instead it calls through `fs:[0xC0]` (the 32-bit TEB's WOW32Reserved field), which was set at thread init to `wow64cpu!KiFastSystemCall`.
3. `KiFastSystemCall` issues a far jmp to CS=0x33 — the long-mode code segment. This is Heaven's Gate.
4. Now in 64-bit mode, the code is in `wow64cpu.dll` → `wow64.dll`, which extracts 32-bit args from the old stack, sign/zero-extends them to 64-bit, and issues the real `syscall`.
5. On return, the inverse jmp back to CS=0x23 resumes 32-bit execution.

### Thunking
`wow64.dll` maintains four service tables. Each entry maps a 32-bit syscall number to a `wh*` thunk function. The thunk receives a pointer to the 32-bit argument array, walks structures (handles pointer width — 4 vs 8 bytes — plus `ULONG_PTR`/`SIZE_T`/`HANDLE` which change width), reallocates them in 64-bit form on the 64-bit stack, and fires the syscall. **Turbo thunks** are an x64 fast-path: for trivially-shaped syscalls (no pointer args, no structures), `wow64cpu` dispatches via a jump table indexed by `eax` without entering `wow64.dll` at all.

### Key constraint: all user address space above 0xFFFFFFFF is reserved by the system, so 32-bit code cannot accidentally dereference a 64-bit pointer as a 32-bit value.

## 3. How Wine Does 32-bit PE on 64-bit Linux

### Timeline
- **Wine 1.x-8.x (pre-2024)**: "Old WoW64" — 32-bit applications ran inside a **32-bit Unix process**, requiring lib32-* multilib everywhere, a separate 32-bit `wine` loader (`wine32`), and a 32-bit `wineprefix` or a mixed 32+64 prefix. Cost: every system library duplicated (glibc, X11, OpenGL, Vulkan...).
- **Wine 9.0 (2024-01)**: "New WoW64" first shipped as opt-in. 32-bit PE modules run inside the **64-bit Unix process** with 64-bit Unix libraries; 32-bit PE ↔ 64-bit Unix is bridged by generated thunks. OpenGL and some other paths had perf regressions, Wayland driver was experimental. Not default.
- **Wine 10.0 (2025-01)**: WoW64 hardening, more apps working. Still not default for distros wanting stability.
- **Wine 11.0 (2026-01-13)**: New WoW64 is feature-complete and **the default**. Single unified `wine` loader (no more separate `wine64`). Adds 16-bit app support via new WoW64. Arch Linux shifted to pure-WoW64 Wine builds following this.

### Architecture
All Wine modules that call Unix libraries are compiled as PE and provided with WoW64 thunks. The stack at a 32-bit→Unix call looks like:
```
32-bit PE code  →  win-thunk (PE, 32-bit)  →  WoW64 thunk (PE, 64-bit)  →  ntdll.so (ELF, 64-bit)  →  Linux syscall
```
Each "Unix call" crosses the 32→64 boundary via a far-jmp to a 64-bit PE code segment (Wine's own Heaven's Gate equivalent — implemented in user space without kernel help because Linux does not reserve CS=0x33 for this purpose, so Wine manages its own LDT/GDT entry via `modify_ldt(2)`).

### LOC estimate (Wine)
Wine's main WoW64 implementation lives in `dlls/wow64/`, `dlls/wow64win/`, `dlls/wow64cpu/`, and generated thunk code scattered through every `dlls/*/` module. The thunks are largely auto-generated by `tools/make_requests` from Wine's IDL/spec files. Rough order-of-magnitude estimate based on the tree: **30,000-50,000 hand-written LOC for the core + multiple hundreds of thousands of generated thunk lines**. Wine 11.0 release notes say ~6,300 individual changes across the release cycle with WoW64 being one of the two main highlights.

Key mainline milestones (best effort; exact SHAs require cloning `gitlab.winehq.org/wine/wine`):
- Initial new-WoW64 work landed 2022-2023 across hundreds of commits by Alexandre Julliard and Jacek Caban.
- Feature parity achieved in the 10.x cycle.
- 11.0 release marked "complete" 2026-01-13.

## 4. How ReactOS Handles the Boundary

**It doesn't.** ReactOS is a 32-bit x86 operating system; there is no 64-bit ReactOS in any shipping form. There is no boundary to handle: everything is 32-bit PE running on a 32-bit kernel. ReactOS's PE loader is instructive to read (clean NT-style reference implementation in `reactos/ntoskrnl/mm/ARM3/section.c` and `dll/ntdll/ldr/`), but it doesn't solve our problem.

## 5. Can Linux Run a 32-bit Process on a 64-bit Kernel?

**Yes — but not how we need it.** Linux supports 32-bit x86 processes on a 64-bit kernel via `CONFIG_IA32_EMULATION`, which enables:
- The 32-bit syscall ABI path (`int 0x80` and `sysenter`).
- Compatibility syscall thunks in the kernel (`arch/x86/entry/syscalls/syscall_32.tbl` → compat wrappers that extract 32-bit args, pad/extend, call the 64-bit syscall).
- `execve` of 32-bit ELF sets CS=0x23 and maps the process in the lower 4GB.

Arch Linux kernels ship with `CONFIG_IA32_EMULATION=y` and the multilib repo provides 32-bit userspace libraries (`lib32-glibc`, `lib32-libx11`, etc.) in `/usr/lib32`. So a 32-bit ELF **does** run. However, our PE loader is a 64-bit ELF, and Linux does not let a process switch ABIs mid-execution; we cannot start in 64-bit mode, do setup, then become 32-bit. We would either need to:
- Spawn a separate 32-bit ELF loader binary (`peloader32`) that `exec`s instead of our 64-bit `peloader` when it sees magic 0x010B, **or**
- Implement Heaven's Gate in user space (Wine's approach) via `modify_ldt(2)` to create a CS=0x33-equivalent segment.

`MAP_32BIT` exists but only constrains mappings to the low 2GB, which is useful (we'd want all 32-bit PE sections there) but does not by itself enable 32-bit code execution in a 64-bit process.

## 6. Cost Estimate to Add PE32 Support (Three Options)

### Parser status (good news)
The parser **already handles PE32**. `pe-loader/include/pe/pe_header.h` defines both `pe_optional_header32_t` (magic 0x010B) and `pe_optional_header64_t` (magic 0x020B). `pe-loader/loader/pe_parser.c:229-278` parses PE32 headers into the same normalized `pe_image_t`. `image->is_pe32plus` is set correctly. The rejection is downstream in `main.c:336-343` — a policy choice, not a parser limitation.

### Option (a): Full native PE32 support
What it takes:
1. **Separate 32-bit ELF binary** `peloader32` compiled with `-m32`, built via Arch multilib toolchain. Dispatch from `peloader` main via `execvp` when `!image.is_pe32plus`. [~500 LOC + Makefile refactor, ~0.5 sessions]
2. **Or:** in-process Heaven's Gate via `modify_ldt(2)` to install a compatibility segment, plus hand-rolled transition trampolines written in assembly. [~2,500 LOC, ~2-3 sessions, dragons]
3. **32-bit DLL stubs:** Rebuild all 40+ `libpe_*.so` as `libpe_*.so.32` in `/usr/lib32/pe-compat/`. Means every DLL stub source file gets compiled twice (`-m32` variant) and 5-path search order extended. [~2,000 LOC of Makefile + per-DLL `size_t`/pointer fixes, ~1-2 sessions]
4. **Thunks:** Our `abi_thunk.S` is SysV-x64↔MS-x64. A 32-bit variant needs a full new thunk family: SysV-i386 cdecl↔MS stdcall, plus fastcall, plus thiscall. Plus varargs (PE32 `__cdecl` callers push args onto the stack which the callee does not clean). [~4,000 LOC of assembly + C glue, ~2 sessions]
5. **Import resolver adaptations:** Pointer-size changes ripple through `pe_import.c` (`IMAGE_THUNK_DATA32` vs 64, IAT entries are 32-bit). [~1,500 LOC of `#ifdef` branches or a templated separate `pe_import32.c`, ~1 session]
6. **Relocation deltas** for a 32-bit image live in the low 2GB, so `MAP_32BIT` must be passed to `mmap` for section mapping and subsequent heap allocs. [~300 LOC changes, ~0.3 sessions]
7. **CRT wrapper table:** ~120 ms_abi wrappers in `pe_find_crt_wrapper` become ~120 stdcall/cdecl wrappers for 32-bit. [~1,000 LOC, ~0.5 sessions]
8. **Trust/cortex integration:** `cortex_request_pe_load` works, but the per-process `trust_subject_t` model and 64-bit handle values need 32-bit mirrors. [~800 LOC, ~0.5 sessions]
9. **Tests:** Extend PE corpus (currently 15 PE32+ binaries built with MinGW-w64) to include 10-15 PE32 binaries built with i686-w64-mingw32. [~500 LOC, ~0.3 sessions]
10. **Debugging grind:** Every Windows struct containing `HANDLE`, `SIZE_T`, `ULONG_PTR`, `LPARAM`, `WPARAM`, `LONG_PTR` has a different in-memory layout between PE32 and PE32+. ~20 of our 40 DLL stubs touch such structs. Each needs audit + parametric `#ifdef`. **This is the real cost** — at least 2-4 full sessions of whack-a-mole on obscure crashes in random apps.

**Total: 8-12 sessions, ~15,000 LOC of new/modified code, extended test corpus.** And at the end of it, we have what Wine already ships and has debugged for two decades.

### Option (b): PE32 → Wine handoff shim [RECOMMENDED]
What it takes:
1. **Detection:** Existing code at `main.c:336-343` already identifies PE32. Change from "print and exit 66" to "exec `/usr/bin/wine` with the original argv." [~50 LOC, ~15 minutes]
2. **Trust-gated Wine:** `libtrust_wine_shim.so` compiled as a `LD_PRELOAD` shim for the Wine process, hooking `ntdll.so` entry points to consult the trust kernel before letting the syscall proceed — same `cortex_request_pe_load` / `trust_gate_check` semantics as our native loader. Preserves the "every PE load goes through trust" invariant. [~300 LOC, ~0.5 sessions]
3. **Packaging:** Add `wine` to `profile/packages.x86_64` (already implicit dependency for PE compat in the S64 audit), pin to Wine 11.0+. [~5 LOC, negligible]
4. **UX:** Replace the "Try running this through Wine" message with a one-line prefix explaining what happened, then just run. [~20 LOC]
5. **Tests:** Add 3-5 PE32 binaries to the corpus that are expected to go through the Wine path. Gate on wine presence. [~200 LOC, ~0.3 sessions]

**Total: 1-2 sessions, ~600 LOC.** User experience: drop-in — user double-clicks `oldgame.exe`, binfmt_misc fires peloader, peloader sees PE32, execs wine, game runs. Trust kernel still sees the PE load event because `libtrust_wine_shim` intercepts at `ntdll.so` boundary. Matches S64 audit recommendation exactly.

### Option (c): Keep refusing
No code change. Document it in `docs/pe-compat.md` and `docs/architecture.md`. Update the error message at `main.c:336-343` to be more explicit about the user's alternatives (copy the relevant text from this report into the help output).

**Total: 0.1 sessions.** Honest but cedes a meaningful fraction of the Windows software corpus.

## 7. Alternative: box64/box86

Box86/Box64 are ARM-focused userspace x86 emulators — they exist to run x86 binaries on ARM/RISC-V/LoongArch, not to run x86-32 on x86-64. On an x86_64 Arch Linux machine, box86 would translate x86→x86 (pointless) or box64 would translate x86_64→x86_64 (also pointless). Neither solves our case. The Box86/Box64 team's own documentation says they're used *in conjunction with* Wine on non-x86 hosts, not as a Wine alternative on x86. Rejected.

## 8. Files to Read (Project Pointers)

Confirmed from inspection (all paths absolute within project root):
- `pe-loader/loader/main.c:336-343` — the rejection site to change.
- `pe-loader/loader/pe_parser.c:229-278` — already handles PE32 magic 0x010B; the normalized `pe_image_t` is agnostic. No parser changes needed for either option.
- `pe-loader/include/pe/pe_header.h:48-82` — `pe_optional_header32_t` already defined.
- `pe-loader/include/pe/pe_header.h:138` — `image->is_pe32plus` flag.
- `pe-loader/loader/pe_mapper.c:88-112` — where to add `MAP_32BIT` for option (a).
- `pe-loader/loader/pe_relocator.c:19-49` — relocation delta computation, works for both.
- `pe-loader/loader/pe_import.c:1-80` — import resolver; the heaviest option-(a) rewrite site.
- `pe-loader/loader/abi_thunk.S:1-178` — x64 thunks; need 32-bit sibling for option (a).
- `pe-loader/Makefile:31-634` — DLL build stanzas; ~40 `libpe_*.so` would need 32-bit variants for option (a).

## 9. Old Hardware Fit

- **Actual 32-bit-only x86 CPUs (Pentium 4 pre-EMT64, Pentium M, old Atom):** Don't boot ARCHWINDOWS at all — we require x86_64. Out of scope.
- **64-bit CPUs running 32-bit OS (rare today):** Also out of scope.
- **Modern low-end hardware running 64-bit OS that wants to run old 32-bit apps:** This is the actual use case. Option (b) fits perfectly — the device has 64-bit capability, just needs a path for 32-bit PE input.

## 10. New Hardware Fit

No loss. Native 64-bit PE remains the fast path with full trust-kernel integration. PE32 is handled via the Wine fallback with trust-shim, preserving the trust invariant. Users get broader compatibility with no regression on the 64-bit path.

## 11. Recommendation

**Implement option (b) in 1-2 sessions.** Rationale:

1. **User intent respected:** The user in S64/S65 explicitly said "we don't want wine." That rejection was about using Wine for things we can do ourselves (Win32 API emulation for 64-bit binaries). Using Wine for PE32 is different — it's using Wine for a thing we **cannot** do ourselves without reinventing 15,000 LOC of mode-switching, dual-ABI thunks, and two-decade debugging. Keeping Wine strictly as a PE32 *fallback* (never touched for 64-bit binaries) is consistent with the user's position.

2. **Trust-gating preserved:** `libtrust_wine_shim.so LD_PRELOAD` means every Wine-handled PE32 still flows through `cortex_request_pe_load` and `trust_gate_check`. The trust-mediated execution invariant holds. This is what S64's A2 agent recommended verbatim.

3. **Cost/benefit:** Option (a) costs 8-12 sessions to duplicate solved work with no differentiation. Option (b) costs 1-2 sessions to reach full PE32 coverage. Ratio: ~6x cheaper for the same user-observable capability.

4. **Measurable:** After option (b), extend `tests/pe/corpus/` to include PE32 binaries (5-10 small i686-w64-mingw32-built test programs, similar to our current 15 PE32+ binaries). Test that routing detects PE32, execs Wine, Wine runs them, trust-shim fires, exit codes preserved. This becomes a verifiable smoke test in `scripts/test-ai-commands.sh`.

5. **Reversibility:** If at some future session we want to implement option (a) natively, option (b)'s shim is not in conflict — the shim only fires when the native loader says "PE32." Option (a) can be added later by replacing the exec-wine branch with an `exec /usr/bin/peloader32` branch.

**Concrete S72 work plan (1-2 sessions):**
- Session 1: Replace `main.c:336-343` reject with wine exec. Write `libtrust_wine_shim.so` (~300 LOC) hooking `NtOpenFile`/`NtCreateSection`/`LdrLoadDll` to call `cortex_request_pe_load` + `trust_gate_check` before letting them proceed. Add wine to packages.x86_64. Update `docs/pe-compat.md`.
- Session 2: Extend PE corpus with PE32 binaries (hello32.exe, console_mini32.exe, mfc42_basic32.exe, delphi_hello32.exe built via cross-compile or shipped prebuilt binaries). Add pytest integration. Update `scripts/test-ai-commands.sh`.

**The one thing to watch:** on Arch Linux, Wine 11.0+ has dropped WINEARCH=win32; so 32-bit binaries now go through the new WoW64 path automatically. No special invocation needed — just `wine foo.exe` — but we should pin `wine>=11.0` in PKGBUILD to avoid the old-WoW64 multilib dependency cascade.

---

## Sources

- [WOW64 Implementation Details - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/winprog64/wow64-implementation-details)
- [WINE 9.0 brings better WoW64 support - The Register](https://www.theregister.com/2024/01/18/wine_90_is_out)
- [Wine 9.0 Released with Experimental Wayland Driver - OMG! Ubuntu](https://www.omgubuntu.co.uk/2024/01/wine-9-0-released-with-new-wow64-mode-experimental-wayland-driver)
- [Wine 11.0 Brings Fully Supported WoW64 Mode - Linuxiac](https://linuxiac.com/wine-11-0-brings-fully-supported-wow64-mode/)
- [Arch Linux Shifts to Pure WoW64 Builds for Wine - Linuxiac](https://linuxiac.com/arch-linux-shifts-to-pure-wow64-builds-for-wine-and-wine-staging/)
- [Wine Architecture Overview - WineHQ GitLab Wiki](https://gitlab.winehq.org/wine/wine/-/wikis/Wine-Developer's-Guide/Architecture-Overview)
- [WoW64 internals - mindless-area](https://wbenny.github.io/2018/11/04/wow64-internals.html)
- [Hooking Heaven's Gate - a WOW64 hooking technique - Medium](https://medium.com/@fsx30/hooking-heavens-gate-a-wow64-hooking-technique-5235e1aeed73)
- [Closing "Heaven's Gate" - Alex Ionescu's Blog](https://www.alex-ionescu.com/closing-heavens-gate/)
- [Deep dive into WOW64 - Sogeti ESEC Lab](http://esec-lab.sogeti.com/posts/2016/09/12/deep-dive-wow64.html)
- [Steam Hardware & Software Survey](https://store.steampowered.com/hwsurvey/)
- [Valve ends Steam support for 32-bit Windows from 2026 - TechBriefly](https://techbriefly.com/2025/09/19/valve-ends-steam-support-for-32-bit-windows-from-2026/)
- [Support Statement for Visual Basic 6.0 on Windows - Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/visualstudio/visual-basic-6/visual-basic-6-support-policy)
- [List of Windows 32-bit games - PCGamingWiki](https://www.pcgamingwiki.com/wiki/List_of_Windows_32-bit_games)
- [Steam Curator: 32-bit gamers](https://store.steampowered.com/curator/31982166-32-bit-gamers/)
- [Box86 / Box64 official site](https://box86.org/)
- [Box86 GitHub](https://github.com/ptitSeb/box86)
- [x86 calling conventions - Wikipedia](https://en.wikipedia.org/wiki/X86_calling_conventions)
- [Linux mmap(2) manual page - MAP_32BIT](https://man7.org/linux/man-pages/man2/mmap.2.html)
- [Arch Linux multilib - ArchWiki](https://wiki.archlinux.org/title/Official_repositories)
