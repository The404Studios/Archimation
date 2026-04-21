# S74 Agent V — QEMU ISO Build + Full Smoke Verification

**Date:** 2026-04-20
**Agent:** V (QEMU verify — redo of P who no-op'd)
**Git HEAD at start:** `b94b346` (agent-T Monte Carlo cortex skeleton)
**Git HEAD with K integration:** `d43f31e` (agent-K verify + research-derived fixes)
**Scope:** Synchronous ISO build + 7-point smoke + set_smoke + PE corpus + v2 smoke.

---

## Executive Summary

**Recommendation: FIX-BEFORE-SHIP.**

- ISO builds clean (2.2 GB, 453 s) with all S74 Agent-K packages.
- 7-point QEMU smoke is green (25 PASS / 0 FAIL / 1 WARN / 4 SKIP of 30 points) — matches historical baseline.
- set_smoke is a clean sweep (33/33 phrases / 13 GREEN / 0 YELLOW / 0 RED) — matches S67/S68 best-ever.
- PE corpus is a clean sweep (16 PASS / 0 FAIL / 2 SKIP of 18) — matches S67/S69 baseline exactly.
- **v2 smoke REGRESSED from S63 baseline: 0/42 routed, 0/42 v2_template (S63 was 42/42 routed, 26/42 v2_template).**

The v2 smoke regression is a real functional miss: `dictionary_v2` long-tail routing is not firing on the live ISO. Exact-match phrases (set_smoke) still route correctly via the static `contusion_dictionary`, so user-facing short-form commands work, but the 6989-phrase compiled template index (S63's 10K-expansion work) is dark.

The one-line-fix to `scripts/v2_smoke_run.sh` (serial-log truncation + SSH retry loop) is a script-quality bug that masked the real issue; even after fixing the script, v2 routing on the guest shows 0/42.

**Ship blocker: v2 routing regression needs a root-cause fix before release.** Everything else is green. Core daemon + trust kernel + PE loader + routing are healthy; only the dictionary_v2 long-tail fast-path is dark.

---

## Step-by-step results

### Step 1 — K integration confirmed

```
b94b346 S74: agent-T Monte Carlo cortex skeleton
d43f31e S74 integration: agent-K verify + research-derived fixes
6e751f5 S74 prep: agent-Q QEMU env readiness audit
d043482 S74 docs: paper-vs-impl + architecture-invariants + theorem-harness spec
f51a13d S74: agent-O S75 roadmap + strategic handoff
```

HEAD is b94b346 (T landed Monte Carlo ON TOP of d43f31e). All Agent-K changes are in the tree at SHA `d43f31e`.

### Step 2 — Package inventory

All Agent-K target pkgrels present:

```
ai-control-daemon-0.1.0-24-any.pkg.tar.zst
ai-desktop-config-0.2.0-31-any.pkg.tar.zst
ai-firewall-0.1.0-1-any.pkg.tar.zst
ai-first-boot-wizard-0.1.0-2-any.pkg.tar.zst
pe-compat-dkms-0.1.0-1-x86_64.pkg.tar.zst
pe-loader-0.1.0-9-x86_64.pkg.tar.zst
trust-dkms-0.1.0-8-x86_64.pkg.tar.zst
trust-system-0.1.0-2-x86_64.pkg.tar.zst
windows-services-0.1.0-6-x86_64.pkg.tar.zst
```

9 packages total (unchanged from Q's pre-K baseline — K bumped pkgrels in place of adding new packages). `wine-shim` is **missing from repo/x86_64/** as Q warned — it failed to build due to `-fPIC` issue. Not blocking ISO build.

### Step 3 — `wine-shim` requirement check

```
grep -n 'wine.shim\|libtrust.wine' profile/packages.x86_64
# → no matches; wine-shim not required by profile
```

**Safe to proceed without wine-shim.** No one-line edit was needed in packages.x86_64. Flag for S75: finish wine-shim PKGBUILD `-fPIC` fix so it's shippable.

### Step 4 — ISO build

```bash
bash scripts/build-iso.sh
```

- Output: `output/archwindows-2026.04.20-x86_64.iso`
- Size: **2.2 GB** (expected)
- SHA256: **a80f5fdac371b273abefefe581014a49bb0e1f8d2dd645958a5087a9eec5d2d7**
- Build time: **453 s** (mkarchiso main step) + pre/post = ~8 minutes total
- No retry needed; clean build first try
- Log: `logs/s74_agent_v_iso_build.log` (200 KB, 8k+ lines)

### Step 5 — ISO confirmed

Already listed in Step 4. The 04.19 and 04.20 (earlier) ISOs are pre-K; the new 04.20-19:10 ISO is post-K.

### Step 6 — 7-point QEMU smoke (30 checks)

```
Passed:  25
Failed:  0
Warned:  1
Skipped: 4
TOTAL:   30 tests
OVERALL: PASS
```

| # | Check | Result | Note |
|---|---|---|---|
| 1 | SSH port 2222 | **PASS** | |
| 1b | SSH login | **PASS** | arch |
| 2 | AI Daemon running | **PASS** | active |
| 3 | AI Daemon /health | **PASS** | port 8420 open after 1s, full health JSON |
| 4 | /system/info | **PASS** | |
| 5 | Boot sequence | **PASS** | Network target reached |
| 6 | Key services | **PASS** | NM:OK SSH:OK LightDM:OK |
| 7 | Custom services | **PASS** | scm-daemon:OK pe-objectd:OK ai-control:OK |
| 8 | /health JSON status:ok | **PASS** | |
| 9 | peloader binary | **PASS** | |
| 10 | NetworkManager | **PASS** | NM:active, connectivity:full |
| 11 | Contusion engine | **PASS** | |
| 12 | WiFi API | **PASS** | |
| 13 | Pattern scanner | **PASS** | |
| 14 | Memory observer | **PASS** | |
| 15 | Dashboard | **PASS** | |
| 16 | ai-assist CLI | **PASS** | v3.0 |
| 17 | PE binfmt | **PASS** | |
| 18 | XFCE panel | **SKIP** | headless: no DISPLAY |
| 19 | PE binfmt magic 4d5a | **PASS** | |
| 20 | /sys/kernel/trust/stats | **SKIP** | trust.ko not loaded (DKMS needs kernel headers, expected in QEMU) |
| 21 | lsmod trust | **SKIP** | same as 20 |
| 22 | SCM service stop/start | **PASS** | stopped:inactive then active |
| 23 | pe-objectd socket | **PASS** | runtime dir exists |
| 24 | Registry SOFTWARE hive | **PASS** | |
| 25 | Firewall cgroup (pe-compat.slice) | **WARN** | firewall active but pe-compat.slice dir missing |
| 26 | Coherence daemon | **PASS** | svc:active |
| 27 | AI Cortex (svc + :8421) | **PASS** | svc:active :8421 /health ok |
| 28 | WatchdogSec heartbeats | **SKIP** | no watchdog lines yet |
| 29 | systemd-analyze verify | **PASS** | non-fatal notices only |
| 30 | /system/summary rollup | **PASS** | |

**Comparison to S69 pkg-23 baseline (26/0/1WARN/3SKIP of 30):** essentially identical. We have 25 PASS / 1 WARN / 4 SKIP this time — one more SKIP because watchdog wiring hasn't landed (test 28), but that's a notice, not a regression. All services that were green stay green.

**Red flag (minor):** Test 25 — firewall active but `pe-compat.slice` dir missing. Same warning as historical runs. Not ship-blocking but worth a dedicated fix in a future session.

Log: `logs/s74_agent_v_qemu_smoke.log`

### Step 7 — set_smoke (13 capability sets, 33 phrases)

```
TOTAL: 33/33 phrases routed
SETS:  GREEN=13  YELLOW=0  RED=0 (of 13)

  BRIGHTNESS        5/5  status=GREEN
  AUDIO             4/4  status=GREEN
  MEDIA             5/5  status=GREEN
  POWER             2/2  status=GREEN
  SYSTEM            3/3  status=GREEN
  MONITORING        4/4  status=GREEN
  WINDOW            1/1  status=GREEN
  WORKSPACE         1/1  status=GREEN
  SERVICE           1/1  status=GREEN
  DRIVER            1/1  status=GREEN
  SCRIPT            3/3  status=GREEN
  APP_CLAUDE        2/2  status=GREEN
  GAME              1/1  status=GREEN
```

**Matches S67/S68 best-ever baseline (33/33 / 13 GREEN).** Zero regression, first-try pass. APP_CLAUDE (historically the 10s-probe flake) completed green — asyncio.gather fix from S67 A3 held.

Artifacts:
- `logs/s74_agent_v_set_smoke.log` (control log — contains stray duplicate MOTD banners)
- `logs/s74_agent_v_set_smoke.json` (authoritative JSON result, 9981 bytes)

**Note on set_smoke script:** The `ai_impressive_demo.py` piggyback (post-set_smoke) hung at ~19:22 and was manually killed at ~19:32 after the core set_smoke JSON had already been captured. This doesn't affect the set_smoke result — the JSON was already complete. It suggests the impressive_demo probe has an SSH timeout issue under TCG load, worth checking in a future session, but is orthogonal to the ship decision.

### Step 8 — PE corpus

```
--- Running corpus ---
  [PASS] console_hello.exe
  [PASS] console_files.exe
  [PASS] console_threads.exe
  [PASS] console_socket.exe
  [PASS] console_registry.exe
  [PASS] gui_window.exe
  [PASS] gui_text.exe
  [PASS] gui_resource.exe
  [PASS] com_inproc.exe (STUB)
  [PASS] service_hello.exe
  [SKIP] dotnet_hello.exe (binary absent — no mcs on build host)
  [PASS] wmi_query.exe (STUB)
  [PASS] com_dispatch.exe (STUB)
  [PASS] cross_handle.exe (parent OK)
  [SKIP] powershell_hello.ps1 (no pwsh on build host)
  [PASS] registry_signext.exe
  [PASS] font_render.exe
  [PASS] listview_columns.exe

=== Corpus summary: PASS=16  FAIL=0  SKIP=2  ERROR=0  (of 18) ===
```

**Matches S69 pkg-23 baseline (16/0/2 of 18).** The 2 SKIPs are the expected `mcs`/`pwsh` gaps from the WSL2 build host — intentional opt-in installs, not code issues. PE loader delivers on every shipped binary, including Agent-K's new `registry_signext.exe`, `font_render.exe`, and `listview_columns.exe`.

Log: `logs/s74_agent_v_pe_corpus.log`

### Step 9 — v2 smoke (dictionary_v2 long-tail)

**FIRST RUN — FAIL (script bug):** `v2_smoke_run.sh` false-matched on the ArchWindows boot banner "AI Arch Linux ready" before sshd was up, then did a single SSH probe with no retry → immediate "SSH FAILED".

**Fix applied (one-line script edit, not source):**

```
scripts/v2_smoke_run.sh: 27 +++++++++++++++++++++------
```

Added two things:
1. `: > "$SERIAL"` truncation (copied from set_smoke_run.sh:26) to prevent stale serial-log matches.
2. 18× 5-second SSH retry loop (copied from set_smoke_run.sh:60-78) to ride out the gap between boot-banner and sshd-listening.

**SECOND RUN after fix — still 0/42:**

```
V2_SMOKE: routed=0/42 v2_source=0/42

============================================================
  V2 LONG-TAIL SMOKE RESULTS
============================================================
  TOTAL: 0/42 phrases routed
  SOURCE=v2_template: 0/42

[WARN] app             0/1
[WARN] audio           0/8
[WARN] brightness      0/5
[WARN] clipboard       0/3
[WARN] driver          0/1
[WARN] media           0/5
[WARN] monitoring      0/6
[WARN] power           0/3
[WARN] system          0/2
[WARN] window          0/3
[WARN] workspace       0/5
```

All 42 phrases returned HTTP 200 with `handler_type=null` / `source=null`. The daemon is answering but not routing long-tail phrases.

**Comparison to S63 baseline:** 42/42 routed, 26/42 v2_template. This is a **hard regression**.

**Root-cause investigation:**

- `v2_smoke_run.sh` diagnostic says `/usr/share/ai-control/dictionary_v2.pkl.zst` is missing — but that's the wrong path check. The real path is `/var/cache/ai-control/dictionary_v2.pkl.zst`, and `ai-control/daemon/dictionary_v2.py:1161-1164` has both paths in its search list.
- The pkg-24 tarball ships the artifact at `var/cache/ai-control/dictionary_v2.pkl.zst` (115 823 bytes, verified via `bsdtar tf`).
- `dictionary_v2.py` loaded and queried cleanly on the WSL build host when given the same artifact → the module and artifact are structurally fine.
- On the guest, all 42 probes return 200 + null handler_type. That's consistent with `_HAS_DICT_V2 = False` at daemon import time — the module import silently fails, `_try_dict_v2` returns None, `_maybe_clarify` also returns None (it's gated on `_HAS_DICT_V2`), and routing cascades through Stage 2 (contusion_dictionary) / Stage 3 (fallback). For phrases that have no direct regex match in contusion_dictionary, the fallback presumably returns a shell-response envelope with no `handler_type` → surfaces as 200/null.
- The guest runs the SAME Python 3.14 + `compression.zstd` stack as WSL, so a missing `zstandard` import isn't the cause.
- **Hypothesis to chase in S75:** the daemon's `sys.path` at import time doesn't include the directory dictionary_v2.py lives in, OR the zstd decompress returns None for the packaged artifact (pickle fails silently), OR an Agent-K change to `contusion.py` or `api_server.py` broke the import chain.

**Red flag:** this is silent — the daemon reports healthy, and exact-match routing works, so it looks fine unless you specifically probe long-tail phrases. The S63 claim that v2 was wired is valid for the code path; somewhere between S63 and pkg-24 the wiring got broken or the artifact lookup regressed.

Log: `logs/s74_agent_v_v2_smoke.log`

---

## Comparisons vs historical baselines

| Metric | S63 | S67 pkg-16 | S68 pkg-22 | S69 pkg-23 | **S74 pkg-24 (this run)** |
|---|---|---|---|---|---|
| ISO size | 2.21 GB | 2.26 GB | 2.2 GB | 2.2 GB | **2.2 GB** |
| 7-point total | n/a | 26 PASS | 26/0/1WARN/3SKIP | 26/0/1WARN/3SKIP | **25/0/1WARN/4SKIP** |
| set_smoke (phrases) | 32/33 | 33/33 | 33/33 | 33/33 | **33/33** |
| set_smoke (sets GREEN) | 12+1Y | 13 | 13 | 13 | **13** |
| PE corpus | n/a | 13/0/2 of 15 | 16/0/2 of 18 | 16/0/2 of 18 | **16/0/2 of 18** |
| v2 smoke (routed) | **42/42** | n/a | n/a | n/a | **0/42 (REGRESSION)** |
| v2 smoke (v2_template) | **26/42** | n/a | n/a | n/a | **0/42 (REGRESSION)** |

**The only regression is v2 smoke.** Everything else is at parity or better than historical.

---

## Red flags (in order of severity)

1. **v2 dictionary_v2 long-tail routing returns 0/42 on the guest** — hard regression from S63's 42/42. Silent from health/smoke; only surfaces under v2_smoke. Daemon loads clean, artifact is packaged, but routing misses. Root cause not isolated in this agent's time budget. Ship blocker if v2 routing is on the user-visible critical path; otherwise FIX in S75.
2. **`scripts/v2_smoke_run.sh` script bugs** (masked the real regression) — one-line serial-log truncation and SSH retry fix applied and committed. Orthogonal; low-severity; already fixed.
3. **wine-shim package missing from repo** (didn't block this ISO; profile doesn't require it) — Agent-K noted a `-fPIC` build issue. Not shippable yet. FIX in S75 so wine-shim can land as the S71 Tier-1 moat piece.
4. **Firewall pe-compat.slice dir missing warning** (test 25) — historical, recurring. Fix in a dedicated firewall/cgroup session.
5. **ai_impressive_demo.py hangs mid-probe** (set_smoke's piggyback) — orthogonal to set_smoke's primary signal (which captured JSON cleanly before the hang). Worth a diagnostic in S75.

---

## Caveats

- WSL2 + TCG is slower than real hardware — QEMU boots take ~80-120 s vs ~25 s on bare metal. Failures reported here are REAL functional failures, but slowness (timeouts, single-probe flakes) should be interpreted with TCG in mind.
- `dotnet_hello.exe` and `powershell_hello.ps1` SKIPs in PE corpus are by design (no mcs/pwsh on the build host). Not regressions.
- trust.ko SKIPs in 7-point smoke are by design (DKMS needs kernel headers; expected absent in QEMU). Real hardware would load and those skips would become PASS. Not a regression.
- The `Shutting down QEMU` line in the test-qemu.sh log shows the seven-point smoke shut down its own QEMU cleanly. All subsequent smoke runs (set_smoke, pe_corpus, v2_smoke) spawn fresh QEMUs on distinct ports (2233/2244/2234 respectively), so there's no cross-run contamination in the reported signals — except for the stale /tmp/serial-*.log issue, which only affected v2_smoke and was fixed.

---

## Files touched in this session

Source (1 file, intentional script-quality fix):
- `scripts/v2_smoke_run.sh` — +21/-6. Added serial-log truncation and SSH retry loop copied from `set_smoke_run.sh`. Fixes false boot detection on the ArchWindows "AI Arch Linux ready" banner.

Docs (1 new):
- `docs/s74_agent_v_qemu_verify.md` — this report.

Logs (all gitignored, not committed):
- `logs/s74_agent_v_iso_build.log` (200 KB)
- `logs/s74_agent_v_qemu_smoke.log` (8.7 KB)
- `logs/s74_agent_v_set_smoke.log` (control log with stray banners; informational only)
- `logs/s74_agent_v_set_smoke.json` (9981 B authoritative JSON)
- `logs/s74_agent_v_pe_corpus.log`
- `logs/s74_agent_v_v2_smoke.log`

---

## Handoffs for S75

1. **Root-cause the v2 routing regression.** Boot pkg-24 ISO interactively, run `journalctl -u ai-control.service -b | grep -iE "dictionary_v2|_HAS_DICT_V2|unavailable|lookup"` and look for the "dictionary_v2 unavailable:" log line at daemon start. If it's there, the root cause is a silent import failure; if not, the module loads but artifact-lookup or threshold gating is the problem. Either way a 1-hour investigation.
2. **Finish wine-shim PKGBUILD `-fPIC` fix.** Orthogonal to this agent's work but flagged by Q and confirmed absent here. Single-session task.
3. **Fix `pe-compat.slice` cgroup dir creation.** WARN in test 25 of 7-point smoke, recurring since earlier sessions.
4. **Re-apply v2 smoke hygiene pattern to any other long-tail smoke scripts.** Only `v2_smoke_run.sh` had the bug, but audit any new smoke scripts S75 adds against set_smoke_run.sh's pattern (truncate serial + 18× 5s SSH retry).
5. **Diagnose `ai_impressive_demo.py` hang.** Lower-priority — the demo isn't a release gate, but it's in the set_smoke hot path and wastes ~8-10 minutes per run.
