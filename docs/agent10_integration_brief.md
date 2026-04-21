# S74 Agent 10 — Integration + Post-Research Fix Brief

**Purpose:** Self-contained prompt for a dispatchable agent. This agent
runs AFTER the 10 parallel research agents (A-J) and the 9 S74 feature
agents (1-9). Its job is (a) verify integration of the feature agents'
work, (b) execute a targeted set of post-research fixes that came out of
the research synthesis (see `docs/architecture-v2.md` §4 Findings table),
(c) bake + test.

**Dispatch mode:** single sequential agent. No parallel subdispatch
unless explicitly noted.

**Reference documents (must be read first):**
- `CLAUDE.md` — build commands, architecture overview, pitfalls
- `docs/architecture-v2.md` — canonical architecture specification,
  §4 Findings and §8 Punch List are the scope doc
- `docs/research/s74_c_endosymbiosis.md` §0.2 top-3 — algedonic reader
  sketch
- `docs/research/s74_f_homoiconic_isa.md` §0, §7 — dispatch table rodata
  specifics
- `docs/research/s74_d_crypto_audit.md` §3.3 items 3, 10 — APE
  regression investigation
- `docs/research/s74_g_reliability_consensus.md` §0, §2.3, §2.4 —
  quorum threat-model honesty + sysfs path drift
- Memory:
  `memory/session73_12framework_meta_exploit.md`,
  `memory/roa_paper_validation_tier_audit_and_s74_plan.md`

**Git starting HEAD:** `5013ad9` + 9 S74 feature agents dirty in working
tree (likely all committed by the time this agent runs; otherwise first
task is to coordinate commits from the feature agents).

---

## Task 1 — Verify integration of S74 feature agents (1-9)

For each of the 9 feature agents, verify their output is present, compiles,
and passes basic smoke:

| Agent | Artifact | Verification |
|-------|----------|--------------|
| 1 | Wine PE32 shim in `packages/wine-shim/` | `ls packages/wine-shim/`; check PKGBUILD exists; verify it builds cleanly in a pacman sandbox |
| 2 | SCM polish: svchost SHARE_PROCESS, LP-JSON grouping | `grep -rn SHARE_PROCESS services/scm/`; verify additions |
| 3 | HID driver bring-up `services/drivers/kernel/` IRP/HAL/HID | `ls services/drivers/kernel/*.c`; verify compiles via `make` |
| 4 | RISC-V QEMU phase 1 + `docs/riscv-portability-deltas.md` | `cat docs/riscv-portability-deltas.md | head -30`; verify QEMU harness present |
| 5 | `trust_morphogen.c` (32×32 RD grid) | `ls trust/kernel/trust_morphogen.*`; verify Kbuild reference; compile test |
| 6 | `active_inference.py` (cortex with GenerativeModel + EFE) | `ls ai-control/cortex/active_inference.py`; `python3 -c 'import ai_control.cortex.active_inference'`; basic instantiation test |
| 7 | `entropy_observer.py` + `assembly_index.py` | Same pattern; `python3 -m pytest tests/unit/test_entropy_observer.py` should pass |
| 8 | `trust_quorum.c` + `trust_algedonic.c` | Verify both files present, Kbuild references, compile |
| 9 | Catalysis CI gate (`scripts/catalysis_analysis.py` already shipped; verify CI hook) | Check `.github/workflows/` for catalysis gate invocation |

**Output:** a per-agent ✓/✗ table with file:line evidence or "file absent."
If any agent is absent, note it but do NOT attempt to land that agent's
work in this session — it's out of scope. Raise as blocker if absent and
critical.

---

## Task 2 — Post-research fix #1: Algedonic reader (Finding #1)

**File to create:** `ai-control/daemon/algedonic_reader.py` (~130 LOC)

**Scope per research-H §1.5 + research-C §0.2:**

```python
# ai-control/daemon/algedonic_reader.py — ~130 LOC
#
# Userspace half of Beer's VSM algedonic channel.
# The kernel (trust_algedonic.c) emits 40-byte packets to
# /dev/trust_algedonic; this daemon opens that device, blocks on read(),
# decodes packets, and dispatches:
#   - event_bus.publish() for general distribution
#   - cortex.active_inference.on_algedonic() for fast-path if severity > CRITICAL
#   - Prometheus metric: trust_algedonic_packets_total{reason=...,severity=...}
#
# Critical packets (severity > TRUST_ALG_SEVERITY_CRITICAL) inject a
# synthetic observation into select_action() to bypass the normal
# belief-update cycle.

import asyncio
import os
import struct
import logging
from typing import Optional

_ALG_REASON_NAMES = {
    # from trust/include/trust_algedonic.h — keep in sync
    1: "ape_pool_exhausted",
    2: "subject_pool_exhausted",
    3: "dispatch_timeout",
    4: "cascade_apoptosis",
    5: "cancer_detected",
    6: "chromosome_integrity_lost",
    7: "quorum_disputed",
    8: "tpm_attestation_failed",
    9: "self_attest_mismatch",
}

TRUST_ALG_SEVERITY_CRITICAL = 32768  # match kernel
_PACKET_SIZE = 40  # u64 ts_ns | u32 pid | u16 sev | u16 reason | u64 d0 | u64 d1 | u64 d2

log = logging.getLogger(__name__)


class AlgedonicReader:
    def __init__(self, dev_path: str = "/dev/trust_algedonic",
                 event_bus=None, cortex=None, metrics=None):
        self._dev_path = dev_path
        self._event_bus = event_bus
        self._cortex = cortex
        self._metrics = metrics
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self):
        self._running = True
        self._task = asyncio.create_task(self._run())

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _run(self):
        # Graceful handling if the device is absent (SOFTWARE-mode boot,
        # kernel module not loaded, or dev not yet created).
        try:
            fd = os.open(self._dev_path, os.O_RDONLY | os.O_NONBLOCK)
        except FileNotFoundError:
            log.warning("algedonic_reader: %s not present; kernel "
                        "module not loaded? daemon will skip algedonic "
                        "bypass", self._dev_path)
            return
        except PermissionError:
            log.error("algedonic_reader: no read on %s; check perms "
                      "(should be mode 0640 group=trust)", self._dev_path)
            return

        # Re-open blocking for the actual read loop
        os.close(fd)
        fd = os.open(self._dev_path, os.O_RDONLY)
        loop = asyncio.get_running_loop()
        try:
            while self._running:
                try:
                    packet = await loop.run_in_executor(
                        None, os.read, fd, _PACKET_SIZE)
                except OSError as e:
                    log.warning("algedonic_reader: read failed: %s", e)
                    await asyncio.sleep(0.5)
                    continue
                if not packet or len(packet) != _PACKET_SIZE:
                    await asyncio.sleep(0.01)
                    continue
                self._handle_packet(packet)
        finally:
            os.close(fd)

    def _handle_packet(self, packet: bytes):
        ts_ns, pid, sev, reason, d0, d1, d2 = struct.unpack(
            "<QIHHQQQ", packet)
        reason_name = _ALG_REASON_NAMES.get(reason, f"unknown({reason})")
        event = {
            "source": "algedonic",
            "ts_ns": ts_ns,
            "subject_pid": pid,
            "severity": sev,
            "reason_code": reason,
            "reason_name": reason_name,
            "payload": [d0, d1, d2],
        }
        if self._metrics:
            self._metrics.algedonic_packets_total.labels(
                reason=reason_name, severity=str(sev)).inc()
        if self._event_bus:
            self._event_bus.publish(event)
        if sev > TRUST_ALG_SEVERITY_CRITICAL and self._cortex is not None:
            # Beer's bypass: skip belief-update, go straight to action
            try:
                self._cortex.select_action(bypass=event)
            except Exception as e:
                log.exception("algedonic bypass invocation failed: %s", e)
```

**Integration points:**

- Wire into `ai-control/daemon/api_server.py`. Create instance at startup:
  ```python
  self.algedonic = AlgedonicReader(
      event_bus=self.event_bus,
      cortex=self.active_inference_agent,  # S74 agent 6 output
      metrics=self.metrics,  # S74 agent from memory/metrics.py
  )
  await self.algedonic.start()
  ```
- Shutdown handler calls `await self.algedonic.stop()`.
- Unit test: `tests/unit/test_algedonic_reader.py` with a mock fd backed
  by a bytes-buffer; assert 3 packet shapes decode correctly; assert
  critical-severity bypass invokes cortex.

**Kernel-side verification required:**

- Check `trust/kernel/trust_algedonic.c` emits exactly 40-byte packets in
  the format `<QIHHQQQ`. If the format differs, adjust the Python struct.
- Check `/dev/trust_algedonic` permissions in the udev rules /
  `packages/trust-dkms/` — should be mode 0660 group=trust (per
  memory/session69_5agent_adoption_push.md permissions fixes).

**Acceptance test:**

1. `make` builds clean (kernel side)
2. `pytest tests/unit/test_algedonic_reader.py` passes
3. Run daemon with kernel module loaded; inject an algedonic packet via
   kernel test shim (trust_algedonic has a debugfs trigger; verify exists)
4. Assert event_bus receives the synthetic event and cortex receives
   bypass= kwarg on select_action

---

## Task 3 — Post-research fix #2: W^X on dispatch_table (Finding #4)

**File to modify:** `trust/kernel/trust_dispatch.c:1293`

**Current state (verified via grep):**

```c
static trust_cmd_handler_t dispatch_table[TRUST_STAT_FAMILY_SLOTS][TRUST_CMD_MAX_OPCODES] = {
    /* rows... */
};
```

**Target state:**

```c
static const trust_cmd_handler_t dispatch_table[TRUST_STAT_FAMILY_SLOTS][TRUST_CMD_MAX_OPCODES] __ro_after_init = {
    /* rows unchanged */
};
```

**Cross-cutting concerns to audit:**

1. **All write sites.** `grep -n 'dispatch_table\[' trust/kernel/*.c`. Any
   assignment to `dispatch_table[x][y]` must be eliminated or moved to
   module init before `__ro_after_init` freezes the rodata.
2. **`struct trust_cmd_handler_t` layout.** The struct itself must be
   trivially copyable; check `trust/include/trust_cmd.h` for the typedef.
   If it contains function pointers, `const` applies correctly. If it
   contains union types, verify `const` applies recursively.
3. **The fused-op handler table** at `trust/kernel/trust_fused.c` — per
   research-F §2, this table is also static but not marked. Apply same
   hardening.
4. **Module unload path.** If there is any re-registration of handlers
   in `trust_exit()` (there should not be), remove — the table is
   single-init.
5. **`set_memory_ro`** — for belt-and-suspenders, add a
   `set_memory_ro((unsigned long)dispatch_table, pages)` after init
   completes. This catches JIT-style writes that somehow bypass
   `__ro_after_init`. Per research-F §7 this is optional hardening.

**Acceptance test:**

1. Kernel builds clean with `make trust/kernel/` no warnings
2. Module loads successfully
3. At runtime:
   `echo 'w' > /sys/kernel/trust/debug_force_table_write` (a debug
   interface to intentionally write the table) must produce OOPS; this
   is a positive test that `__ro_after_init` is enforced. Only attempt
   in a VM. If no debug interface exists, add one under CONFIG_DEBUG.
4. `pytest tests/unit/test_trust_dispatch.py` still passes with normal
   dispatch.

**Rollback plan.** If the `__ro_after_init` annotation causes boot
failure on any target kernel version, revert to `const` only and file a
TODO for `__ro_after_init` re-enablement. Under no circumstances leave
the table fully mutable.

---

## Task 4 — Post-research fix #3: trust_quorum sysfs path drift (Finding #9)

**Discrepancy:**

- `trust/include/trust_quorum.h:48` documents sysfs path as
  `/sys/kernel/trust/quorum/*`
- `trust/kernel/trust_quorum.c:194` creates it as `/sys/kernel/quorum`
  (no `/trust/` prefix)

**Decision required:** pick ONE and make both match.

**Recommendation:** use `/sys/kernel/trust/quorum/` — consistent with
other trust sysfs (e.g. `/sys/kernel/trust/stats` at
`tests/test_dispatch_roundtrip.c:70`) and honors the existing
documentation claim.

**Patch (~5 LOC) at `trust/kernel/trust_quorum.c:194-195`:**

```c
/* Look up or create the /sys/kernel/trust parent first. */
static struct kobject *_trust_parent_kobj(void)
{
    static struct kobject *cached;
    if (cached)
        return cached;
    /* Check if trust_invariants already created /sys/kernel/trust — if
     * so, use it. Otherwise create. */
    /* ... (kobject_find_by_name or similar; fallback to create) ... */
    return cached;
}

static int trust_quorum_init(void)
{
    struct kobject *parent = _trust_parent_kobj();
    g_quorum_kobj = kobject_create_and_add("quorum", parent);
    /* ... rest unchanged ... */
}
```

Alternatively, if other trust sysfs nodes are created independently at
`/sys/kernel/` (not under `/sys/kernel/trust/`), align with their
convention and document the pattern in `docs/architecture-v2.md` §1
Layer 0 external interface.

**Acceptance test:**

1. After module load, `ls /sys/kernel/trust/` shows `quorum/` directory
2. `cat /sys/kernel/trust/quorum/votes_taken` works
3. `cat /sys/kernel/trust/stats` still works (existing counters
   unaffected)
4. Unit test that opens both paths and verifies readability.

---

## Task 5 — Post-research investigation: APE regression triage (Finding #10)

**This is INVESTIGATION, not CODE CHANGE.** Do not attempt to bring back
`consume_proof_v2` or `apply_reconfigurable_hash` in this session.

**Finding:** `docs/roa-conformance.md:58-60` references
`apply_reconfigurable_hash()` at `trust_ape.c:224`. `trust_ape.c` is 656
LOC and has no function by that name. `trust_ape.h:88` declares
`trust_ape_consume_proof_v2` with no `.c` implementation.

**Investigation steps:**

1. **Git archaeology.** `git log --all --oneline -- trust/kernel/trust_ape.c |
   head -40`. Look for commits that reduced the line count from ~1038 to
   656. If found, examine the diff: was the removal deliberate (e.g.,
   rollback after instability) or accidental?
2. **Branch scan.** `git branch --contains <commit-if-found>` to see if
   the older code survives on another branch.
3. **Header vs. code.** Verify `trust_ape.h:88` declaration and match
   (or mismatch) against `trust_ape.c` function table. If header is
   authoritative, the .c file is missing the impl. If code is
   authoritative, the header declaration is an orphan.
4. **`docs/roa-conformance.md` line-by-line.** Lines 58-60 cite a
   specific line number. Was this doc auto-generated? If yes, find the
   generator; if no, assess drift.
5. **Paper (Zenodo DOI 10.5281/zenodo.18710335) §APE.** Does the paper's
   formal spec require 94M configs or is the "720 × 256 × 16 × 32" a
   header aspiration?

**Output:** a 1-page `docs/ape_regression_triage_report.md` with:
- Git history finding (which commit, which session)
- Which file is authoritative (header spec, .c reality, or paper)
- Recommendation (one of):
  (a) implement 94M-config reconfigurable hash + `consume_proof_v2`
      (~300-400 LOC, next session)
  (b) amend docs + header to match 3-algo shipping reality (~40 LOC,
      can do now)
  (c) determine that code was never there (paper aspiration); update
      paper-conformance doc to reflect status.

**Do not land any code fix in this session** — escalate to user / next
session with recommendation.

---

## Task 6 — Original S74 agent 10 scope: verify + bake

This is the original pre-research scope for agent 10. Execute after
Tasks 1-5.

### Task 6a — Kbuild integration

Verify `trust/kernel/Kbuild` references every new `.c` shipped by agents
5, 8 (trust_morphogen.c, trust_quorum.c, trust_algedonic.c).

Verify `ai-control/daemon/Kbuild` equivalent (Python Makefile) lists
agents 6, 7 outputs (active_inference.py, entropy_observer.py,
assembly_index.py) + the new `algedonic_reader.py`.

### Task 6b — pkgrel bumps

Bump `pkgrel` in:
- `packages/trust-dkms/PKGBUILD` (trust.ko changed)
- `packages/ai-control-daemon/PKGBUILD` (daemon changed)
- `packages/windows-services/PKGBUILD` if SCM changes

Document bumps in commit message. Do NOT bump pkgver.

### Task 6c — Build packages

```bash
wsl.exe -d Arch -- bash -c 'cd /mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control && bash scripts/build-packages.sh'
```

Expect pkg-24 artifacts in `repo/x86_64/`. Verify SHA-256 written to log.

### Task 6d — Pytest

```bash
wsl.exe -d Arch -- bash -c 'cd /mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control && pytest tests/ -x -v'
```

Target: no regressions vs S69 baseline (225 pass / 84 skip / 2 QEMU-env
fails). If regressions, identify and fix before ISO build.

### Task 6e — PE corpus

Execute PE corpus test suite. Target: 16/18 baseline held (2 SKIP for
mcs/pwsh on build host acceptable; no new FAILs).

### Task 6f — ISO bake (optional — user decision)

If user requests ISO bake:

```bash
wsl.exe -d Arch -- bash -c 'cd /mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control && bash scripts/build-iso.sh'
```

Artifact: `output/archlinux-archwindows-<ts>-x86_64.iso`.

### Task 6g — set_smoke live test (optional — requires QEMU)

```bash
wsl.exe -d Arch -- bash -c 'cd /mnt/c/Users/wilde/Downloads/arch-linux-with-full-ai-control && bash scripts/set_smoke_run.sh'
```

Target: 13/13 sets GREEN (S67+ baseline). Any RED is a blocker.

---

## Task 7 — Commit and report

Commit all changes as ONE new commit (do NOT amend):

```
fix: S74 Agent 10 — research-finding fixes + feature-agent integration

Addresses findings #1, #4, #9, #10 from docs/architecture-v2.md §4:
  #1 — algedonic userspace reader (~130 LOC)
        Closes the producer-without-consumer loop; kernel emits
        to /dev/trust_algedonic now reach cortex active_inference
        and event_bus.
  #4 — W^X on dispatch_table (~40 LOC)
        dispatch_table now const __ro_after_init; kernel-write
        adversary can no longer rewrite handlers without trapping.
  #9 — trust_quorum sysfs path drift (~5 LOC)
        /sys/kernel/quorum/ moved to /sys/kernel/trust/quorum/
        consistent with trust_quorum.h:48 documentation.
  #10 — APE regression triaged; report in
        docs/ape_regression_triage_report.md. No code change.

Plus standard S74 integration: verified agents 1-9 artifacts,
bumped pkgrel on trust-dkms + ai-control-daemon + windows-services,
built pkg-24, pytest + PE corpus regressions-free.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

**Final report back to user:** concise summary covering:
- Which feature agents (1-9) integrated successfully
- Which findings (#1, #4, #9, #10) were fixed
- Build artifact hashes (pkg-24)
- Pytest / PE corpus results
- Anything blocked or escalated

---

## Constraints and non-goals

**DO NOT do any of the following:**

- Attempt to implement the 94M-variant reconfigurable hash (Finding #10)
  — investigation only.
- Attempt Monte Carlo module, bisim harness, or adversarial theorem
  harness — these are S75 items.
- Rename `trust_meiosis()` to `trust_dual_authority_bond()` — paper
  disclaimer first, rename second.
- Add `libtrust_wine_shim` — S76-S77 item.
- Touch the paper (`PLAN/Root_of_Authority_Full_Paper*`) — user-owned
  authorial artifact.
- Skip hooks or bypass signing on commits.
- Force-push.
- Create new .md files beyond `ape_regression_triage_report.md` (as a
  Task 5 deliverable) without explicit user permission. Architecture
  changes are in architecture-v2.md already.

**DO ensure the following:**

- Every commit has the standard `Co-Authored-By: Claude` trailer.
- Every new kernel file is in Kbuild.
- Every new Python module is in tests (unit test on create).
- No regression in set_smoke GREEN count.
- No regression in PE corpus PASS count.

---

## Rollback / escalation criteria

**Immediate rollback if:**
- `__ro_after_init` causes kernel boot failure on any tested kernel
  version
- algedonic_reader.py causes daemon startup to hang or crash
- sysfs path change breaks an existing test in tests/

**Escalate to user if:**
- Any S74 feature agent (1-9) artifact is absent from working tree
- pkg-24 build fails
- pytest regresses vs S69 baseline (225 pass)
- PE corpus regresses (new FAIL)
- set_smoke drops below 12 GREEN

---

**End of agent 10 integration brief.**
