# Architecture

This document describes what the system actually does, as opposed to what its name suggests. It is intended to be read after the top-level [`README.md`](../README.md) and before diving into source.

If you want marketing prose, read `/trust/architecture` on a running daemon. This document is the engineering view.

## 1. The 5-layer model

```
                        ┌───────────────────────────────────────┐
 Layer 4 — AI cortex    │ event bus · decision engine · cortex  │
                        │ orchestrator · autonomy controller    │
                        │ (Python / FastAPI, port 8420)         │
                        └──────────────────┬────────────────────┘
                                           │ commands ↓  events ↑
                        ┌──────────────────┴────────────────────┐
 Layer 3 — Service      │ scm-daemon: Windows + Linux service   │
            fabric      │ lifecycle · driver host · dep graph   │
                        └──────────────────┬────────────────────┘
                                           │
                        ┌──────────────────┴────────────────────┐
 Layer 2 — PE runtime   │ pe-loader (per-process): parser ·     │
            (per proc.) │ mapper · relocator · import resolver ·│
                        │ TLS · SEH · ~37 DLL stubs · trust gate│
                        └──────────────────┬────────────────────┘
                                           │
                        ┌──────────────────┴────────────────────┐
 Layer 1 — Object       │ pe-objectd: named objects · registry  │
            broker      │ hive · device namespace · sessions    │
                        └──────────────────┬────────────────────┘
                                           │
                        ┌──────────────────┴────────────────────┐
 Layer 0 — Kernel       │ trust.ko (Root of Authority)          │
                        │ binfmt_pe (MZ detection) + Linux      │
                        └───────────────────────────────────────┘
```

**Direction rule.** Commands flow down, events flow up, no layer calls the one above it. The cortex can *subscribe* to events from lower layers but cannot be *called* synchronously from the PE runtime. This is enforced by the event bus socket being the only upward channel.

**Shared-memory rule.** No layer shares mutable state with another layer except through the trust kernel's `/dev/trust` ioctl interface (Layer 0) or the object broker's shared-memory regions (Layer 1). Crossing any other boundary requires going through the event bus or a well-typed command handler.

## 2. Trust ontologies — there are five

The word "trust" in this codebase covers five distinct numeric or categorical domains. Session 41's audit (A5) found these overlap in the positive integers and produced silent unit-confusion bugs. The canonical translation layer is [`ai-control/daemon/trust_translate.py`](../ai-control/daemon/trust_translate.py); every boundary crossing must go through it.

| Ontology | Range | Shape | Source of truth | Consumer |
|---|---|---|---|---|
| **Kernel score** | `[-1000, +1000]` | signed, continuous | `trust.ko` | `/dev/trust` ioctl, observer `last_score` |
| **API band** | `{0, 100, 200, ..., 1000}` | discrete tiers | `auth.ENDPOINT_TRUST` | JWT `trust` claim on FastAPI routes |
| **PE-loader gate** | `[5, 90]` | integer threshold | pe-loader config | per-binary launch gate |
| **Anti-cheat PID allowlist** | categorical | set of PIDs | `services/anticheat/` | injected-library checks |
| **Cortex reputation** | `[0, 100]` | bounded, non-negative | `cortex/trust_history.py` | `decision_engine`, autonomy throttling |

**API band semantic tiers** (rough):

- `0` public, `200` read, `400` mutate, `600` admin, `900` kernel-equivalent.

**Cortex quarantine** triggers below `CORTEX_QUARANTINE_THRESHOLD = 10`; a quarantined subject is rejected even if its kernel score is otherwise acceptable.

Do not compare values across ontologies directly. The number `600` is a valid kernel score *and* a valid API band *and* a valid PE-loader gate, but means three unrelated things. Always translate.

## 3. Authority graph — who can do what

The authority chain on a running system, from bottom to top:

```
  kernel root
      │
      ▼
  systemd (PID 1)
      │
      ├─ ai-control.service (User=root, hardened namespace)
      │      │
      │      ▼
      │   ai-cortex (cortex orchestrator subprocess)
      │      │
      │      ▼
      │   optional: LLM (llama-cpp-python) — veto only
      │
      ├─ scm-daemon (Windows service fabric)
      ├─ pe-objectd (object broker)
      └─ trust.ko (kernel module, loaded at boot)
```

**Honest notes** (Session 41 A3, Session 45 A4):

- `ai-control.service` runs `User=root`. The service unit applies a hardened namespace (`ProtectSystem`, `PrivateTmp`, `NoNewPrivileges`), but the daemon itself is root — a root compromise on the host bypasses every control.
- The LLM (when enabled) is a **veto-only** stage: it can reject a proposed cortex action, but it cannot originate one. This is enforced in `cortex/decision_engine.py` by the order of the pipeline — action is produced by the rule-based engine first, then optionally vetoed. The LLM never holds a handle, never signs a token, and cannot be called as a principal.
- "Full AI Control" in the project name is marketing. What actually exists is a daemon that can mediate a fixed set of desktop automation actions (window management, game launching, shortcut execution) with autonomy knobs. It is not a general-purpose autonomous agent.

## 4. Event bus

PE events flow from the loader to the cortex through a Unix socket at `/run/pe-compat/events.sock`. Ownership is the `pe-compat` group; the socket is `0660`.

**Schema v2** (current, Session 44 A6). Each event is a single NDJSON line:

```json
{
  "v": 2,
  "ts_ns": 1742900000123456789,
  "source": "pe-loader",
  "pid": 4711,
  "subject": "trust-subject-id-or-null",
  "kind": "load | syscall | exception | exit | ...",
  "payload": { /* kind-specific */ }
}
```

- `v`: schema version; bump breaks wire compatibility.
- `ts_ns`: monotonic nanoseconds since boot (CLOCK_MONOTONIC).
- `source`: originating layer; currently one of `pe-loader`, `scm`, `objectd`, `firewall`.
- `subject`: opaque trust-subject identifier, or `null` if not yet bound.
- `kind` + `payload`: per-kind, see the schema map in [`pe-loader/include/eventbus/pe_event.h`](../pe-loader/include/eventbus/pe_event.h).

**Delivery guarantees.** At-most-once, lossy on buffer overflow. Events are advisory; the cortex must not rely on every event being received. Security-critical gating lives in the trust kernel, not the event bus.

## 5. Control loop — event-driven policy arbiter

The coherence daemon (`coherence/daemon/`) is described elsewhere as a "multi-rate control system with 100/250/500 ms ticks". Session 41 A4's honest audit clarified this:

**What it is.** An event-driven *policy arbiter* with four states and hysteresis. On each tick (or on boundary-crossing events), it evaluates EMA-smoothed sensor inputs (thermal, cpufreq, trust score, load) against a 4-state arbiter machine and, if the state changed, emits idempotent actuation commands.

**What it is NOT.** It is not a continuous controller in the control-theory sense. It does not compute a control law, does not have a plant model, and does not attempt closed-loop stabilisation. Calling it "control" is convenient but misleading.

**Why it still earns its keep.** The 4-state arbiter with transition lockout prevents oscillation — the failure mode that matters in practice on mixed-workload hardware where thermal, trust, and load signals disagree. The stability simulator in `coherence/simulator/` runs 280 synthetic scenarios and verifies the arbiter never enters a thrash loop.

Reference: `coherence/daemon/include/state_machine.h` — look at `coh_arbiter_t`, dwell counters, and the lockout logic. The transition table is the actual specification.

## 6. Known limitations

These are the findings of recent audit sessions rephrased in user-facing terms. See session memory notes (`memory/MEMORY.md`) for detail and commit hashes.

- **Naming vs. reality** (Session 41 A3). "Full AI Control" describes the aspiration, not the behaviour. The cortex mediates a fixed menu of actions with human-in-the-loop approval for destructive operations. Do not expect autonomous system administration.
- **Five overlapping trust domains** (Session 41 A5). Anyone writing new code that reads a "trust" number must pass it through `trust_translate.py`. Ad-hoc comparisons between domains are the single largest source of logic bugs in this codebase.
- **Authority sits at root** (Session 41 A3). The daemon runs as root with systemd hardening; this is not equivalent to capability-based isolation. A root compromise defeats the trust kernel from above.
- **LLM is opt-in veto only** (Session 45 A4). If you disable the LLM, the system still functions — the rule-based decision engine owns the policy. The LLM is a safety stage, not a brain.
- **Control loop is a policy switcher, not a controller** (Session 41 A4). Do not cite it as a feedback control system in a paper.
- **PE loader compatibility is narrow** (CLAUDE.md, Known Pitfalls section). Wide categories of Win32 APIs are stubbed or unimplemented. See [`docs/pe-compat.md`](pe-compat.md) for the compatibility matrix.
- **Testing runs under TCG** (no KVM under WSL2). Boot times and timing-sensitive races differ on real hardware. Real-hardware coverage is thin.
- **No LICENSE file.** Redistribution is not permitted until one is added.

## Further reading

- [`docs/quickstart.md`](quickstart.md) — end-to-end first boot.
- [`docs/pe-compat.md`](pe-compat.md) — Win32 compatibility surface.
- [`docs/build.md`](build.md) — build pipeline in detail.
- [`docs/system-summary.md`](system-summary.md) — the `/system/summary` endpoint.
- `PLAN/Root_of_Authority_Full_Paper(full).pdf` — the trust system's theoretical basis.
- `ai-control/daemon/trust_translate.py` — canonical trust-domain translator.
- `memory/MEMORY.md` — running audit log across sessions.
