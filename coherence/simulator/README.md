# Offline Stability Simulator

Validation artifact for the coherence control system. Replays recorded or
synthetic M(t) traces through a faithful reference pipeline and proves that
the shipping θ/τ/weight defaults are stable under bounded stochastic
perturbations.

The simulator is **self-contained** — it doesn't need the coherence daemon
to be running, and builds even if `coherence/daemon/src/state_machine.c` and
`coherence/daemon/src/derived.c` are not yet on disk. It re-implements the
minimum required subset in-process, sharing the contract from
`coherence/daemon/include/coherence_types.h`.

---

## Build

```
cd coherence/simulator
make                 # → ./simulator
make stability-report # → report/correctness-report.md + report/sweep-grid.csv
make clean
```

Requires a POSIX-C11 toolchain. No external dependencies.

If the daemon later ships `coherence/daemon/build/libcoherence_core.a`, the
Makefile links against it automatically on the next build; no changes
needed.

---

## Run

Default action (replays 3 example traces + full sweep + report):

```
./simulator
```

Single-trace replay:

```
./simulator --trace traces/burst_load.bin --report report/burst.md
```

Options:

| Flag | Meaning |
|------|---------|
| `--trace FILE`        | replay a specific trace, skip the sweep |
| `--report FILE`       | where to write `correctness-report.md` |
| `--csv FILE`          | where to write the sweep grid CSV |
| `--seed N`            | PRNG seed (default `0xC0FFEE`) |
| `--no-sweep`          | skip sweep even in default mode |
| `--generate-traces`   | (re)generate example `.bin` traces and exit |
| `-h`, `--help`        | help |

Exit code:
- `0`  — every trace PASSED
- `2`  — at least one trace FAILED the stability gate
- `1`  — simulator crashed / cannot load trace

---

## Adding a new trace

A trace is a sequence of `sim_trace_frame_t` records at 100 ms cadence.
The binary layout is documented in `include/trace.h`:

```
offset  size  field
  0      4    magic = 'COHT'
  4      4    version = 1
  8      4    count (uint32 LE)
 12      4    reserved = 0
 16      N    frames[count]  (64 bytes each on x86_64)
```

Options for producing one:

1. **Export from the daemon.** Drop frame samples into a buffer and call
   `trace_save()`; that's the production path for recorded traces.
2. **Extend a generator.** Copy one of `trace_gen_*()` in `trace.c`, pick
   a new seed mask, and hook it into `main()`'s ensure-exist block.
3. **Hand-craft in any language.** The format is little-endian and stable
   on x86_64; a 50-line Python writer works fine.

Once the `.bin` is on disk, pass it with `--trace` or add it to the
default-replay list in `simulator.c`.

---

## Interpreting the report

`report/correctness-report.md` has 7 sections:

1. **Executive summary** — top-level table: per-trace PASS/FAIL, oscillation
   count, WCD, RT, dV/dt, mean V, actuation writes vs. no-ops.

2. **Per-trace detailed** — state occupancy percentages + all the numbers
   individually explained so you can see *why* something failed.

3. **Sweep grid** — for each τ_hold value, a 2-D matrix of θL × θT cells
   showing PASS/FAIL. Our default is marked `*P*`/`*F*`.

4. **Lyapunov plots** — ASCII plot of V(t) per trace. If the silhouette
   is roughly flat or decreasing, the system is dissipating energy; a
   rising silhouette is cause for alarm.

5. **Oscillation log** — every recorded state transition, in time order.

6. **Defaults within stable region** — explicit proof that our shipping
   default is a stable cell *and* that it's within a stable neighbourhood
   (surrounding cells also stable).

7. **Reproducibility footer** — PRNG seed + commit so the exact report
   can be re-emitted bit-identically.

### What "PASS" means

A trace passes iff **all four** gates hold:

- `oscillation_count == 0` — no window of 2 s contains more than 3 sign
  flips of ΔV(t).
- `worst_case_deviation < 0.20` — the maximum observed D_latency_pressure
  never climbed more than 20% above θ_latency_enter.
- `recovery_time_max_ms < 2000` — the longest contiguous run of
  non-NORMAL state is under 2 s.
- `lyapunov_slope <= 0` — linear fit of V(t) is non-increasing.

If any single gate fails, the trace is FAIL and the first failing gate is
recorded as `fail_reason`.

---

## Determinism

Reproducibility is a hard requirement. Same commit + same seed + same
trace set → **bit-identical** `correctness-report.md`. Specifically:

- All random draws go through `sim_prng` (xorshift64*), seeded from
  `sim_noise_cfg_t::seed`.
- Every per-frame noise call re-seeds from `(seed ^ t_ms)`, so the
  order in which frames are processed doesn't change the final state.
- No wall-clock time, PID, or environment variable enters the report.
- Floating-point is IEEE 754 double throughout; we never use `-ffast-math`.

If CI sees a diff in `correctness-report.md` after a refactor that didn't
touch the pipeline, **that's a bug** — the simulator lost determinism
somewhere.

---

## Contract

The simulator links against the headers under `coherence/daemon/include/`:

- `coherence_types.h` — authoritative type + constant contract.
- `config.h`          — per-host override struct (used by sweep).
- `state_machine.h`   — state table documentation.
- `derived.h`         — derivation contract.

It does **not** include any implementation headers not part of the
contract. If those headers change, this directory must be rebuilt.
