# Coherence Control — Offline Stability Correctness Report

**Overall Verdict:** **PASS — every trace satisfies all stability gates.**

Pass/fail gates:
- `oscillation_count == 0`
- `worst_case_deviation < 0.20`
- `recovery_time_max_ms < 2000`
- `lyapunov_slope <= 0` (V decreasing on average)

## 1. Executive Summary

| trace | verdict | oscillations | WCD | RT (max not-normal) | dV/dt (/ms) | mean V | max V | A writes | A no-ops | fail reason |
|-------|---------|--------------|-----|---------------------|-------------|--------|-------|----------|----------|-------------|
| steady.bin | **PASS** | 0 | 0.0000 | 0.0 ms | -0.000000002 | 0.0866 | 0.2426 | 1 | 1199 | — |
| thermal_storm.bin | **PASS** | 0 | 0.0000 | 0.0 ms | -0.000000011 | 0.0918 | 0.2433 | 1 | 599 | — |
| burst_load.bin | **PASS** | 0 | 0.0000 | 0.0 ms | -0.000000054 | 0.1100 | 1.0995 | 1 | 599 | — |

## 2. Per-Trace Stability Results

### 2.1 steady.bin

- Path: `traces/steady.bin`
- Total ticks: 6000
- Verdict: **PASS**
- Oscillation count: 0
- Worst-case deviation (max D_latency − θL_enter): 0.0000
- Recovery time max (longest not-NORMAL run): 0.0 ms
- Lyapunov slope dV/dt: -0.000000002 /ms
- Mean V: 0.0866, max V: 0.2426
- Actuation writes: 1, no-ops: 1199 (idempotent barrier efficacy: 99.9%)

**State occupancy:**

- NORMAL              : 6000 ticks (100.0%)
- LATENCY_CRITICAL    : 0 ticks (0.0%)
- THERMAL_CONSTRAINED : 0 ticks (0.0%)
- DEGRADED            : 0 ticks (0.0%)

### 2.2 thermal_storm.bin

- Path: `traces/thermal_storm.bin`
- Total ticks: 3000
- Verdict: **PASS**
- Oscillation count: 0
- Worst-case deviation (max D_latency − θL_enter): 0.0000
- Recovery time max (longest not-NORMAL run): 0.0 ms
- Lyapunov slope dV/dt: -0.000000011 /ms
- Mean V: 0.0918, max V: 0.2433
- Actuation writes: 1, no-ops: 599 (idempotent barrier efficacy: 99.8%)

**State occupancy:**

- NORMAL              : 3000 ticks (100.0%)
- LATENCY_CRITICAL    : 0 ticks (0.0%)
- THERMAL_CONSTRAINED : 0 ticks (0.0%)
- DEGRADED            : 0 ticks (0.0%)

### 2.3 burst_load.bin

- Path: `traces/burst_load.bin`
- Total ticks: 3000
- Verdict: **PASS**
- Oscillation count: 0
- Worst-case deviation (max D_latency − θL_enter): 0.0000
- Recovery time max (longest not-NORMAL run): 0.0 ms
- Lyapunov slope dV/dt: -0.000000054 /ms
- Mean V: 0.1100, max V: 1.0995
- Actuation writes: 1, no-ops: 599 (idempotent barrier efficacy: 99.8%)

**State occupancy:**

- NORMAL              : 3000 ticks (100.0%)
- LATENCY_CRITICAL    : 0 ticks (0.0%)
- THERMAL_CONSTRAINED : 0 ticks (0.0%)
- DEGRADED            : 0 ticks (0.0%)


## 3. Parameter Sweep Grid

Sweep ranges:
- θ_latency_enter ∈ [0.70, 1.30] step 0.10
- θ_thermal_enter ∈ [0.75, 0.95] step 0.05
- τ_hold ∈ [550, 1250] step 100 ms (phase-shifted 50 ms from brief's [500, 1200] so the shipping default τ = 750 ms lands on a grid point)


#### τ_hold = 550 ms

Rows = θ_latency_enter, cols = θ_thermal_enter. `P` = PASS, `F` = FAIL, `*P*` = DEFAULT (PASS), `*F*` = DEFAULT (FAIL).

| θL \ θT | 0.75 | 0.80 | 0.85 | 0.90 | 0.95 |
|---|---|---|---|---|---|
| 0.70 |  P  |  P  |  P  |  P  |  P  |
| 0.80 |  P  |  P  |  P  |  P  |  P  |
| 0.90 |  P  |  P  |  P  |  P  |  P  |
| 1.00 |  P  |  P  |  P  |  P  |  P  |
| 1.10 |  P  |  P  |  P  |  P  |  P  |
| 1.20 |  P  |  P  |  P  |  P  |  P  |
| 1.30 |  P  |  P  |  P  |  P  |  P  |

#### τ_hold = 650 ms

Rows = θ_latency_enter, cols = θ_thermal_enter. `P` = PASS, `F` = FAIL, `*P*` = DEFAULT (PASS), `*F*` = DEFAULT (FAIL).

| θL \ θT | 0.75 | 0.80 | 0.85 | 0.90 | 0.95 |
|---|---|---|---|---|---|
| 0.70 |  P  |  P  |  P  |  P  |  P  |
| 0.80 |  P  |  P  |  P  |  P  |  P  |
| 0.90 |  P  |  P  |  P  |  P  |  P  |
| 1.00 |  P  |  P  |  P  |  P  |  P  |
| 1.10 |  P  |  P  |  P  |  P  |  P  |
| 1.20 |  P  |  P  |  P  |  P  |  P  |
| 1.30 |  P  |  P  |  P  |  P  |  P  |

#### τ_hold = 750 ms

Rows = θ_latency_enter, cols = θ_thermal_enter. `P` = PASS, `F` = FAIL, `*P*` = DEFAULT (PASS), `*F*` = DEFAULT (FAIL).

| θL \ θT | 0.75 | 0.80 | 0.85 | 0.90 | 0.95 |
|---|---|---|---|---|---|
| 0.70 |  P  |  P  |  P  |  P  |  P  |
| 0.80 |  P  |  P  |  P  |  P  |  P  |
| 0.90 |  P  |  P  |  P  |  P  |  P  |
| 1.00 |  P  |  P  | *P* |  P  |  P  |
| 1.10 |  P  |  P  |  P  |  P  |  P  |
| 1.20 |  P  |  P  |  P  |  P  |  P  |
| 1.30 |  P  |  P  |  P  |  P  |  P  |

#### τ_hold = 850 ms

Rows = θ_latency_enter, cols = θ_thermal_enter. `P` = PASS, `F` = FAIL, `*P*` = DEFAULT (PASS), `*F*` = DEFAULT (FAIL).

| θL \ θT | 0.75 | 0.80 | 0.85 | 0.90 | 0.95 |
|---|---|---|---|---|---|
| 0.70 |  P  |  P  |  P  |  P  |  P  |
| 0.80 |  P  |  P  |  P  |  P  |  P  |
| 0.90 |  P  |  P  |  P  |  P  |  P  |
| 1.00 |  P  |  P  |  P  |  P  |  P  |
| 1.10 |  P  |  P  |  P  |  P  |  P  |
| 1.20 |  P  |  P  |  P  |  P  |  P  |
| 1.30 |  P  |  P  |  P  |  P  |  P  |

#### τ_hold = 950 ms

Rows = θ_latency_enter, cols = θ_thermal_enter. `P` = PASS, `F` = FAIL, `*P*` = DEFAULT (PASS), `*F*` = DEFAULT (FAIL).

| θL \ θT | 0.75 | 0.80 | 0.85 | 0.90 | 0.95 |
|---|---|---|---|---|---|
| 0.70 |  P  |  P  |  P  |  P  |  P  |
| 0.80 |  P  |  P  |  P  |  P  |  P  |
| 0.90 |  P  |  P  |  P  |  P  |  P  |
| 1.00 |  P  |  P  |  P  |  P  |  P  |
| 1.10 |  P  |  P  |  P  |  P  |  P  |
| 1.20 |  P  |  P  |  P  |  P  |  P  |
| 1.30 |  P  |  P  |  P  |  P  |  P  |

#### τ_hold = 1050 ms

Rows = θ_latency_enter, cols = θ_thermal_enter. `P` = PASS, `F` = FAIL, `*P*` = DEFAULT (PASS), `*F*` = DEFAULT (FAIL).

| θL \ θT | 0.75 | 0.80 | 0.85 | 0.90 | 0.95 |
|---|---|---|---|---|---|
| 0.70 |  P  |  P  |  P  |  P  |  P  |
| 0.80 |  P  |  P  |  P  |  P  |  P  |
| 0.90 |  P  |  P  |  P  |  P  |  P  |
| 1.00 |  P  |  P  |  P  |  P  |  P  |
| 1.10 |  P  |  P  |  P  |  P  |  P  |
| 1.20 |  P  |  P  |  P  |  P  |  P  |
| 1.30 |  P  |  P  |  P  |  P  |  P  |

#### τ_hold = 1150 ms

Rows = θ_latency_enter, cols = θ_thermal_enter. `P` = PASS, `F` = FAIL, `*P*` = DEFAULT (PASS), `*F*` = DEFAULT (FAIL).

| θL \ θT | 0.75 | 0.80 | 0.85 | 0.90 | 0.95 |
|---|---|---|---|---|---|
| 0.70 |  P  |  P  |  P  |  P  |  P  |
| 0.80 |  P  |  P  |  P  |  P  |  P  |
| 0.90 |  P  |  P  |  P  |  P  |  P  |
| 1.00 |  P  |  P  |  P  |  P  |  P  |
| 1.10 |  P  |  P  |  P  |  P  |  P  |
| 1.20 |  P  |  P  |  P  |  P  |  P  |
| 1.30 |  P  |  P  |  P  |  P  |  P  |

#### τ_hold = 1250 ms

Rows = θ_latency_enter, cols = θ_thermal_enter. `P` = PASS, `F` = FAIL, `*P*` = DEFAULT (PASS), `*F*` = DEFAULT (FAIL).

| θL \ θT | 0.75 | 0.80 | 0.85 | 0.90 | 0.95 |
|---|---|---|---|---|---|
| 0.70 |  P  |  P  |  P  |  P  |  P  |
| 0.80 |  P  |  P  |  P  |  P  |  P  |
| 0.90 |  P  |  P  |  P  |  P  |  P  |
| 1.00 |  P  |  P  |  P  |  P  |  P  |
| 1.10 |  P  |  P  |  P  |  P  |  P  |
| 1.20 |  P  |  P  |  P  |  P  |  P  |
| 1.30 |  P  |  P  |  P  |  P  |  P  |

## 4. Lyapunov V(t) Plots (ASCII)

### 4.1 steady.bin

```
V_max = 0.2426
|                                                                  |
|                                                                  |
|                                                                  |
|                                                                  |
|                                                                  |
|                                                                  |
|                                                                  |
|                                                                  |
|                  #                         #                   # |
| ################################ ############## #### ########### |
| ################################################################ |
| ################################################################ |
V_min = 0.0426
  t=0 ms -> t=599900 ms
```

### 4.2 thermal_storm.bin

```
V_max = 0.2433
|                                                                  |
|                                                                  |
|                                                                  |
|                                                                  |
|                                                                  |
|                                                                  |
|                                                                  |
|                                                                  |
|        #         ###    # # # #   #     #        # #        # #  |
| #### ########################################### # # ##########  |
| ################################################################ |
| ################################################################ |
V_min = 0.0434
  t=0 ms -> t=299900 ms
```

### 4.3 burst_load.bin

```
V_max = 1.0995
|                                                                  |
|                                                                  |
|                                                                  |
|                                                                  |
|                                                                  |
|                                                                  |
|                                                                  |
|                                                                  |
| #                                                                |
| #                                                  #             |
| #      #     #     #     #      #     #     #      #     #       |
| ################################################################ |
V_min = 0.0449
  t=0 ms -> t=299900 ms
```


## 5. Oscillation / Transition Log

### 5.1 steady.bin

| t_ms | prev | next | dV |
|------|------|------|----|
| — | — | — | (no transitions recorded) |

### 5.2 thermal_storm.bin

| t_ms | prev | next | dV |
|------|------|------|----|
| — | — | — | (no transitions recorded) |

### 5.3 burst_load.bin

| t_ms | prev | next | dV |
|------|------|------|----|
| — | — | — | (no transitions recorded) |


## 6. Defaults Within the Stable Region

Shipping default: θ_latency_enter = 1.00, θ_thermal_enter = 0.85, τ_hold = 750 ms.

Default sweep row: oscillations=0, WCD=0.0000, RT=0.0 ms, dV/dt=-0.000000002 → **PASS**

Best corner (min oscillations, min WCD): θL=0.70, θT=0.75, τ_hold=550 → oscillations=0, WCD=0.0000, stable=true

Stable grid cells: 280 / 280 (100.0%). Default is inside the stable region.


## 7. Reproducibility

- PRNG seed: `0xC0FFEE`
- Commit: `HEAD`
- Simulator binary reads `coherence/daemon/include/coherence_types.h` for the contract.
- To reproduce: `make stability-report` from `coherence/simulator/`.
- Trace files live in `coherence/simulator/traces/` and are regenerated if missing.
