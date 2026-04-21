# tests/bisim — Empirical bisimulation harness (S75 Agent D)

Roadmap anchor: `docs/s75_roadmap.md` §1.2.6 Item 6 — the engineering-
tolerable evidence that the trust kernel module (`trust.ko`) and a
future RISC-V/Verilator oracle implement the same Authority-Proof-Engine
state machine. A formal Coq/Isabelle bisimulation proof is 3-5
person-years (see seL4 precedent); the empirical harness fits a single
agent and closes enough of the gap that a peer reviewer cannot dismiss
the FPGA-vs-kernel equivalence claim.

## What lives here

| File | LOC (approx) | Purpose |
|------|------:|---------|
| `ape_pure_cross.py`       | ~250 | Reimplements `decode_cfg` + `heap_permute_init` + `apply_reconfigurable_hash` in pure Python; byte-exact against `trust/kernel/trust_ape.c`. Runs without a kernel. |
| `trace_harness.py`        | ~320 | `BisimHarness` orchestrator, `TraceEvent`/`Trace` schema, `OracleAdapter` ABC, `MockOracle`, `KernelOracle` skeleton. |
| `discrepancy_detector.py` | ~120 | First-divergence classifier: op-mismatch / length-mismatch / byte-mismatch / result-mismatch. |
| `test_bisim_smoke.py`     | ~140 | pytest entry — exercises all three + kernel-arm skip. |
| `conftest.py`             | ~35  | pytest fixtures (repo_root, bisim_dir, kernel_available). |

## What the APE pure cross-check covers

Three kernel functions, byte-exact reimplemented:

1. **`heap_permute_init`** (kernel `trust_ape.c:147`) — produces the
   720-row permutation table of `{0..7}` using the *iterative* form of
   Heap's algorithm. Identity permutation is row 0.
2. **`decode_cfg`** (kernel `trust_ape.c:194`) — extracts
   `(perm_idx, window, mask, rot)` from the first 4 bytes of a destroyed
   proof. Layout documented inline.
3. **`apply_reconfigurable_hash_pure`** (kernel `trust_ape.c:224`) —
   the per-byte left-rotate → windowed XOR mask → 8-byte block permute
   transform. Tail bytes `<8` bytes are left as-is, matching the kernel
   comment at `trust_ape.c:265`.

**NOT covered** (deferred):

- `compute_proof_v2`'s outer SHA-2/3/BLAKE2 dispatch: requires linking
  against the kernel crypto API. A Python `hashlib` reimpl would only
  prove Python agrees with Python. The transform step is where the moat
  claim bites (per roadmap §0.4 "behavioral-state binding").
- The xchg-read-and-zero atomicity: needs a live concurrent harness;
  belongs to `tests/adversarial/` (Agent A).
- APE state-machine transitions (`create_entity`, `consume_proof`,
  `destroy_entity`): need `/dev/trust` ioctl surface via libtrust.
  Handled by the `KernelOracle` skeleton here but **not wired** because
  of the RISC-V dependency described below.

## RISC-V dependency (deferred to Agent F)

The full end-to-end path — record a trace on the kernel side, replay on
the RISC-V/Verilator oracle, diff — is blocked on roadmap Item 8:

> **RISC-V kprobe syscall-tracer port** — `~240 LOC`, 22 call sites
> across `trust/kernel/trust_syscall.c` + `trust_memory.c` need
> `REG_ARG0..5` macros to work on `riscv64`. Current code uses x86_64
> `pt_regs` layout.

Until that lands, the harness runs in **Python-side only** mode:

- `ape_pure_cross.cross_check()` runs the pure functions against a
  fixture (if present) or against a self-consistency golden vector.
- `BisimHarness.record_trace()` + `MockOracle` runs end-to-end without
  ever touching the kernel.
- `KernelOracle.__init__` fails cleanly with `OSError` if `libtrust.so`
  is not present.

## How to plug in the Verilator oracle later

1. Finish Agent F's kprobe port; capture syscall traces to JSON via a
   new trace_tap writing to debugfs.
2. Build a `RiscvVerilatorOracle(OracleAdapter)` subclass that:
   - Spawns the Verilator simulation (or talks to an FPGA JTAG bridge).
   - Implements `submit_action` by translating each action to a
     memory-mapped register poke.
   - Implements `get_state_hash` by reading the APE state register bank.
3. Write `tests/bisim/ape_vectors.json` fixture by running the kernel
   tap in a clean-slate QEMU ARCHIMATION boot and capturing 10 tuples.
4. Run `pytest tests/bisim/` — `cross_check` flips from `python-self`
   mode to `kernel-fixture` mode automatically.

## Expected outcomes (WSL dev host)

```
$ pytest tests/bisim/test_bisim_smoke.py -v
tests/bisim/test_bisim_smoke.py::test_perm_table_size_and_identity_first PASSED
tests/bisim/test_bisim_smoke.py::test_apes_cfg_total_matches_paper PASSED
tests/bisim/test_bisim_smoke.py::test_decode_cfg_zero_proof_is_identity PASSED
tests/bisim/test_bisim_smoke.py::test_decode_cfg_known_vector PASSED
tests/bisim/test_bisim_smoke.py::test_apply_hash_zero_cfg_is_identity PASSED
tests/bisim/test_bisim_smoke.py::test_apply_hash_preserves_length PASSED
tests/bisim/test_bisim_smoke.py::test_ape_pure_cross_check_passes PASSED
tests/bisim/test_bisim_smoke.py::test_harness_record_and_replay_matched PASSED
tests/bisim/test_bisim_smoke.py::test_harness_json_roundtrip PASSED
tests/bisim/test_bisim_smoke.py::test_detector_negative_matched_traces_have_zero_discrepancies PASSED
tests/bisim/test_bisim_smoke.py::test_detector_positive_byte_mismatch PASSED
tests/bisim/test_bisim_smoke.py::test_detector_positive_op_mismatch PASSED
tests/bisim/test_bisim_smoke.py::test_detector_positive_length_mismatch PASSED
tests/bisim/test_bisim_smoke.py::test_detector_positive_result_mismatch_non_bytelike PASSED
tests/bisim/test_bisim_smoke.py::test_kernel_oracle_skips_cleanly_without_libtrust PASSED
```

## Fixture contract

`tests/bisim/fixtures/ape_vectors.json` is a JSON list of objects with
shape:

```json
[
  {
    "cfg_proof_hex":       "<32-byte hex of destroyed P_n>",
    "input_hex":           "<N-byte hex of the pre-transform buffer>",
    "expected_output_hex": "<N-byte hex of the post-transform buffer>"
  }
]
```

The fixture is produced by a kernel-side helper (planned for
`tests/adversarial/helpers.c`, Agent A) that calls
`apply_reconfigurable_hash()` via a debug ioctl and emits the three
hex blobs. `cross_check()` prefers the fixture when present; falls
back to `python-self` mode otherwise.

Any byte-mismatch between the fixture and the Python reimpl is a
**hard regression** — either the kernel transform drifted or the
Python reimpl did. Both cases require investigation before the next
paper submission.
