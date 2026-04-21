# S71-C: On-Device LLM Inference for ARCHWINDOWS Cortex (2024-2026)

**Author:** Research Agent C
**Date:** 2026-04-20
**Scope:** Optional LLM-augmented routing for the long tail + conversational responses. Must run on 4 GB Skylake integrated graphics **and** on 96 GB M2 Max. Zero telemetry. No phone-home.
**Current state:** `ai-control/daemon/llm.py` wraps `llama-cpp-python` with a global lock + optional GGUF load. Cortex already has Markov bigrams + 45K-phrase hand-tuned dictionary, which is the correct cheap-first layer. The LLM is the *last* fallback, not the first hop.

---

## 1. Model matrix 2026

All sizes below are **instruction-tuned, Q4_K_M GGUF** (the llama.cpp default). "MMLU" is the 5-shot published figure. "IFEval" is instruction-following (strict-prompt); higher is better. "RAM" = total resident during inference at 2K context. "CPU t/s" = generation throughput, llama.cpp on a modern x86 laptop CPU (Ryzen/Core Ultra with AVX2/AVX-512); halve for 2015-era Skylake.

| Model | Params | Q4 RAM | MMLU | IFEval | CPU gen t/s | License | Notes |
|---|---|---|---|---|---|---|---|
| **Qwen2.5-0.5B-Instruct** | 0.5 B | ~450 MB | 47.5 | 29.7 | 40-80 | Apache 2.0 | Draft-model grade; not standalone |
| **Llama 3.2 1B-Instruct** | 1.2 B | ~900 MB | 49.3 | **59.5** | 25-50 | Llama Community | Strong IFEval / size |
| **Qwen2.5-1.5B-Instruct** | 1.5 B | ~1.0 GB | 60.0 | 44.0 | 20-45 | Apache 2.0 | **Old-hardware pick** |
| **Gemma 3-1B-it** | 1.0 B | ~900 MB | 38.0 | ~56 | 25-50 | Gemma (permissive) | Multilingual, 32K ctx |
| **Llama 3.2 3B-Instruct** | 3.2 B | ~2.0 GB | 63.4 | **77.4** | 12-25 | Llama Community | Beats Phi-3.5 on IFEval |
| **Qwen2.5-3B-Instruct** | 3.1 B | ~1.9 GB | 65.6 | 58.2 | 12-25 | Qwen Research (non-commercial) | MMLU edge, watch license |
| **Phi-3.5-mini-instruct** | 3.8 B | ~2.3 GB | 69.0 | 59.2 | 10-22 | MIT | iPhone 14 hits 12 t/s |
| **Gemma 3-4B-it** | 4.3 B | ~2.6 GB | 59.6 | ~70 | 10-22 | Gemma | Multimodal (image-in) |
| **Qwen2.5-7B-Instruct** | 7.6 B | ~4.6 GB | **74.2** | 74.7 | 6-14 | Apache 2.0 | Best 8-GB-RAM pick |
| **Llama 3.1 8B-Instruct** | 8.0 B | ~4.9 GB | 68.0 | 72.0 | 6-13 | Llama Community | Reference workhorse |
| **Gemma 3-12B-it** | 12 B | ~7.4 GB | 64.7 | ~77 | 3-7 | Gemma | Competitive @ 12 B |
| **Phi-4** | 14 B | ~8.6 GB | **84.8** | ~59 | 2-5 | MIT | STEM monster; weak IFEval vs Qwen-14B |
| **Qwen2.5-14B-Instruct** | 14.7 B | ~9.0 GB | 79.7 | 81.0 | 2-5 | Apache 2.0 | Best <16 GB all-rounder |
| **Gemma 3-27B-it** | 27 B | ~17 GB | 76.2 (67.5 MMLU-Pro) | ~83 | 1-3 | Gemma | Chatbot-Arena 1338, beats Llama-3-405B |
| **Llama 3.3 70B-Instruct** | 70 B | ~40 GB | 86.0 | 92.1 | 0.4-1.2 | Llama Community | 64 GB+ RAM needed |

**Headline:** The sweet spot for a *routing-class* model (classify NL → handler + slot-fill) is **Qwen2.5-1.5B** or **Llama-3.2-3B**. Neither needs special hardware; both run on 2015 Skylake. For *conversational* replies the bar is MMLU ≥ 65, pointing at **Phi-3.5-mini**, **Llama-3.2-3B**, or **Qwen2.5-7B** (if the machine has 6 GB free). Phi-4 at 14 B is the reasoning monster but its IFEval is a known weak spot — bad choice for a router.

---

## 2. Quantization guide

### 2.1 Reference table (Mistral-7B / Llama-7B class, from llama.cpp quant README + Artefact2 KL table)

| Quant | Bits/w | 7B size | Δ PPL vs FP16 | KL-div | When to use |
|---|---|---|---|---|---|
| FP16 | 16.00 | 13.0 GB | 0 | 0 | Only if you have a GPU; never for storage |
| Q8_0 | 8.50 | 7.2 GB | +0.003 | ~0.001 | Server; want "perfect" accuracy |
| **Q5_K_M** | 5.67 | 4.78 GB | +0.012 | 0.0043 | 6-8 GB RAM; quality matters |
| **Q4_K_M** | 4.83 | 4.07 GB | **+0.054** | **0.0075** | **Default.** 4-5 GB sweet spot |
| Q4_K_S | 4.57 | 3.86 GB | +0.115 | 0.0083 | Tight on RAM, still good |
| Q4_0 | 4.50 | 3.50 GB | +0.250 | — | Legacy, avoid unless ARM NEON |
| **IQ3_M** | 3.66 | 3.2 GB | +0.22 | — | Need <4 GB; K-quant too big |
| IQ3_XS | 3.32 | 2.85 GB | +0.30 | 0.0296 | Phones / 2 GB RAM |
| **IQ2_M** | 2.76 | 2.4 GB | +0.55 | **0.0702** | Noticeable; use only >13 B models |
| IQ2_XS | 2.31 | 2.0 GB | +0.85 | 0.10 | Degraded; 13 B+ only |
| IQ1_M | 1.75 | 1.6 GB | +1.9 | — | Breaks <70 B; 70 B+ only |
| IQ1_S | 1.56 | 1.4 GB | +3.0+ | — | Experimental; skip |

### 2.2 Rules of thumb (distilled from the community quant guides)

1. **Below Q4 only makes sense for larger models.** IQ3/IQ2 on a 3 B model catastrophically degrades. On a 70 B model, IQ2_M is still coherent. The "quantize-up vs shrink-down" heuristic: **a 7 B Q4_K_M beats a 3 B Q8_0** at the same RAM budget almost always.
2. **K-quants (Q4_K_M, Q5_K_M) need no special calibration** and are shipped by every model publisher. **I-quants (IQ2/IQ3/IQ4_XS)** are importance-matrix-based and need an imatrix file (usually shipped alongside).
3. **Q4_K_M is the global default.** +0.054 PPL vs FP16 is inaudible in practice. Everything below Q4 degrades linearly, everything above Q5 is wasted bits on a routing/chat workload.
4. **Activations:** llama.cpp applies per-block dequantization — activation quantization (SmoothQuant, FP8) is a GPU-server concern (vLLM, TensorRT-LLM). For our workload: ignore.
5. **AWQ / GPTQ** are also weight-only post-training quant. **AWQ** usually beats GPTQ on small models; both are mainly useful for *GPU* inference (vLLM, TensorRT-LLM). For llama.cpp CPU: stick with GGUF Q4_K_M.

---

## 3. Runtime recommendation

### 3.1 Candidates

| Runtime | Lang | Platforms | Strengths | Weaknesses |
|---|---|---|---|---|
| **llama.cpp** (GGML backend) | C/C++ | CPU (x86/ARM), CUDA, Vulkan, Metal, ROCm | Universal, Q4_K_M GGUF is lingua franca, no Python deps needed, maintained by ggml-org | Not the fastest on Apple or NVIDIA |
| **llama-cpp-python** | Python | Same as llama.cpp | Easy FastAPI glue | Python dep chain; ABI pinning against CPython minor versions |
| **MLX / MLX-LM** | Python + C++ | **Apple only** | 20-87 % faster than llama.cpp on M-series for <14 B; saturates unified mem bandwidth | Nothing on Linux/Windows/x86 |
| **ONNX Runtime + DirectML / QNN** | C++/Python | Windows (DirectML, NPU QNN) | NPU path (Qualcomm, Intel), unified `Windows ML` system runtime | Model conversion required; GGUF→ONNX lossy |
| **vLLM** | Python | CUDA/ROCm (server) | Throughput via continuous batching + paged KV | GPU only; heavy; not for a single-user daemon |
| **TensorRT-LLM** | C++/Python | NVIDIA only | Fastest on NVIDIA; lookahead decoding | NVIDIA-locked; big build |
| **Ollama** | Go wrapper over llama.cpp | Cross-platform | "it just works" UX | Adds daemon-in-daemon; we already have a daemon |

### 3.2 Recommendation for ARCHWINDOWS

Keep **llama.cpp as the baseline everywhere** (it's the only option that runs on a 2015 Skylake laptop *and* a $5K workstation). Add **MLX as an optional fast-path on Apple Silicon**, and **ONNX Runtime + QNN/DirectML as an optional NPU fast-path on supported hardware**. The cortex should auto-select at boot. Drop the `llama-cpp-python` binding and shell out to the `llama.cpp` binary (`llama-server` / `llama-cli`) over a Unix socket — **fewer Python deps, no ABI pinning, same performance**. We already have the FastAPI daemon; it can just proxy.

Concrete selection function (draft):

```python
def pick_runtime() -> str:
    """Returns one of: "mlx", "qnn", "dml", "cuda", "vulkan", "metal", "cpu"."""
    import platform, shutil, os
    sys = platform.system()
    mach = platform.machine()
    # Apple Silicon → MLX (if installed) else llama.cpp Metal
    if sys == "Darwin" and mach == "arm64":
        if shutil.which("mlx_lm.generate"):
            return "mlx"
        return "metal"
    # NVIDIA → CUDA
    if os.path.exists("/dev/nvidia0"):
        return "cuda"
    # AMD ROCm
    if os.path.exists("/dev/kfd"):
        return "rocm"
    # Intel NPU (Meteor/Lunar Lake) via ONNXRT
    if os.path.exists("/dev/accel/accel0") and _has_intel_npu():
        return "intel_npu"
    # AMD XDNA NPU (Phoenix/Strix Halo) via xdna
    if os.path.exists("/dev/accel/accel0") and _has_amd_xdna():
        return "amd_xdna"
    # Vulkan fallback (works on nearly all GPUs)
    if _has_vulkan() and _gpu_has_at_least_vram_mb(2000):
        return "vulkan"
    # Integrated everything else → CPU + AVX2/AVX-512
    return "cpu"
```

The daemon spawns `llama-server --port 8421 --model <pick_model()> --n-gpu-layers <gl> --mlock --threads <nproc>` and pipes to `/ai/query`.

---

## 4. Speculative decoding fit

Speculative decoding (spec-dec) runs a small **draft** model to propose N tokens, then runs the **target** model once to verify all N. When the draft is ~10× smaller than the target and they share a vocab, this reliably delivers **2-3× speedup** at zero quality loss (`llama.cpp` `-md <draft.gguf> --draft-max 10`).

Published numbers (from the `ggml-org/llama.cpp` discussion #10466, LM Studio 0.3.10, Snowflake/vLLM):

- Qwen2.5-14B + Qwen2.5-0.5B draft: **2.5×** max speedup at 10 draft tokens (code); ~2.0× conversational.
- Qwen2.5-7B + Qwen2.5-0.5B draft: **~1.8-2.0×**.
- Llama-3.1-8B + Llama-3.2-1B draft: **~1.7×**.
- Phi-3-medium + Phi-3-mini: works but lower gain because size ratio < 5×.

**Fit for our daemon:**
- **8 GB RAM machine**: Qwen2.5-7B Q4_K_M (4.6 GB) + Qwen2.5-0.5B Q4 (0.5 GB) = 5.1 GB working set. **Yes, worth it** — turns 8 t/s into ~16 t/s, conversational becomes snappy.
- **4 GB RAM machine**: no margin. Run Qwen2.5-1.5B alone, skip spec-dec.
- **16 GB+**: Qwen2.5-14B + 0.5 B draft is the sweet pairing (2.5×, delivered).
- Draft ≥ 1.5 B **does not pay off** on our hardware; 0.5 B is the only draft worth shipping.

Implementation: `llama-server -m target.gguf -md draft.gguf --draft-max 8 --draft-p-min 0.4`.

---

## 5. NPU support status by vendor (April 2026)

| Vendor | Chip family | Peak TOPS | Linux kernel driver | Userspace | Status |
|---|---|---|---|---|---|
| **AMD XDNA** (gen 1) | Phoenix / Hawk Point | 10-16 | `amdxdna` **mainlined in 6.14**, initial merge hoped for 6.12 | XRT SHIM + Ryzen AI SW 1.7 | Production; out-of-tree backport for 6.10+ |
| **AMD XDNA2** (gen 2) | Strix Point / Halo (Ryzen AI 300/MAX+ 395) | **55** | `amdxdna` 6.14+ (also 6.17 docs) | XRT SHIM + ONNX-RT QNN EP | Production, Ubuntu 25.04 ships it |
| **Intel NPU 3720 / 4000** | Meteor / Arrow / Lunar / Panther Lake | 11 / 40 | `intel-vpu` **mainline** (6.6+) | OpenVINO + Level Zero 1.24 | Stable, `linux-npu-driver` v1.28 (Dec 2025) |
| **Qualcomm Hexagon** | Snapdragon X Elite / X2 | 45 | Kernel 6.8 onwards for SoC; **NPU driver upstream mainline = not yet (Q2 2026)** | Windows-only for LLM work (QNN EP); Linux NPU = binary only | Basic mainline support, NPU inference blocked on Linux |
| **Apple Neural Engine** | M1-M5 + A-series | 17-38 | N/A (closed; Metal used instead) | MLX / Core ML (from Linux: nothing) | Not reachable from Linux |

**Takeaway:** For Linux, Intel NPU is the most mature (OpenVINO + Level Zero is upstream and tested). AMD XDNA2 works on Ubuntu 25.04 + kernel 6.14+ with caveats (XRT SHIM is still a separate tarball). **Qualcomm Linux NPU for LLM = not yet on mainline.** On a Copilot+ PC booted into ARCHWINDOWS, the NPU is dark — we fall back to the Adreno GPU via Vulkan/OpenCL, which is still fine for 3 B models.

---

## 6. Graceful tier system

The cortex boot should read `/proc/meminfo`, `/proc/cpuinfo` and GPU nodes, then pick a tier. Override via `/etc/ai-control/cortex.conf : tier_override`.

| Tier | Detection | Default model | Quant | Spec-dec draft | Runtime | Expected gen t/s |
|---|---|---|---|---|---|---|
| **T0 — Markov only** | RAM < 2.5 GB, no GPU | (none) | — | — | — | fallback to Markov + 45K dict |
| **T1 — Phone-grade** | RAM 2.5-5 GB, iGPU | Qwen2.5-1.5B | Q4_K_M | — | llama.cpp CPU | 8-15 |
| **T2 — Laptop-grade** | RAM 6-10 GB | Llama-3.2-3B **or** Phi-3.5-mini | Q4_K_M | Qwen2.5-0.5B (opt) | llama.cpp CPU/Vulkan | 10-20 |
| **T3 — Workstation-grade** | RAM 12-20 GB, discrete GPU w/ ≥4 GB VRAM | Qwen2.5-7B | Q4_K_M | Qwen2.5-0.5B | llama.cpp CUDA/Vulkan | 25-50 |
| **T4 — Heavy-desktop** | RAM 24-48 GB, GPU ≥ 12 GB VRAM | Qwen2.5-14B or Phi-4 | Q4_K_M | Qwen2.5-0.5B | llama.cpp CUDA | 30-60 |
| **T5 — Pro** | RAM 48-128 GB, GPU ≥ 24 GB VRAM (4090/H100) or M-series ≥ 48 GB | Gemma-3-27B or Llama-3.3-70B | Q4_K_M | 7B draft | llama.cpp / MLX | 15-40 |
| **T6 — Apple Silicon** | M2+/M3+/M4 + ≥ 32 GB unified | Same as T4/T5 | Q4_K_M | Qwen2.5-0.5B | **MLX** | 40-230 |

**The one thing that impresses on old hardware:** **Qwen2.5-1.5B Q4_K_M** is ~1.0 GB on disk, ~1.1 GB resident, and delivers MMLU 60 + IFEval 44. On a **6th-gen Skylake i5-6500 with AVX2** it sustains **10-14 t/s** on llama.cpp built with `-march=native -mavx2`. That's fast enough to classify a natural-language command and return a one-sentence conversational confirmation in well under a second. A user on a 10-year-old Dell Optiplex gets an LLM-backed assistant for free, with **zero network I/O** — that is the distro's privacy story on a postcard.

---

## 7. Privacy considerations

- **Licenses to prefer (true permissive, no phone-home clause):** **Qwen2.5 (Apache 2.0)**, **Phi-3.5 / Phi-4 (MIT)**, **Gemma 3 (Gemma terms — permissive, commercial OK)**, **Mistral Small (Apache 2.0)**. These are what we ship.
- **Licenses to gate:** **Llama 3.x (Community License)** — 700 M MAU cap + EU acceptable-use restrictions. Probably fine for ARCHWINDOWS, but document the trap and keep a Qwen-based alternative as the default.
- **Qwen2.5-3B license gotcha:** Alibaba published the 3B variant under the **Qwen Research License** (non-commercial) while 0.5/1.5/7/14/32 B are Apache 2.0. Ship the 1.5B and 7B, skip the 3B.
- **No telemetry in llama.cpp.** Confirmed in source. No outbound sockets during inference. MLX, same. ONNX Runtime, same (local inference path).
- **Disk-resident models only.** Never fetch at runtime. All models pre-baked into `/var/lib/ai-control/models/` or the `ai-models-basic` Arch package.
- **Trust-gated loads.** `llm.load_model` should require `TRUST_ACTION_LOAD_MODEL` (consistent with S65 A1 `TRUST_ACTION_LOAD_KERNEL_BINARY`). A compromised service can't swap in a poisoned model.
- **Brand the feature.** "Your assistant runs 100 % on your CPU. Nothing leaves this machine." Put it in `fastfetch` next to the AI/Cortex/Trust badges from S64.

---

## 8. Implementation plan

### 8.1 File-level changes

| File | Change |
|---|---|
| `ai-control/daemon/llm.py` | Keep as today for backwards compat. Add `backend="llama-server" \| "llama-cpp-python" \| "mlx"` toggle; default `llama-server` subprocess when binary present. |
| `ai-control/daemon/llm_runtime.py` (**new**) | `detect_tier()` + `pick_model()` + `pick_runtime()`. Reads `/proc/meminfo`, `/proc/cpuinfo`, `/sys/class/drm/card*/device/vendor`, `/dev/kfd`, `/dev/nvidia0`, `/dev/accel/*`. |
| `ai-control/daemon/llm_spec.py` (**new**) | Thin wrapper: if target model is Qwen2.5-7B/14B or Llama-3.x-8B, auto-attach Qwen2.5-0.5B draft. |
| `ai-control/cortex/decision_engine.py` | Already has Markov last-chance. Add LLM last-**last**-chance: if confidence < 0.3 *and* `llm_tier >= T1`, call `llm.query` with a 4-shot classification prompt, cache result keyed on normalized phrase. |
| `packages/ai-control-daemon/PKGBUILD` | Add optdepend `llama.cpp` (pacman has it in `extra`); demote `python-llama-cpp` to alt-backend. |
| `packages/ai-models-basic/` (**new PKGBUILD**) | Pulls `Qwen2.5-1.5B-Instruct-Q4_K_M.gguf` + `Qwen2.5-0.5B-Instruct-Q4_K_M.gguf` into `/var/lib/ai-control/models/` (~1.5 GB total; optional) |
| `packages/ai-models-laptop/` | Llama-3.2-3B-Q4 **or** Phi-3.5-mini-Q4 (~2.2 GB) |
| `packages/ai-models-workstation/` | Qwen2.5-7B-Q4 + 0.5B draft (~5 GB) |
| `profile/packages.x86_64` | Do **not** auto-install any ai-models-* package (keep ISO small). Document the `sudo pacman -S ai-models-basic` path in first-boot MOTD. |
| `scripts/test-ai-commands.sh` | New T6 block: skip unless model present, load `Qwen2.5-1.5B`, run 10 classification probes, assert > 80 % correct routing. |

### 8.2 Why switch llama-cpp-python → llama-server subprocess

1. **Fewer Python deps.** llama-cpp-python pulls `cmake`, `scikit-build-core`, a local compile, and pins against one CPython minor. Broken twice in 2025 in AUR.
2. **Performance parity.** The bindings add Python-call overhead on every token; the REST server's per-token overhead is smaller than network latency over a Unix socket.
3. **Cleaner lifecycle.** `systemctl reload ai-control` can `kill -HUP` the server; OOM-killer only takes the server, daemon survives. Today an OOM in `llama-cpp-python` tombstones the whole Python process.
4. **Spec-dec is a command-line flag (`-md`).** The Python binding's spec-dec plumbing is less mature.
5. **Backwards compat:** keep `llama-cpp-python` path as `backend="llama-cpp-python"` for users who already set it.

### 8.3 Boot choreography

```
ai-control.service starts
  ├─ llm_runtime.detect_tier() → T2
  ├─ llm_runtime.pick_model() → /var/lib/ai-control/models/llama-3.2-3b-q4.gguf
  ├─ if trust_gate("TRUST_ACTION_LOAD_MODEL"): ok
  ├─ exec llama-server --port 8421 --model … --ctx-size 4096 --threads $(nproc) --mlock
  └─ wait for /health on 8421, then mark ready

cortex/decision_engine
  on low-confidence NL:
    post http://127.0.0.1:8421/completion with 4-shot classify prompt
    parse JSON; map to handler; confidence ← model's top-token prob
```

### 8.4 Zero-model graceful path

If `/var/lib/ai-control/models/` is empty (common on first-boot ISO), the cortex simply never promotes beyond T0 — Markov + 45K dictionary is the complete pipeline. The LLM is *purely* an upgrade available offline via `pacman -S ai-models-basic`. No degraded UX for users who opt out.

### 8.5 Test additions

- `tests/integration/test_llm_tier.py` — mock `/proc/meminfo`, assert `detect_tier()` returns the right tier for each fixture.
- `tests/integration/test_llm_classify.py` — if model present, run 20 known-good phrases, assert ≥ 18 route to the expected handler.
- `scripts/bench_llm.py` — one-shot t/s bench on whatever model is loaded; publish on first boot into `/var/log/ai-control/llm_bench.json` for telemetry-less diagnostics.

### 8.6 Bake sequencing

1. Land `llm_runtime.py` + tier detection (source-only, no new deps).
2. Land `llama-server` subprocess backend behind an opt-in env.
3. Add `ai-models-basic` PKGBUILD, publish Qwen2.5-1.5B-Q4 as a lean 1 GB add-on.
4. Flip cortex to optionally call LLM on low-confidence.
5. Bake pkg-17 ISO; run live test on a Skylake fixture + a Ryzen AI fixture + a Mac fixture (dogfood).

---

## 9. References

1. [Phi-4 Technical Report (Microsoft, Dec 2024)](https://arxiv.org/html/2412.08905v1)
2. [Qwen2.5 Technical Report (Qwen Team, Jan 2025)](https://arxiv.org/pdf/2412.15115)
3. [Qwen2.5-LLM blog — full model table](https://qwenlm.github.io/blog/qwen2.5-llm/)
4. [Gemma 3 Technical Report (Google DeepMind, Mar 2025)](https://arxiv.org/html/2503.19786v1)
5. [Llama 3.2 release post (Meta, Sep 2024)](https://ai.meta.com/blog/llama-3-2-connect-2024-vision-edge-mobile-devices/)
6. [llama.cpp quantization README](https://github.com/ggml-org/llama.cpp/blob/master/tools/quantize/README.md)
7. [GGUF quantization overview — Artefact2 KL table](https://gist.github.com/Artefact2/b5f810600771265fc1e39442288e8ec9)
8. [Demystifying LLM Quantization Suffixes — Paul Ilvez, Medium](https://medium.com/@paul.ilvez/demystifying-llm-quantization-suffixes-what-q4-k-m-q8-0-and-q6-k-really-mean-0ec2770f17d3)
9. [Choosing a GGUF Model: K-quants vs I-quants — Kaitchup substack](https://kaitchup.substack.com/p/choosing-a-gguf-model-k-quants-i)
10. [A Comparative Study of MLX, MLC-LLM, Ollama, llama.cpp (arXiv 2511.05502, Nov 2025)](https://arxiv.org/pdf/2511.05502)
11. [MLX vs llama.cpp on Apple Silicon — Groundy](https://groundy.com/articles/mlx-vs-llamacpp-on-apple-silicon-which-runtime-to-use-for-local-llm-inference/)
12. [SiliconBench — Apple Silicon LLM benchmarks](https://siliconbench.radicchio.page/)
13. [Speculative decoding potential — llama.cpp discussion #10466](https://github.com/ggml-org/llama.cpp/discussions/10466)
14. [LM Studio 0.3.10 Speculative Decoding notes](https://lmstudio.ai/blog/lmstudio-v0.3.10)
15. [Red Hat "Speculators" — production-ready spec-dec (Nov 2025)](https://developers.redhat.com/articles/2025/11/19/speculators-standardized-production-ready-speculative-decoding)
16. [AMD XDNA Linux driver documentation — kernel.org](https://docs.kernel.org/accel/amdxdna/amdnpu.html)
17. [AMDXDNA Linux driver v2 — Phoronix](https://www.phoronix.com/news/AMDXDNA-Linux-Driver-v2)
18. [Intel Linux NPU Driver repository](https://github.com/intel/linux-npu-driver)
19. [Intel Linux NPU Driver 1.6 for Meteor/Arrow/Lunar Lake — Phoronix](https://www.phoronix.com/news/Intel-Linux-NPU-Driver-1.6)
20. [ONNX Runtime QNN Execution Provider (Qualcomm NPU)](https://onnxruntime.ai/docs/execution-providers/QNN-ExecutionProvider.html)
21. [Snapdragon X Elite Laptop Performance On Linux End-of-Year 2025 — Phoronix](https://www.phoronix.com/review/snapdragon-x-elite-linux-eoy2025)
22. [Accelerating llama.cpp on AMD Ryzen AI 300 — AMD blog, 2024](https://www.amd.com/en/blogs/2024/accelerating-llama-cpp-performance-in-consumer-llm.html)
23. [AWQ: Activation-aware Weight Quantization (MLSys 2024 Best Paper)](https://proceedings.mlsys.org/paper_files/paper/2024/file/42a452cbafa9dd64e9ba4aa95cc1ef21-Paper-Conference.pdf)
24. [Comprehensive Evaluation of Quantized Instruction-Tuned LLMs up to 405B (arXiv 2409.11055)](https://arxiv.org/html/2409.11055v1)
25. [Phi-3.5-mini-instruct model card — Hugging Face](https://huggingface.co/microsoft/Phi-3.5-mini-instruct)
26. [Practical GGUF Quantization Guide for iPhone/Mac — Enclave AI (Nov 2025)](https://enclaveai.app/blog/2025/11/12/practical-quantization-guide-iphone-mac-gguf/)
