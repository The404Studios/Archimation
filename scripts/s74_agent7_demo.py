#!/usr/bin/env python3
"""S74 Agent 7 demo: exercise entropy_observer + assembly_index on stock binaries."""
import asyncio
import os
import sys
import math
import zlib
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "ai-control"))

from daemon.entropy_observer import (
    EntropyObserver, shannon_entropy_bits, compressibility, ncd, _read_region, _iter_maps,
)
from daemon.assembly_index import AssemblyIndexer


def baseline_calc(path):
    with open(path, "rb") as fh:
        s = fh.read(4096)
    counts = Counter(s)
    n = len(s)
    p = [c / n for c in counts.values()]
    h = sum(-x * math.log2(x) for x in p)
    c = len(zlib.compress(s, 1)) / len(s)
    return h, c


async def entropy_demo():
    # For each target binary, show Shannon entropy + compressibility + NCD
    # (NCD between pairs so we exercise that code path).
    targets = ["/usr/bin/ls", "/usr/bin/bash", "/usr/lib/systemd/systemd"]
    samples = {}
    for t in targets:
        if not os.path.exists(t):
            print(f"skip {t} (not present)")
            continue
        with open(t, "rb") as fh:
            samples[t] = fh.read(4096)

    print("=" * 68)
    print("ENTROPY OBSERVER — per-file 4 KiB sample")
    print("=" * 68)
    print(f"{'file':<28} {'H(bits)':>10} {'comp':>8} {'ncd(ls)':>10}")
    ls_sample = samples.get("/usr/bin/ls", b"")
    for t, s in samples.items():
        h = shannon_entropy_bits(s)
        c = compressibility(s)
        d = ncd(ls_sample, s) if ls_sample else float("nan")
        print(f"{t:<28} {h:>10.4f} {c:>8.4f} {d:>10.4f}")

    print()
    print("Baseline check via raw stdlib (must agree with observer):")
    for t in samples:
        h, c = baseline_calc(t)
        print(f"  {t}: H={h:.4f} comp={c:.4f}")


async def assembly_demo():
    idx = AssemblyIndexer()
    captured = []
    idx.add_callback(lambda e: captured.append(e))

    targets = ["/usr/bin/ls", "/usr/bin/bash", "/usr/lib/systemd/systemd"]
    print()
    print("=" * 68)
    print("ASSEMBLY INDEX — Cronin/Walker A and sigma")
    print("=" * 68)
    print(f"{'file':<28} {'A':>4} {'|Sigma|':>6} {'parts':>6} {'sigma':>14} {'trivial':>8} {'method':>9}")
    for t in targets:
        if not os.path.exists(t):
            print(f"skip {t}")
            continue
        r = idx.compute(t)
        if r is None:
            print(f"{t}: compute returned None")
            continue
        sigma_disp = f"{r.sigma:.3e}" if math.isfinite(r.sigma) else "inf"
        print(f"{t:<28} {r.ai:>4} {r.alphabet_size:>6} {r.parts_found:>6} "
              f"{sigma_disp:>14} {str(r.trivial):>8} {r.method:>9}")
    print()
    print(f"callback events captured: {len(captured)}")
    print(f"indexer stats: {idx.stats}")
    # Demonstrate LRU hit
    for t in targets:
        if os.path.exists(t):
            idx.compute(t)
    print(f"after second pass: {idx.stats}")


async def trivial_demo():
    import tempfile
    print()
    print("=" * 68)
    print("TRIVIAL DETECTION — tiny synthetic PE blob")
    print("=" * 68)
    blob = b"MZ" + b"\x00" * 256 + b"PE\x00\x00" + b"\x00" * 512
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as t:
        t.write(blob)
        path = t.name
    try:
        idx = AssemblyIndexer()
        r = idx.compute(path)
        print(f"  tiny blob: A={r.ai} alphabet={r.alphabet_size} sigma={r.sigma} trivial={r.trivial}")
        print(f"  indexer stats: {idx.stats}")
    finally:
        os.unlink(path)


async def main():
    await entropy_demo()
    await assembly_demo()
    await trivial_demo()


if __name__ == "__main__":
    asyncio.run(main())
