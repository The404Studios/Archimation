"""
Assembly index observer — S74 Agent 7 (Cronin/Walker assembly-theory layer).

Cronin & Walker (2017, 2022) define a molecule's *assembly index*, A, as the
minimum number of joining steps needed to build it from a finite alphabet of
primitive parts, with reuse of intermediate products allowed.  The companion
bound σ is the alphabet-size-to-the-A upper bound on the number of distinct
objects reachable at that depth:

    σ = |Σ|^A

We apply the same pair to a binary: "parts" are the union of imports and
recognisable function prologues; "joining steps" are the reachable edges in a
lightweight call / import graph; A is an approximation of the path length
needed to assemble the whole executable from those parts.

Purpose within ARCHIMATION:

    * Low A AND low σ  → trivial / likely auto-generated / possibly hostile —
      flag for trust_observer scrutiny.
    * High A          → genuine assembled object.
    * σ is reported alongside A to capture "this assembly could have produced
      many alternatives" vs. "this is one of very few possible objects".

Uses capstone when available for best accuracy; falls back to a header +
prologue scan that still yields a plausible (A, σ) on any host.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import os
import re
import struct
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Optional, Tuple

logger = logging.getLogger("aicontrol.assembly_index")

LRU_SIZE = 256
MAX_SAMPLE = 1 << 20           # 1 MiB — enough for any UPX-stripped exe
TRIVIAL_A_THRESHOLD = 5
TRIVIAL_SIGMA_THRESHOLD = 10

# Common x86-64 function prologues (rough; used only in fallback).
# push rbp; mov rbp, rsp             → 55 48 89 e5
# sub rsp, imm8                      → 48 83 ec ??
# endbr64                            → f3 0f 1e fa
# push rbx                           → 53
_PROLOGUES = [
    b"\x55\x48\x89\xe5",
    b"\xf3\x0f\x1e\xfa",
    b"\x48\x83\xec",
    b"\x53\x48\x83\xec",
    b"\x41\x57\x41\x56",
]

# PE / ELF magic
_PE_MAGIC = b"MZ"
_ELF_MAGIC = b"\x7fELF"


@dataclass
class AssemblyResult:
    pe_path: str
    ai: int
    sigma: float
    alphabet_size: int
    parts_found: int
    trivial: bool
    method: str          # "capstone" | "fallback"
    sha256: str
    ts: float


class _LRU(OrderedDict):
    """Tiny LRU cache keyed on content sha256."""

    def __init__(self, maxsize: int = LRU_SIZE):
        super().__init__()
        self._maxsize = maxsize

    def get_cached(self, k: str):
        if k in self:
            self.move_to_end(k)
            return self[k]
        return None

    def put(self, k: str, v: Any) -> None:
        if k in self:
            self.move_to_end(k)
        self[k] = v
        while len(self) > self._maxsize:
            self.popitem(last=False)


def _sha256_of_file(path: str, max_bytes: int = MAX_SAMPLE) -> Tuple[str, bytes]:
    """Return (hex digest of up to max_bytes, the bytes themselves)."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes)
    except (OSError, PermissionError):
        return "", b""
    return hashlib.sha256(data).hexdigest(), data


# ── PE / ELF import scanners (fallback path) ─────────────────────────────

def _parse_pe_imports(data: bytes) -> list[str]:
    """
    Extract imported DLL names + function names from a PE by walking the
    import directory.  Conservative — returns partial list rather than raise.
    """
    if len(data) < 0x40 or data[:2] != _PE_MAGIC:
        return []
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return []
        coff = e_lfanew + 4
        machine = struct.unpack_from("<H", data, coff)[0]
        size_opt = struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        # PE32 (0x10b) vs PE32+ (0x20b)
        if magic == 0x20B:
            data_dirs = opt + 112
        else:
            data_dirs = opt + 96
        # Import table is DataDirectory[1]
        imp_rva, imp_sz = struct.unpack_from("<II", data, data_dirs + 8)
        if imp_rva == 0 or imp_sz == 0:
            return []
        # Walk sections to map RVA → file offset
        sect_off = opt + size_opt
        n_sect = struct.unpack_from("<H", data, coff + 2)[0]
        sections = []
        for i in range(n_sect):
            base = sect_off + i * 40
            if base + 40 > len(data):
                break
            vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, base + 8)
            sections.append((vaddr, vsize, roff, rsize))

        def rva_to_off(rva: int) -> int:
            for va, vs, ro, rs in sections:
                if va <= rva < va + max(vs, rs):
                    return ro + (rva - va)
            return -1

        names: list[str] = []
        off = rva_to_off(imp_rva)
        if off < 0:
            return []
        while off + 20 <= len(data):
            oft, ts, fwd, name_rva, fthunk = struct.unpack_from("<IIIII", data, off)
            if name_rva == 0:
                break
            no = rva_to_off(name_rva)
            if no < 0 or no >= len(data):
                break
            end = data.find(b"\x00", no)
            if end < 0:
                break
            names.append(data[no:end].decode("ascii", "replace"))
            off += 20
        return names
    except (struct.error, IndexError, ValueError):
        return []


def _parse_elf_imports(data: bytes) -> list[str]:
    """
    Minimal ELF DT_NEEDED / dynamic symbol scanner.  Just counts unique
    strings that look like library names or symbol names for A-estimation.
    """
    if len(data) < 16 or data[:4] != _ELF_MAGIC:
        return []
    # Grep printable strings from the dynamic section range; cheap but works.
    names = set()
    for m in re.finditer(rb"(?:lib[a-zA-Z0-9._+-]+\.so(?:\.[0-9]+)*)|(?:[a-zA-Z_][a-zA-Z0-9_]{2,31})", data):
        s = m.group(0)
        if b".so" in s or len(s) >= 6:
            try:
                names.add(s.decode("ascii"))
            except UnicodeDecodeError:
                pass
        if len(names) >= 2048:
            break
    return sorted(names)[:2048]


def _count_prologues(data: bytes) -> int:
    """Count occurrences of recognisable function prologues."""
    total = 0
    for sig in _PROLOGUES:
        total += data.count(sig)
    return total


# ── capstone path ────────────────────────────────────────────────────────

def _capstone_disasm(data: bytes) -> Tuple[int, int]:
    """
    If capstone is importable, count (unique_mnemonics, total_instructions)
    on the first text-ish region.  Returns (0,0) when unavailable.
    """
    try:
        import capstone  # type: ignore
    except Exception:
        return 0, 0

    # Heuristic: try PE .text section, else ELF .text, else first executable slice
    offset, size = 0, min(len(data), MAX_SAMPLE)

    # PE .text lookup
    if data[:2] == _PE_MAGIC and len(data) > 0x40:
        try:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            coff = e_lfanew + 4
            size_opt = struct.unpack_from("<H", data, coff + 16)[0]
            n_sect = struct.unpack_from("<H", data, coff + 2)[0]
            sect_off = coff + 20 + size_opt
            for i in range(n_sect):
                base = sect_off + i * 40
                name = data[base:base + 8].rstrip(b"\x00")
                if name == b".text":
                    vsize, vaddr, rsize, roff = struct.unpack_from(
                        "<IIII", data, base + 8
                    )
                    offset, size = roff, min(rsize, MAX_SAMPLE)
                    break
        except struct.error:
            pass

    section = data[offset:offset + size]
    if not section:
        return 0, 0

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    mnemonics: set[str] = set()
    total = 0
    try:
        for insn in md.disasm_lite(section, 0x1000):
            mnemonics.add(insn[2])
            total += 1
            if total >= 200_000:
                break
    except capstone.CsError:
        pass
    return len(mnemonics), total


# ── core computation ─────────────────────────────────────────────────────

def _compute(pe_path: str, data: bytes, digest: str) -> AssemblyResult:
    """
    Estimate (A, σ):

    Capstone mode
        alphabet |Σ|       = unique mnemonics seen (bounded below by 8)
        A                  = log_|Σ|(unique_mnemonics) + log2(unique_imports+1)
                             + log2(total_instructions / max(unique_mnemonics,1)+1)
        σ                  = |Σ| ** A

    Fallback mode
        alphabet |Σ|       = imports ∪ {prologues}
        A                  = log2(parts + 1) + log2(unique_imports + 1)
        σ                  = |Σ| ** A
    """
    method = "fallback"
    is_pe = data[:2] == _PE_MAGIC
    is_elf = data[:4] == _ELF_MAGIC

    imports = _parse_pe_imports(data) if is_pe else _parse_elf_imports(data)
    unique_imports = len(set(imports))
    prologues = _count_prologues(data)

    mnemonics, total_insns = _capstone_disasm(data)
    if mnemonics > 0:
        method = "capstone"
        alphabet = max(mnemonics, 8)
        ai_est = (
            math.log2(max(mnemonics, 2))
            + math.log2(unique_imports + 1)
            + math.log2(max(total_insns, 1) / max(mnemonics, 1) + 1)
        )
    else:
        alphabet = max(unique_imports + len(_PROLOGUES), 4)
        # prologues approximate "distinct assembly sites"; imports give alphabet
        parts = max(prologues + unique_imports, 1)
        ai_est = math.log2(parts + 1) + math.log2(unique_imports + 1)

    ai = int(round(ai_est))
    # σ can overflow float easily — clamp at 1e300.
    try:
        sigma = float(alphabet) ** float(ai)
        if not math.isfinite(sigma):
            sigma = 1e300
    except OverflowError:
        sigma = 1e300

    trivial = (ai < TRIVIAL_A_THRESHOLD) and (sigma < TRIVIAL_SIGMA_THRESHOLD)

    return AssemblyResult(
        pe_path=pe_path,
        ai=ai,
        sigma=sigma,
        alphabet_size=alphabet,
        parts_found=unique_imports + prologues,
        trivial=trivial,
        method=method,
        sha256=digest,
        ts=time.time(),
    )


class AssemblyIndexer:
    """
    On-demand assembly-index calculator with a 256-entry LRU keyed on
    content sha256.  Thread-safe for the daemon's single event loop.
    """

    def __init__(self):
        self._cache: _LRU = _LRU(LRU_SIZE)
        self._callbacks: list[Callable[[dict], None]] = []
        self.stats = {"computed": 0, "cache_hits": 0, "trivial": 0, "errors": 0}

    def add_callback(self, cb: Callable[[dict], None]) -> None:
        self._callbacks.append(cb)

    def compute(self, pe_path: str) -> Optional[AssemblyResult]:
        """Synchronous compute; safe to call from an executor."""
        digest, data = _sha256_of_file(pe_path)
        if not data:
            self.stats["errors"] += 1
            return None
        cached = self._cache.get_cached(digest)
        if cached is not None:
            self.stats["cache_hits"] += 1
            return cached
        try:
            result = _compute(pe_path, data, digest)
        except Exception:
            logger.exception("assembly compute failed for %s", pe_path)
            self.stats["errors"] += 1
            return None
        self._cache.put(digest, result)
        self.stats["computed"] += 1
        if result.trivial:
            self.stats["trivial"] += 1
        self._emit({
            "source": "assembly",
            "pe_path": result.pe_path,
            "ai": result.ai,
            "sigma": result.sigma,
            "alphabet_size": result.alphabet_size,
            "parts_found": result.parts_found,
            "trivial": result.trivial,
            "method": result.method,
            "sha256": result.sha256,
            "ts": result.ts,
        })
        return result

    async def compute_async(self, pe_path: str) -> Optional[AssemblyResult]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.compute, pe_path)

    def on_pe_load(self, event: dict) -> None:
        """Callback shape matching trust_observer's TRUST_EVENT_LOAD_PE."""
        pe_path = event.get("path") or event.get("pe_path") or event.get("exe_path")
        if pe_path and os.path.isfile(pe_path):
            try:
                self.compute(pe_path)
            except Exception:
                logger.exception("on_pe_load failed")

    def _emit(self, event: dict) -> None:
        for cb in self._callbacks:
            try:
                r = cb(event)
                if asyncio.iscoroutine(r):
                    asyncio.create_task(r)
            except Exception:
                logger.exception("assembly callback error")

    # REST handler — agent 10 wires this into api_server.
    async def assembly_snapshot(self) -> dict:
        return {
            "stats": dict(self.stats),
            "cache_size": len(self._cache),
            "lru_capacity": LRU_SIZE,
            "recent": [
                {
                    "pe_path": r.pe_path,
                    "ai": r.ai,
                    "sigma": r.sigma if math.isfinite(r.sigma) else None,
                    "alphabet_size": r.alphabet_size,
                    "trivial": r.trivial,
                    "method": r.method,
                    "ts": r.ts,
                }
                for r in list(self._cache.values())[-32:]
            ],
            "ts": time.time(),
        }


def register_with_daemon(app, event_bus, trust_observer=None) -> AssemblyIndexer:
    """
    Build an AssemblyIndexer, wire its emissions to *event_bus*, subscribe
    to trust_observer PE-load events (if available), and register the REST
    snapshot endpoint on *app*.  Returns the indexer; caller keeps the ref.
    """
    idx = AssemblyIndexer()

    def _fanout(event: dict) -> None:
        for name in ("publish", "emit"):
            fn = getattr(event_bus, name, None)
            if callable(fn):
                try:
                    fn(event)
                    return
                except Exception:
                    logger.debug("event_bus.%s failed", name)
        logger.debug("assembly event (no bus sink): %s", event)

    idx.add_callback(_fanout)

    if trust_observer is not None and hasattr(trust_observer, "add_event_callback"):
        def _route(ev: dict) -> None:
            # trust_observer emits many event kinds; only act on PE-load-ish ones.
            t = ev.get("type") or ev.get("event")
            if t in ("pe_load", "TRUST_EVENT_LOAD_PE", "load_pe"):
                idx.on_pe_load(ev)
        try:
            trust_observer.add_event_callback(_route)
        except Exception:
            logger.debug("trust_observer subscription skipped")

    if app is not None:
        try:
            app.add_api_route(
                "/cortex/assembly/snapshot", idx.assembly_snapshot, methods=["GET"],
            )
        except Exception:
            logger.debug("FastAPI route registration skipped")
    return idx


__all__ = [
    "AssemblyIndexer",
    "AssemblyResult",
    "register_with_daemon",
]
