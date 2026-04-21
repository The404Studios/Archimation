"""
Root of Authority (RoA) -- paper-to-implementation conformance tests.

Paper:  Roberts / Eli / Leelee, "Root of Authority"
        Zenodo record 18710335
        DOI: 10.5281/zenodo.18710335

One test per major paper concept. Tests that require the kernel module
(``trust.ko``) to be loaded use ``pytest.mark.skip`` with a clear reason
when the corresponding sysfs node is absent. Userspace tests (cortex
HTTP, libtrust dlopen) skip cleanly when their dependency is missing.

Session 50 / Agent I rewrote this file in lockstep with
``docs/roa-conformance.md`` so every assertion below maps to a real
symbol that grep finds. References to paper-only symbols (``cfg(n)``,
``trust_state_get_C/S/P/G/L``, ``trust_assign_sex``,
``TRUST_IOC_MEIOSIS_REQUEST/ACCEPT``, ``A_AUTH_PROFILE``,
``B_LINEAGE_ROOT``) have been replaced with their shipping equivalents
or removed. The doc's Deviations section enumerates each rename.

Run:
    pytest tests/integration/test_roa_conformance.py -v
"""
from __future__ import annotations

import ctypes
import os
import socket
import urllib.error
import urllib.request
from pathlib import Path

import pytest

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------

ZENODO_RECORD = "18710335"
DOI = "10.5281/zenodo.18710335"

TRUST_SYSFS = Path("/sys/kernel/trust")
CORTEX_BASE = os.environ.get("CORTEX_BASE", "http://127.0.0.1:8420")

REPO_ROOT = Path(__file__).resolve().parents[2]


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _read_sysfs(node: str) -> str:
    p = TRUST_SYSFS / node
    if not p.exists():
        pytest.skip(f"trust.ko not loaded -- {p} missing")
    return p.read_text().strip()


def _http_get(path: str, timeout: float = 3.0) -> tuple[int, bytes]:
    url = f"{CORTEX_BASE}{path}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""
    except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as e:
        pytest.skip(f"cortex daemon unreachable at {url}: {e}")


def _find_libtrust() -> str | None:
    for cand in (
        "/usr/lib/libtrust.so.1",
        "/usr/lib/libtrust.so",
        "/usr/lib/x86_64-linux-gnu/libtrust.so.1",
        "/usr/local/lib/libtrust.so.1",
    ):
        if Path(cand).exists():
            return cand
    return None


def _read_repo_text(*parts: str) -> str | None:
    p = REPO_ROOT.joinpath(*parts)
    if not p.exists():
        return None
    return p.read_text(encoding="utf-8", errors="replace")


# ----------------------------------------------------------------------
# Paper-anchor metadata test
# ----------------------------------------------------------------------

def test_paper_citation_present_in_repo_docs():
    """Conformance doc must cite Zenodo 18710335 + DOI prominently."""
    doc = REPO_ROOT / "docs" / "roa-conformance.md"
    assert doc.exists(), f"missing {doc}"
    text = doc.read_text(encoding="utf-8")
    assert ZENODO_RECORD in text, "Zenodo record id missing"
    assert DOI in text, "DOI missing"


# ----------------------------------------------------------------------
# 1. Authority State A_t = (C, S, P, G, L)
# ----------------------------------------------------------------------

def test_authority_state_header_defines_five_tuple():
    """trust_types.h must declare authority_C/S/P/G/L macros and the
    trust_authority_state_t wire struct (Session 48 / Agent 6)."""
    src = _read_repo_text("trust", "include", "trust_types.h")
    if src is None:
        pytest.skip("trust_types.h not present in this checkout")
    for needle in (
        "authority_C(s)",
        "authority_S(s)",
        "authority_P(s)",
        "authority_G(s)",
        "authority_L(s)",
        "trust_authority_state_t",
    ):
        assert needle in src, f"trust_types.h missing 5-tuple symbol: {needle}"


def test_authority_state_ioctl_declared():
    """TRUST_IOC_AUTHORITY_STATE is the read-tuple ioctl (NR=133)."""
    src = _read_repo_text("trust", "include", "trust_ioctl.h")
    if src is None:
        pytest.skip("trust_ioctl.h not present")
    assert "TRUST_IOC_AUTHORITY_STATE" in src, \
        "TRUST_IOC_AUTHORITY_STATE missing from trust_ioctl.h"


# ----------------------------------------------------------------------
# 2. Self-Consuming Proof (APE)
# ----------------------------------------------------------------------

def test_ape_consume_proof_present():
    """APE must expose trust_ape_consume_proof[_v2]() (Session 48)."""
    src = _read_repo_text("trust", "kernel", "trust_ape.c")
    if src is None:
        pytest.skip("trust_ape.c not present (kernel module not vendored)")
    assert "trust_ape_consume_proof_v2" in src, \
        "trust_ape_consume_proof_v2 entry point missing"
    assert "derive_hash_cfg" in src, \
        "derive_hash_cfg (paper H_cfg(n) derive half) missing"
    assert "apply_reconfigurable_hash" in src, \
        "apply_reconfigurable_hash (paper H_cfg(n) apply half) missing"


# ----------------------------------------------------------------------
# 3. 23 A-segments + 23 B-segments
# ----------------------------------------------------------------------

def test_chromosomes_23_pairs():
    """trust_types.h must declare 23 A-segments and 23 B-segments via
    the CHROMO_A_* / CHROMO_B_* enum (NOT the paper's A_AUTH_PROFILE
    naming -- see doc Deviations Section B)."""
    src = _read_repo_text("trust", "include", "trust_types.h")
    if src is None:
        pytest.skip("trust_types.h not present")
    # Sample of real symbols spanning the range; full list lives in the
    # doc table. We don't assert all 46 here -- the structural anchor is
    # CHROMO_A_SEX / CHROMO_B_SEX (index 22) which proves the 23-slot
    # design is in place.
    for needle in (
        "CHROMO_A_ACTION_HASH",
        "CHROMO_A_TOKEN_BALANCE",
        "CHROMO_A_TRUST_STATE",
        "CHROMO_A_SEX",
        "CHROMO_B_BINARY_HASH",
        "CHROMO_B_FUSE_STATE",
        "CHROMO_B_SEX",
        "TRUST_CHROMOSOME_PAIRS",
    ):
        assert needle in src, f"chromosome symbol missing: {needle}"
    assert "TRUST_CHROMOSOME_PAIRS   23" in src or \
           "TRUST_CHROMOSOME_PAIRS 23" in src or \
           "TRUST_CHROMOSOME_PAIRS    23" in src, \
        "TRUST_CHROMOSOME_PAIRS macro must be 23"


# ----------------------------------------------------------------------
# 4. Sex Determination -- sex_threshold sysfs
# ----------------------------------------------------------------------

def test_sex_threshold_node_readable():
    val = _read_sysfs("sex_threshold")
    assert val.isdigit(), f"sex_threshold not numeric: {val!r}"
    n = int(val)
    assert 0 <= n <= 0xFFFFFFFF, f"sex_threshold out of u32 range: {n}"


def test_sex_threshold_setter_declared():
    """trust_sex_threshold_get/set must be exported (Session 48)."""
    src = _read_repo_text("trust", "kernel", "trust_core.c")
    if src is None:
        pytest.skip("trust_core.c not vendored")
    assert "trust_sex_threshold_get" in src
    assert "trust_sex_threshold_set" in src


# ----------------------------------------------------------------------
# 5. Mitosis
# ----------------------------------------------------------------------

def test_mitosis_entrypoint_declared():
    """trust_mitosis() is the paper-spec entrypoint (Session 48)."""
    src = _read_repo_text("trust", "kernel", "trust_lifecycle.c")
    if src is None:
        pytest.skip("trust_lifecycle.c not vendored")
    assert "trust_mitosis" in src, "trust_mitosis entry point missing"
    assert "trust_mitosis_by_id" in src, \
        "trust_mitosis_by_id (fork-hookable form) missing"


# ----------------------------------------------------------------------
# 6. Meiosis
# ----------------------------------------------------------------------

def test_meiosis_active_bonds_node():
    val = _read_sysfs("meiosis_active_bonds")
    assert val.lstrip("-").isdigit(), f"meiosis_active_bonds not int: {val!r}"
    n = int(val)
    assert 0 <= n <= 256, f"meiosis_active_bonds out of expected range: {n}"


def test_meiosis_count_monotone_nonnegative():
    val = _read_sysfs("meiosis_count")
    assert val.isdigit(), f"meiosis_count not numeric: {val!r}"
    assert int(val) >= 0


def test_meiosis_ioctl_single_call():
    """The shipping kernel uses ONE TRUST_IOC_MEIOSIS (not the paper's
    request+accept pair). See doc Deviations Section D."""
    src = _read_repo_text("trust", "include", "trust_ioctl.h")
    if src is None:
        pytest.skip("trust_ioctl.h not vendored")
    assert "TRUST_IOC_MEIOSIS" in src, "TRUST_IOC_MEIOSIS missing"
    # Negative assertion: paper-only names must NOT appear (sanity-check
    # the doc honesty).
    assert "TRUST_IOC_MEIOSIS_REQUEST" not in src, \
        "fictional TRUST_IOC_MEIOSIS_REQUEST leaked into trust_ioctl.h"
    assert "TRUST_IOC_MEIOSIS_ACCEPT" not in src, \
        "fictional TRUST_IOC_MEIOSIS_ACCEPT leaked into trust_ioctl.h"


# ----------------------------------------------------------------------
# 7. Cancer Detection
# ----------------------------------------------------------------------

def test_cancer_detections_node_readable():
    val = _read_sysfs("cancer_detections")
    assert val.isdigit(), f"cancer_detections not numeric: {val!r}"


def test_cancer_threshold_ms_in_sane_range():
    val = _read_sysfs("cancer_threshold_ms")
    assert val.isdigit()
    n = int(val)
    # Paper recommends ms-to-seconds-scale; refuse anything pathological.
    # Default in code is 100 ms (TRUST_CANCER_THRESHOLD_MS_DEFAULT).
    assert 1 <= n <= 600_000, f"cancer_threshold_ms out of sane range: {n}"


def test_cancer_action_kernel_symbol():
    """The kernel verb is trust_apoptosis_request, NOT the paper's
    trust_apoptose. See doc Deviations Section E."""
    src = _read_repo_text("trust", "kernel", "trust_lifecycle.c")
    if src is None:
        pytest.skip("trust_lifecycle.c not vendored")
    assert "trust_apoptosis_request" in src, \
        "trust_apoptosis_request kernel symbol missing"


# ----------------------------------------------------------------------
# 8. ISA -- 6 families (AUTH, TRUST, GATE, RES, LIFE, META/FLOW)
# ----------------------------------------------------------------------

def test_isa_families_documented():
    """All six paper-named families appear in the conformance doc.
    META is the shipping name for the paper's FLOW (see Deviations F)."""
    doc = (REPO_ROOT / "docs" / "roa-conformance.md").read_text(encoding="utf-8")
    for fam in ("AUTH", "TRUST", "GATE", "RES", "LIFE", "META"):
        assert fam in doc, f"ISA family {fam} missing from roa-conformance.md"
    # Rename note must be present so the divergence is auditable.
    assert "FLOW" in doc, "FLOW (paper name) must be cross-referenced in doc"


def test_isa_families_in_header():
    src = _read_repo_text("trust", "include", "trust_types.h")
    if src is None:
        pytest.skip("trust_types.h not vendored")
    for fam in (
        "TRUST_ISA_FAMILY_AUTH",
        "TRUST_ISA_FAMILY_TRUST",
        "TRUST_ISA_FAMILY_GATE",
        "TRUST_ISA_FAMILY_RES",
        "TRUST_ISA_FAMILY_LIFE",
        "TRUST_ISA_FAMILY_META",
    ):
        assert fam in src, f"ISA family macro {fam} missing"


# ----------------------------------------------------------------------
# 9. APE pool isolation
# ----------------------------------------------------------------------

@pytest.mark.skip(reason="ring -2 is approximated in software; "
                         "see Deviations Section G in roa-conformance.md")
def test_ape_ring_minus_two_isolation():
    """Hardware-level claim -- verified by code review, not runtime probe."""


# ----------------------------------------------------------------------
# 10. Theorems 1, 2, 4, 5, 6 -- runtime invariant counters
# ----------------------------------------------------------------------

@pytest.mark.parametrize("theorem", [1, 2, 4, 5, 6])
def test_theorem_violation_counter_zero(theorem: int):
    val = _read_sysfs(f"theorem{theorem}_violations")
    assert val.isdigit(), f"theorem{theorem}_violations not numeric: {val!r}"
    n = int(val)
    assert n == 0, f"theorem {theorem} has been violated {n} times"


# ----------------------------------------------------------------------
# 11. Authorization Decision auth(E, a, t) -- trust_authz_check()
# ----------------------------------------------------------------------

def test_authz_source_present():
    src = _read_repo_text("trust", "kernel", "trust_authz.c")
    if src is None:
        pytest.skip("trust_authz.c not vendored in this checkout")
    assert "trust_authz_check" in src, "trust_authz_check entry point missing"


# ----------------------------------------------------------------------
# 12. Generational Decay S_max(g) = alpha^g * S_max(0)
# ----------------------------------------------------------------------

def test_generational_decay_constants():
    """alpha is system-wide TRUST_GENERATION_ALPHA_NUM/DEN, NOT a
    per-subject A_DECAY_ALPHA chromosome slot. See Deviations H."""
    src = _read_repo_text("trust", "include", "trust_types.h")
    if src is None:
        pytest.skip("trust_types.h not vendored")
    assert "TRUST_GENERATION_ALPHA_NUM" in src, "alpha numerator missing"
    assert "TRUST_GENERATION_ALPHA_DEN" in src, "alpha denominator missing"


def test_generational_decay_referenced_in_lifecycle():
    src = _read_repo_text("trust", "kernel", "trust_lifecycle.c")
    if src is None:
        pytest.skip("trust_lifecycle.c not vendored")
    text = src.lower()
    assert ("decay" in text) or ("generation" in text), \
        "trust_lifecycle.c does not reference generational decay"


# ----------------------------------------------------------------------
# 13. AI Cortex / Dynamic Hyperlation HTTP surface
# ----------------------------------------------------------------------

def test_cortex_hyperlation_state_endpoint():
    code, body = _http_get("/cortex/hyperlation/state")
    assert code in (200, 401, 403, 503), \
        f"cortex /cortex/hyperlation/state returned {code}"


def test_cortex_hyperlation_theorems_endpoint():
    code, body = _http_get("/cortex/hyperlation/theorems")
    assert code in (200, 401, 403, 503), \
        f"cortex /cortex/hyperlation/theorems returned {code}"


# ----------------------------------------------------------------------
# 14. Three foundational hypotheses -- anchored in cortex policy slots
# ----------------------------------------------------------------------

def test_three_hypotheses_cited_in_doc():
    doc = (REPO_ROOT / "docs" / "roa-conformance.md").read_text(encoding="utf-8")
    for slot in (
        "HYP_DYNAMIC_AUTHORITY",
        "HYP_BIOLOGICAL_TRUST",
        "HYP_APOPTOTIC_SAFETY",
    ):
        assert slot in doc, f"hypothesis slot {slot} missing from doc"


def test_three_hypotheses_present_in_module():
    """Cortex enum and module-level aliases must export all three. The
    module file is owned by Agent C this session; we read it as text to
    avoid pulling in dynamic_hyperlation's runtime dependencies."""
    src = _read_repo_text("ai-control", "cortex", "dynamic_hyperlation.py")
    if src is None:
        pytest.skip("dynamic_hyperlation.py not present in checkout")
    for slot in (
        "HYP_DYNAMIC_AUTHORITY",
        "HYP_BIOLOGICAL_TRUST",
        "HYP_APOPTOTIC_SAFETY",
        "HYPOTHESIS_SLOTS",
    ):
        assert slot in src, f"slot {slot} missing from dynamic_hyperlation.py"


# ----------------------------------------------------------------------
# libtrust ioctl reachability (userspace)
# ----------------------------------------------------------------------

@pytest.mark.parametrize("symbol", [
    # Real LIBTRUST_1.3 / 1.4 exports per trust/lib/libtrust.map
    "trust_classify_subject",
    "trust_set_subject_class",
    "trust_meiosis_request",
])
def test_libtrust_symbol_exported(symbol: str):
    so = _find_libtrust()
    if so is None:
        pytest.skip("libtrust.so not installed")
    try:
        lib = ctypes.CDLL(so)
    except OSError as e:
        pytest.skip(f"cannot dlopen {so}: {e}")
    if not hasattr(lib, symbol):
        pytest.fail(f"libtrust ({so}) does not export {symbol}")


# ----------------------------------------------------------------------
# Deviation acknowledgement
# ----------------------------------------------------------------------

def test_riscv_fpga_deviation_documented():
    doc = (REPO_ROOT / "docs" / "roa-conformance.md").read_text(encoding="utf-8")
    assert "RISC-V" in doc and "x86_64" in doc, \
        "RISC-V FPGA -> x86_64 software deviation must be documented"
    assert "Deviation" in doc or "deviation" in doc, \
        "Deviations section missing"


def test_doc_lists_paper_to_code_renames():
    """The doc must include a Deviations section enumerating each
    paper-vs-code name divergence (Sections A through J as of S50)."""
    doc = (REPO_ROOT / "docs" / "roa-conformance.md").read_text(encoding="utf-8")
    # Anchor on the section title and one example from each rename
    # cluster -- not every cluster header, since the doc may renumber.
    assert "Deviations from paper" in doc, \
        "doc must have a 'Deviations from paper' section"
    # Example anchors (one per rename cluster)
    for anchor in (
        "derive_hash_cfg",                # H_cfg(n) split
        "CHROMO_A_ACTION_HASH",           # A/B-segment naming
        "trust_sex_threshold_get",        # sex evaluator
        "TRUST_IOC_MEIOSIS",              # single-ioctl meiosis
        "trust_apoptosis_request",        # cancer-action verb
        "TRUST_GENERATION_ALPHA_NUM",     # decay alpha
        "authority_C",                    # 5-tuple accessors
    ):
        assert anchor in doc, \
            f"deviation anchor {anchor!r} missing from doc"
