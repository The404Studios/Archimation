"""Canonical translation between trust ontologies.

Session 41's A5 audit found that the word "trust" in this codebase covers at
least five distinct numeric domains that overlap in the positive integers,
producing silent unit-confusion bugs (e.g. comparing a band "600" against a
kernel score "600" when one means "admin-tier API endpoint" and the other
means "slightly-above-default kernel reputation").

This module is the single, canonical translator.  All boundary crossings
between the three numeric ontologies below MUST go through these functions.

Ontologies
----------
- Kernel trust score: ``int`` in ``[-1000, +1000]`` (signed, continuous).
  Produced by ``trust.ko``; exposed via ``/dev/trust`` ioctl and the
  ``TrustObserver`` profile ``last_score`` field.  Default for new
  subjects is ``+200`` (``TRUST_SCORE_DEFAULT``).

- API band: ``int`` in the discrete set
  ``{0, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000}``.  Populated
  by ``auth.ENDPOINT_TRUST`` and the JWT ``trust`` claim.  Semantic tiers
  roughly: ``0`` = public, ``200`` = read, ``400`` = mutate,
  ``600`` = admin, ``900`` = kernel-equivalent.

- Cortex reputation: ``int`` in ``[0, 100]``.  Bounded, non-negative.
  Maintained by the cortex trust-history module as a "clean score"; used
  by decision_engine / autonomy for throttling.

- PE-gate level: ``int`` in ``[5, 90]``.  Five-step ladder used by the
  PE loader trust gate to classify per-DLL load decisions
  (5=public/unsigned, 30=user, 60=service, 80=admin, 90=kernel/signed).
  Originally implemented inside ``pe_loader/loader/pe_trust_gate.c`` with
  no canonical Python translator; this module is now the canonical one.

- Cortex record score: ``int`` in ``[0, 100]``.  An alias for
  cortex reputation when the source is the trust-history "record"
  (per-event aggregate) rather than the running quarantine reputation.

All five coexist as plain Python ``int`` with no type tag, which is why
Session 41 found collisions.  The functions below are the ONLY sanctioned
way to cross a boundary.
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "KERNEL_SCORE_MIN",
    "KERNEL_SCORE_MAX",
    "API_BAND_MIN",
    "API_BAND_MAX",
    "CORTEX_REP_MIN",
    "CORTEX_REP_MAX",
    "CORTEX_QUARANTINE_THRESHOLD",
    "PE_GATE_MIN",
    "PE_GATE_MAX",
    "PE_GATE_ANCHORS",
    "API_BAND_TO_KERNEL_FLOOR",
    "EXAMPLES",
    "api_band_to_kernel_score",
    "kernel_score_to_api_band",
    "cortex_reputation_to_kernel_score",
    "is_cortex_quarantined",
    "pe_gate_to_kernel",
    "kernel_to_pe_gate",
    "record_to_band",
    "band_to_record",
]

# ── Range constants (single source of truth) ──

KERNEL_SCORE_MIN: Final[int] = -1000
KERNEL_SCORE_MAX: Final[int] = 1000

API_BAND_MIN: Final[int] = 0
API_BAND_MAX: Final[int] = 1000

CORTEX_REP_MIN: Final[int] = 0
CORTEX_REP_MAX: Final[int] = 100

# Below this cortex reputation, the subject is treated as quarantined
# (caller should reject even if kernel score is otherwise acceptable).
CORTEX_QUARANTINE_THRESHOLD: Final[int] = 10

# PE-gate level: a 5-step ladder used by the PE loader's per-DLL trust
# gate (see pe_loader/loader/pe_trust_gate.c). The numeric values are
# intentionally non-linear — each anchor maps to a specific kernel
# trust-score floor that the loader must observe before allowing a DLL
# in that tier to be linked into a process.
PE_GATE_MIN: Final[int] = 5
PE_GATE_MAX: Final[int] = 90

PE_GATE_ANCHORS: Final[dict[int, int]] = {
    5:   -500,   # public/unsigned PE — anyone load
    30:    50,   # user-scoped PE
    60:   400,   # service-scoped PE
    80:   700,   # admin-scoped PE
    90:  1000,   # kernel/signed PE
}
_PE_GATE_SORTED: Final[tuple[int, ...]] = tuple(sorted(PE_GATE_ANCHORS))

# ── API band → kernel score floor mapping ──
#
# This table is the CANONICAL mapping from an API band (the coarse tier
# required by ``auth.ENDPOINT_TRUST``) to the minimum kernel trust score
# a subject must have to be considered "in" that band.
#
# Shape: monotonic, piecewise-linear, spanning the full kernel range so
# that band 0 floors at ``KERNEL_SCORE_MIN`` (anyone is welcome) and
# band 1000 floors at ``KERNEL_SCORE_MAX`` (kernel-only).  Anchored at
# band 200 == score 0 (the symmetric centre) and at band 400 == score
# +300 (roughly the "default + slight positive history" zone).
#
# The specific anchors are the ones Session 41 cited:
#   band 0    → -1000   (public; floor at min)
#   band 100  →  -200   (linear interpolation on the negative half)
#   band 200  →     0   (boundary between negative and positive)
#   band 300  →  +150   (halfway to the default-plus zone)
#   band 400  →  +300   (slightly above default score 200)
#   band 500  →  +500   (midpoint of positive half)
#   band 600  →  +700   (admin; must be in "strong positive" zone)
#   band 700  →  +800
#   band 800  →  +900
#   band 900  → +1000   (kernel-equivalent; ceiling)
#   band 1000 → +1000   (same ceiling; kept for symmetry with API_BAND_MAX)
API_BAND_TO_KERNEL_FLOOR: Final[dict[int, int]] = {
    0:    -1000,
    100:   -200,
    200:      0,
    300:    150,
    400:    300,
    500:    500,
    600:    700,
    700:    800,
    800:    900,
    900:   1000,
    1000:  1000,
}

# Sorted band list for binary-ish lookups and inverse walks.
_BANDS_SORTED: Final[tuple[int, ...]] = tuple(sorted(API_BAND_TO_KERNEL_FLOOR))


def _clamp(value: int, lo: int, hi: int) -> int:
    """Clamp an ``int`` into ``[lo, hi]`` inclusive."""
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _require_int(name: str, value: object) -> int:
    """Reject non-integer inputs with a ``TypeError``.

    Accepts ``bool`` grudgingly (it is an ``int`` subclass in Python) but
    rejects ``float`` because silent truncation is how Session 41's bugs
    started in the first place.
    """
    if isinstance(value, bool):
        # bool is int, but we want a clear-cut integer caller.
        return int(value)
    if isinstance(value, int):
        return value
    raise TypeError(
        f"trust_translate: {name!r} must be int, got {type(value).__name__}"
    )


def api_band_to_kernel_score(band: int) -> int:
    """Return the minimum kernel trust score required to satisfy ``band``.

    Args:
        band: API band value.  Must be an integer.  Negative values clamp
            to ``0``; values above ``1000`` clamp to ``1000``; values
            between defined anchors are resolved by walking down to the
            nearest defined anchor (i.e. the floor of the containing band).

    Returns:
        Kernel trust score floor in ``[KERNEL_SCORE_MIN, KERNEL_SCORE_MAX]``.

    Raises:
        TypeError: if ``band`` is not an integer.
    """
    band_i = _require_int("band", band)
    band_i = _clamp(band_i, API_BAND_MIN, API_BAND_MAX)

    # Exact hit.
    if band_i in API_BAND_TO_KERNEL_FLOOR:
        return API_BAND_TO_KERNEL_FLOOR[band_i]

    # Off-anchor band (e.g. 250): floor to the largest defined band
    # that is <= band_i.  Monotonic by construction.
    floor_band = API_BAND_MIN
    for anchor in _BANDS_SORTED:
        if anchor <= band_i:
            floor_band = anchor
        else:
            break
    return API_BAND_TO_KERNEL_FLOOR[floor_band]


def kernel_score_to_api_band(score: int) -> int:
    """Return the highest API band whose floor ``<= score``.

    The inverse of ``api_band_to_kernel_score``.  Inherently lossy because
    API bands are discrete: many kernel scores map to the same band.

    Args:
        score: Kernel trust score.  Must be an integer.  Clamped into
            ``[KERNEL_SCORE_MIN, KERNEL_SCORE_MAX]``.

    Returns:
        The largest defined band ``b`` such that
        ``API_BAND_TO_KERNEL_FLOOR[b] <= score``.  Guaranteed to return
        a value from ``API_BAND_TO_KERNEL_FLOOR``.

    Raises:
        TypeError: if ``score`` is not an integer.
    """
    score_i = _require_int("score", score)
    score_i = _clamp(score_i, KERNEL_SCORE_MIN, KERNEL_SCORE_MAX)

    best = API_BAND_MIN
    for band in _BANDS_SORTED:
        if API_BAND_TO_KERNEL_FLOOR[band] <= score_i:
            best = band
        else:
            break
    return best


def cortex_reputation_to_kernel_score(reputation: int) -> int:
    """Map a cortex reputation (``0..100``) to a kernel trust score.

    Linear mapping from ``[0, 100]`` to ``[-200, +1000]``.  Note the
    asymmetry: a cortex-quarantined subject (``rep=0``) maps to ``-200``
    rather than the kernel minimum, because cortex reputation 0 means
    "never seen or briefly misbehaved", not "actively malicious".  The
    kernel minimum is reserved for subjects the kernel itself has
    convicted.

    Anchor points:
        rep=  0  →  -200   (cortex freshly-bad / unknown)
        rep= 10  →  -80    (quarantine boundary)
        rep= 50  →  +400   (neutral)
        rep= 95  → +1060 → clamped to +1000
        rep=100  → +1000   (clamped)

    Callers should ALSO check ``is_cortex_quarantined(reputation)``
    when reputation is authoritative — the returned kernel score alone
    does not flag the quarantine condition.

    Args:
        reputation: Cortex reputation.  Must be an integer.  Clamped
            into ``[CORTEX_REP_MIN, CORTEX_REP_MAX]``.

    Returns:
        Kernel trust score in ``[-200, +1000]``, inclusive.

    Raises:
        TypeError: if ``reputation`` is not an integer.
    """
    rep_i = _require_int("reputation", reputation)
    rep_i = _clamp(rep_i, CORTEX_REP_MIN, CORTEX_REP_MAX)

    # Linear: y = -200 + (1200 / 100) * rep  =  -200 + 12*rep
    raw = -200 + 12 * rep_i
    return _clamp(raw, KERNEL_SCORE_MIN, KERNEL_SCORE_MAX)


def is_cortex_quarantined(reputation: int) -> bool:
    """True if ``reputation < CORTEX_QUARANTINE_THRESHOLD``.

    Clamps garbage inputs rather than raising (callers frequently
    receive reputation from loose JSON).  ``TypeError`` is still raised
    for non-integers to catch upstream bugs loudly.
    """
    rep_i = _require_int("reputation", reputation)
    rep_i = _clamp(rep_i, CORTEX_REP_MIN, CORTEX_REP_MAX)
    return rep_i < CORTEX_QUARANTINE_THRESHOLD


def pe_gate_to_kernel(gate: int) -> int:
    """Translate a PE-loader gate level to the kernel trust score floor.

    The PE loader uses gate values in ``[PE_GATE_MIN, PE_GATE_MAX]``;
    each anchor in ``PE_GATE_ANCHORS`` maps to the kernel trust score
    a subject must have for a DLL of that tier to be linked.  Off-anchor
    inputs floor down to the nearest defined anchor (monotonic).

    Returns:
        Kernel trust score floor in
        ``[KERNEL_SCORE_MIN, KERNEL_SCORE_MAX]``.

    Raises:
        TypeError: if ``gate`` is not an integer.
    """
    g = _require_int("gate", gate)
    g = _clamp(g, PE_GATE_MIN, PE_GATE_MAX)
    if g in PE_GATE_ANCHORS:
        return PE_GATE_ANCHORS[g]
    floor_anchor = PE_GATE_MIN
    for a in _PE_GATE_SORTED:
        if a <= g:
            floor_anchor = a
        else:
            break
    return PE_GATE_ANCHORS[floor_anchor]


def kernel_to_pe_gate(score: int) -> int:
    """Inverse of ``pe_gate_to_kernel`` — return the highest PE gate
    whose floor ``<= score``.  Lossy because PE gates are discrete.
    """
    s = _require_int("score", score)
    s = _clamp(s, KERNEL_SCORE_MIN, KERNEL_SCORE_MAX)
    best = PE_GATE_MIN
    for a in _PE_GATE_SORTED:
        if PE_GATE_ANCHORS[a] <= s:
            best = a
        else:
            break
    return best


def record_to_band(record: int) -> int:
    """Translate a cortex record score (``[0, 100]``) to an API band.

    Composes ``cortex_reputation_to_kernel_score`` and
    ``kernel_score_to_api_band`` so all downstream comparisons go through
    the canonical kernel-score domain.  This is the function callers
    should use when an HTTP endpoint needs to know "is this subject
    above band 400 right now?" given only a record score.

    Raises:
        TypeError: if ``record`` is not an integer.
    """
    r = _require_int("record", record)
    r = _clamp(r, CORTEX_REP_MIN, CORTEX_REP_MAX)
    score = cortex_reputation_to_kernel_score(r)
    return kernel_score_to_api_band(score)


def band_to_record(band: int) -> int:
    """Lossy inverse of ``record_to_band``: lowest cortex record at
    which the subject would (after canonical translation) sit at-or-above
    ``band``.  Useful for documenting band thresholds in cortex terms.
    Returns ``CORTEX_REP_MAX`` if the band is unreachable from any
    record (i.e. requires a kernel score above the cortex-mapping
    ceiling).
    """
    b = _require_int("band", band)
    b = _clamp(b, API_BAND_MIN, API_BAND_MAX)
    target_score = api_band_to_kernel_score(b)
    # Walk record range, find the smallest record whose mapped score >=
    # the band's kernel floor.  The mapping is monotonic so a single
    # left-to-right scan suffices.
    for r in range(CORTEX_REP_MIN, CORTEX_REP_MAX + 1):
        if cortex_reputation_to_kernel_score(r) >= target_score:
            return r
    return CORTEX_REP_MAX


# ── Representative mappings, for docs + manual spot-checks ──

EXAMPLES: Final[dict[str, object]] = {
    "api_band_to_kernel_score": {
        0:    api_band_to_kernel_score(0),
        100:  api_band_to_kernel_score(100),
        200:  api_band_to_kernel_score(200),
        300:  api_band_to_kernel_score(300),
        400:  api_band_to_kernel_score(400),
        500:  api_band_to_kernel_score(500),
        600:  api_band_to_kernel_score(600),
        700:  api_band_to_kernel_score(700),
        800:  api_band_to_kernel_score(800),
        900:  api_band_to_kernel_score(900),
        1000: api_band_to_kernel_score(1000),
        # off-anchor + garbage clamps
        250:  api_band_to_kernel_score(250),
        -50:  api_band_to_kernel_score(-50),
        99999: api_band_to_kernel_score(99999),
    },
    "kernel_score_to_api_band": {
        -1000: kernel_score_to_api_band(-1000),
        -500:  kernel_score_to_api_band(-500),
        0:     kernel_score_to_api_band(0),
        200:   kernel_score_to_api_band(200),   # default
        500:   kernel_score_to_api_band(500),
        700:   kernel_score_to_api_band(700),
        1000:  kernel_score_to_api_band(1000),
    },
    "cortex_reputation_to_kernel_score": {
        0:   cortex_reputation_to_kernel_score(0),
        10:  cortex_reputation_to_kernel_score(10),
        50:  cortex_reputation_to_kernel_score(50),
        95:  cortex_reputation_to_kernel_score(95),
        100: cortex_reputation_to_kernel_score(100),
    },
    "pe_gate_to_kernel": {g: pe_gate_to_kernel(g) for g in _PE_GATE_SORTED},
    "record_to_band": {
        0:   record_to_band(0),
        25:  record_to_band(25),
        50:  record_to_band(50),
        75:  record_to_band(75),
        100: record_to_band(100),
    },
}


# ── Import-time invariant guards (cheap; run once on import) ──
#
# These are the Python equivalent of the ``_Static_assert`` guards the
# trust kernel uses in ``trust_cmd.h``.  If any anchor in
# ``API_BAND_TO_KERNEL_FLOOR`` drifts, import fails loudly so the bug
# never reaches a caller.

assert API_BAND_TO_KERNEL_FLOOR[0] == KERNEL_SCORE_MIN, (
    "band 0 must floor at kernel min"
)
assert API_BAND_TO_KERNEL_FLOOR[200] == 0, (
    "band 200 must sit at the kernel zero boundary"
)
assert API_BAND_TO_KERNEL_FLOOR[600] == 700, (
    "band 600 (admin) must require a strongly-positive kernel score"
)
assert API_BAND_TO_KERNEL_FLOOR[900] == KERNEL_SCORE_MAX, (
    "band 900 must ceiling at kernel max"
)

# Monotonicity: floor(band_i) strictly non-decreasing as band_i grows.
_prev = KERNEL_SCORE_MIN - 1
for _b in _BANDS_SORTED:
    _cur = API_BAND_TO_KERNEL_FLOOR[_b]
    assert _cur >= _prev, (
        f"API_BAND_TO_KERNEL_FLOOR not monotonic at band {_b}: "
        f"{_cur} < previous {_prev}"
    )
    _prev = _cur
del _b, _cur, _prev  # no module-level leakage

# Round-trip: band → score → band must land at a band whose floor equals
# the source band's floor (lossy inverse — two bands that share a floor
# collapse onto the higher one, which is correct by design at the ceiling
# where bands 900 and 1000 both floor at kernel +1000).
for _b in _BANDS_SORTED:
    _score = API_BAND_TO_KERNEL_FLOOR[_b]
    _rt = kernel_score_to_api_band(_score)
    assert API_BAND_TO_KERNEL_FLOOR[_rt] == _score, (
        f"round-trip band->score->band landed on a band with a different "
        f"floor: {_b} (floor {_score}) -> {_rt} "
        f"(floor {API_BAND_TO_KERNEL_FLOOR[_rt]})"
    )
del _b, _score, _rt

# Cortex mapping endpoints behave as documented.
assert cortex_reputation_to_kernel_score(0) == -200
assert cortex_reputation_to_kernel_score(100) == 1000
assert is_cortex_quarantined(5) is True
assert is_cortex_quarantined(10) is False
assert is_cortex_quarantined(50) is False

# PE-gate ladder: monotonic, anchored at MIN and MAX.
assert PE_GATE_ANCHORS[PE_GATE_MIN] == -500
assert PE_GATE_ANCHORS[PE_GATE_MAX] == KERNEL_SCORE_MAX
_pg_prev = KERNEL_SCORE_MIN - 1
for _g in _PE_GATE_SORTED:
    _gv = PE_GATE_ANCHORS[_g]
    assert _gv >= _pg_prev, (
        f"PE_GATE_ANCHORS not monotonic at gate {_g}: {_gv} < {_pg_prev}"
    )
    _pg_prev = _gv
del _g, _gv, _pg_prev

# pe_gate_to_kernel + kernel_to_pe_gate round-trip on anchors.
for _g in _PE_GATE_SORTED:
    _s = pe_gate_to_kernel(_g)
    _rt = kernel_to_pe_gate(_s)
    assert PE_GATE_ANCHORS[_rt] == _s, (
        f"PE-gate round-trip drift at gate {_g}: -> score {_s} -> gate {_rt}"
    )
del _g, _s, _rt

# record_to_band is monotonic non-decreasing.
_prev_band = -1
for _r in (0, 5, 10, 25, 50, 75, 95, 100):
    _b = record_to_band(_r)
    assert _b >= _prev_band, (
        f"record_to_band({_r}) = {_b} broke monotonicity (prev {_prev_band})"
    )
    _prev_band = _b
del _r, _b, _prev_band

# band_to_record + record_to_band must satisfy band_to_record(b) -> r,
# and record_to_band(r) >= b for any band reachable from cortex.
for _b in _BANDS_SORTED:
    _r = band_to_record(_b)
    if _r < CORTEX_REP_MAX:
        # Reachable: round-trip must satisfy it.
        assert record_to_band(_r) >= _b, (
            f"band_to_record({_b}) = {_r} but record_to_band({_r}) "
            f"= {record_to_band(_r)} (should be >= {_b})"
        )
del _b, _r


if __name__ == "__main__":
    # CLI smoke-test: print the canonical mapping table so a reviewer can
    # eyeball it without opening the module.  This is the same output an
    # operator would want in a ``trust-audit`` dump.
    print("=== trust_translate: canonical mapping table ===")
    print()
    print("API band -> kernel-score floor")
    print("-" * 40)
    for band in _BANDS_SORTED:
        print(f"  band {band:>4} -> kernel score >= {API_BAND_TO_KERNEL_FLOOR[band]:>+5}")
    print()
    print("Kernel score -> API band (inverse, lossy)")
    print("-" * 40)
    for score in (-1000, -500, -200, 0, 150, 200, 300, 500, 700, 900, 1000):
        print(f"  score {score:>+5} -> band {kernel_score_to_api_band(score):>4}")
    print()
    print("Cortex reputation -> kernel score")
    print("-" * 40)
    for rep in (0, 5, 10, 25, 50, 75, 95, 100):
        ker = cortex_reputation_to_kernel_score(rep)
        quar = " (QUARANTINED)" if is_cortex_quarantined(rep) else ""
        print(f"  rep {rep:>3} -> kernel {ker:>+5}{quar}")
    print()
    print("Garbage-input handling")
    print("-" * 40)
    print(f"  api_band_to_kernel_score(-50)     = {api_band_to_kernel_score(-50)}")
    print(f"  api_band_to_kernel_score(99999)   = {api_band_to_kernel_score(99999)}")
    print(f"  api_band_to_kernel_score(250)     = {api_band_to_kernel_score(250)}  (off-anchor, floors to band 200)")
    try:
        api_band_to_kernel_score(1.5)  # type: ignore[arg-type]
    except TypeError as e:
        print(f"  api_band_to_kernel_score(1.5)     -> TypeError: {e}")
