"""Canonical translation between trust ontologies.

!!! SYNC-NOTICE -- keep byte-for-byte identical to
!!! ``ai-control/daemon/trust_translate.py``.
Cortex runs as a separate Python process (port 8421) and imports this as
a sibling; daemon cannot be imported from here.  When the canonical
module (in ``ai-control/daemon/``) changes, copy the new content here
verbatim.  Import-time asserts in both copies will fail loudly if they
drift.

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

All three coexist as plain Python ``int`` with no type tag, which is why
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
    "API_BAND_TO_KERNEL_FLOOR",
    "EXAMPLES",
    "api_band_to_kernel_score",
    "kernel_score_to_api_band",
    "cortex_reputation_to_kernel_score",
    "is_cortex_quarantined",
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
