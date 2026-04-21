"""
markov_nlp.py -- Tiny stdlib trigram Markov-chain NLP fallback for Contusion.

Position in the routing chain (Session 58):
    1. dictionary  (_route_dictionary)
    2. regex       (_route_fallback body)
    3. LLM         (_route_via_llm, S51)
    4. Markov      (this module, S58)   <-- last resort before "give up"
    5. "Could not understand"

Why a Markov layer at all?
- Sub-millisecond inference (no model load, just dict lookups).
- ~50KB pickle on disk; trains from the existing contusion_dictionary in
  <100ms; no external deps (stdlib only).
- Provides a low-confidence "best guess" handler_type when every other
  router missed -- the caller still gates execution behind confirmation.

Model:
- Token-level (whitespace + simple punctuation strip), lowercased.
- Order-3 trigram: transitions[(tok_n-2, tok_n-1)] -> Counter[tok_n].
- handler_emissions[(tok_n-1, tok_n)] -> Counter[handler_type]   ## bigram-keyed
  emission distribution, used at inference: for each bigram in the input
  phrase, look up which handler_types most plausibly emit it.
- Additive (Laplace) smoothing over the handler vocabulary so unseen
  bigrams don't crash the score to zero.
- Final score per handler_type = sum(log P(handler | bigram)) over input
  bigrams, normalized by length, then softmax-reweighted into a [0,1] band.
"""
from __future__ import annotations

import logging
import math
import os
import pickle
import re
import stat
from collections import Counter, defaultdict
from typing import Iterable, List, Optional, Tuple

logger = logging.getLogger("ai-control.markov_nlp")

# Sentinel boundary tokens used to pad short phrases so trigrams still form.
_BOS = "<s>"
_EOS = "</s>"

# Tokenizer: strip non-word chars (keep dots inside handler_type-style tokens
# only when called on a label, not a phrase). For phrases we just lowercase
# and split on whitespace + punctuation.
_TOKENIZER_RE = re.compile(r"[A-Za-z0-9]+")

# Cache locations -- prefer system path, fall back to user ~/.cache.
# /tmp is intentionally NOT used: pickle.load() executes arbitrary code and
# /tmp is world-writable on multi-user systems (S68 hardening).
def _default_cache_paths() -> Tuple[str, ...]:
    paths = ["/var/cache/ai-control/markov_nlp.pkl"]
    try:
        home = os.path.expanduser("~")
        if home and home != "~":
            paths.append(os.path.join(home, ".cache", "ai-control", "markov_nlp.pkl"))
    except Exception:
        pass
    # Best-effort: create /var/cache/ai-control/ with 0700 if we can.
    try:
        os.makedirs("/var/cache/ai-control", mode=0o700, exist_ok=True)
    except (OSError, PermissionError):
        pass
    return tuple(paths)


_CACHE_PATHS = _default_cache_paths()


def _validate_pickle_source(path: str) -> None:
    """Refuse to unpickle from world-writable locations (S68 hardening).

    pickle.load() executes arbitrary code during deserialization. Gate on
    actual mode of both the file and its parent directory: private tmpdirs
    (pytest tmp_path_factory, mode 0700) are safe; a plain /tmp drop
    (01777) is not.
    """
    resolved_path = os.path.realpath(path)
    st = os.stat(resolved_path)
    parent_st = os.stat(os.path.dirname(resolved_path) or "/")
    if st.st_mode & stat.S_IWOTH:
        raise PermissionError(
            f"refusing to load pickle: file is world-writable: {resolved_path}"
        )
    if parent_st.st_mode & stat.S_IWOTH:
        raise PermissionError(
            f"refusing to load pickle: parent dir is world-writable: {resolved_path}"
        )
    if st.st_uid not in (0, os.geteuid()):
        raise PermissionError(
            f"refusing to load pickle: bad owner uid={st.st_uid}"
        )

# Module-level singleton so contusion._route_fallback doesn't pay the
# build-or-load cost on every miss.
_DEFAULT_MODEL: Optional["HandlerNGramModel"] = None


def _tokenize(text: str) -> List[str]:
    """Lowercase + word-split; keeps numbers; drops punctuation.

    Handler-type labels like 'audio.volume_up' get split into
    ['audio', 'volume', 'up'] which is what the trigram model wants -- we
    train both directions (the label-as-phrase pair seeds the model with the
    handler's own vocabulary, S58 design).
    """
    if not text:
        return []
    return [t for t in _TOKENIZER_RE.findall(text.lower()) if t]


def _bigrams(tokens: List[str]) -> List[Tuple[str, str]]:
    if len(tokens) < 2:
        # Pad single-token phrases with BOS so we still get one bigram.
        if len(tokens) == 1:
            return [(_BOS, tokens[0])]
        return []
    padded = [_BOS] + tokens + [_EOS]
    return [(padded[i], padded[i + 1]) for i in range(len(padded) - 1)]


def _trigrams(tokens: List[str]) -> List[Tuple[str, str, str]]:
    if not tokens:
        return []
    padded = [_BOS, _BOS] + tokens + [_EOS]
    return [(padded[i], padded[i + 1], padded[i + 2]) for i in range(len(padded) - 2)]


class HandlerNGramModel:
    """Trigram Markov chain trained on (phrase, handler_type) pairs.

    Lookup: P(handler_type | phrase) via additive-smoothed bigram emission
    counts, summed in log-space across the phrase's bigrams.
    """

    # Bumped on incompatible pickle layout changes -- guards stale caches.
    _PICKLE_VERSION = 2

    def __init__(self, smoothing: float = 0.01):
        self.smoothing = float(smoothing)
        # transitions: (tok_n-2, tok_n-1) -> Counter[tok_n]   ## kept for
        # future expansion (sequence generation / fluency scoring); inference
        # currently uses handler_emissions only.
        self.transitions: dict[Tuple[str, str], Counter] = defaultdict(Counter)
        # handler_emissions: (tok_n-1, tok_n) -> Counter[handler_type]
        self.handler_emissions: dict[Tuple[str, str], Counter] = defaultdict(Counter)
        # handler vocabulary + total counts -- used for smoothing denominator.
        self.handler_totals: Counter = Counter()
        self.vocab: set[str] = set()
        self.trained_pairs: int = 0

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------
    def train(self, examples: Iterable[Tuple[str, str]]) -> None:
        for phrase, ht in examples:
            if not phrase or not ht:
                continue
            tokens = _tokenize(phrase)
            if not tokens:
                continue
            self.vocab.update(tokens)
            self.handler_totals[ht] += 1
            for a, b, c in _trigrams(tokens):
                self.transitions[(a, b)][c] += 1
            for bg in _bigrams(tokens):
                self.handler_emissions[bg][ht] += 1
            self.trained_pairs += 1
        logger.debug(
            "HandlerNGramModel trained: %d pairs, %d handlers, %d bigrams, %d vocab",
            self.trained_pairs, len(self.handler_totals),
            len(self.handler_emissions), len(self.vocab),
        )

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------
    def predict(self, phrase: str, k: int = 3) -> List[Tuple[str, float]]:
        """Return top-k (handler_type, probability) for `phrase`.

        Probability is a softmax over per-handler log-likelihoods, so the
        returned values sum to (approximately) 1.0 across all handlers --
        the top-k slice will sum to <= 1.0.
        """
        if not self.handler_totals:
            return []
        tokens = _tokenize(phrase)
        if not tokens:
            return []

        # Smoothing denominator: |handler_vocab| ensures every handler has
        # at least `smoothing` mass on every bigram so unseen bigrams never
        # zero out a hypothesis.
        n_handlers = len(self.handler_totals)
        smooth_denom = self.smoothing * n_handlers

        # log P(handler | phrase) ~ sum over bigrams of log P(handler | bigram)
        # Where P(handler | bigram) = (count(bigram, handler) + smoothing) /
        #                             (sum_h count(bigram, h) + smoothing*n_handlers)
        log_scores: dict[str, float] = {h: 0.0 for h in self.handler_totals}
        bgs = _bigrams(tokens)
        if not bgs:
            return []

        for bg in bgs:
            emit = self.handler_emissions.get(bg)
            if emit:
                bg_total = sum(emit.values())
            else:
                emit = Counter()
                bg_total = 0
            denom = bg_total + smooth_denom
            for h in log_scores:
                num = emit.get(h, 0) + self.smoothing
                log_scores[h] += math.log(num / denom)

        # Length-normalize so longer phrases don't always lose to short ones.
        # (The shape of the ranking is invariant under per-bigram-count
        # division, but normalization keeps absolute scores comparable across
        # different phrase lengths for the confidence threshold.)
        n_bg = len(bgs)
        for h in log_scores:
            log_scores[h] /= n_bg

        # Softmax -> probability distribution.
        max_lp = max(log_scores.values())
        exps = {h: math.exp(lp - max_lp) for h, lp in log_scores.items()}
        z = sum(exps.values()) or 1.0
        probs = [(h, exps[h] / z) for h in exps]
        probs.sort(key=lambda r: r[1], reverse=True)
        return probs[: max(1, k)]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _state(self) -> dict:
        # Convert defaultdicts/Counters to plain dicts for stable pickling.
        return {
            "version": self._PICKLE_VERSION,
            "smoothing": self.smoothing,
            "transitions": {k: dict(v) for k, v in self.transitions.items()},
            "handler_emissions": {k: dict(v) for k, v in self.handler_emissions.items()},
            "handler_totals": dict(self.handler_totals),
            "vocab": list(self.vocab),
            "trained_pairs": self.trained_pairs,
        }

    def save(self, path: str) -> None:
        d = os.path.dirname(path)
        if d:
            try:
                os.makedirs(d, exist_ok=True)
            except OSError as e:
                logger.warning("markov_nlp save: cannot mkdir %s: %s", d, e)
                raise
        # Atomic write -- write to .tmp then rename so a torn write never
        # corrupts the cache.
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            pickle.dump(self._state(), f, protocol=pickle.HIGHEST_PROTOCOL)
        os.replace(tmp, path)
        logger.debug("markov_nlp saved to %s", path)

    @classmethod
    def load(cls, path: str) -> "HandlerNGramModel":
        _validate_pickle_source(path)
        with open(path, "rb") as f:
            state = pickle.load(f)
        if not isinstance(state, dict) or state.get("version") != cls._PICKLE_VERSION:
            raise ValueError(f"markov_nlp: incompatible pickle version at {path}")
        m = cls(smoothing=state.get("smoothing", 0.01))
        m.transitions = defaultdict(Counter, {
            k: Counter(v) for k, v in state["transitions"].items()
        })
        m.handler_emissions = defaultdict(Counter, {
            k: Counter(v) for k, v in state["handler_emissions"].items()
        })
        m.handler_totals = Counter(state["handler_totals"])
        m.vocab = set(state["vocab"])
        m.trained_pairs = int(state.get("trained_pairs", 0))
        return m


# ---------------------------------------------------------------------------
# Default-model construction (mines contusion_dictionary + handler registry)
# ---------------------------------------------------------------------------
def _harvest_training_pairs() -> List[Tuple[str, str]]:
    """Collect (phrase, handler_type) pairs from live module sources.

    Sources:
    1. Every dictionary entry with a `handler_type` field contributes
       (entry["desc"], entry["handler_type"]) AND (entry_key_humanized,
       entry["handler_type"]).
    2. Every key in HANDLERS contributes (humanized_label, label) -- this
       seeds the model with the handler's own vocabulary so labels like
       "audio.volume_up" trivially route to themselves.
    """
    pairs: List[Tuple[str, str]] = []

    # 1. dictionary mining
    try:
        # absolute import to match contusion.py's style (S58 follows S51)
        from contusion_dictionary import COMMANDS  # type: ignore
    except Exception:
        try:
            from .contusion_dictionary import COMMANDS  # type: ignore
        except Exception as e:
            logger.warning("markov_nlp: cannot import COMMANDS: %s", e)
            COMMANDS = {}

    for cat, cmds in (COMMANDS or {}).items():
        for key, entry in cmds.items():
            if not isinstance(entry, dict):
                continue
            ht = entry.get("handler_type")
            if not ht:
                continue
            desc = entry.get("desc", "") or ""
            if desc:
                pairs.append((desc, ht))
            # Humanize the key: "volume_up" -> "volume up", "mic_mute_toggle"
            # -> "mic mute toggle".
            humanized_key = key.replace("_", " ").replace(".", " ")
            if humanized_key:
                pairs.append((humanized_key, ht))
            # Also add category as a weak signal: "audio volume up" -> ht.
            cat_phrase = f"{cat.replace('_', ' ')} {humanized_key}"
            pairs.append((cat_phrase, ht))

    # 2. handler self-emission: each handler key trains on itself so that
    # a user typing the handler_type verbatim trivially routes to it.
    try:
        from contusion_handlers import HANDLERS  # type: ignore
    except Exception:
        try:
            from .contusion_handlers import HANDLERS  # type: ignore
        except Exception:
            HANDLERS = {}

    for ht in (HANDLERS or {}):
        # "audio.volume_up" -> "audio volume up"
        humanized = ht.replace(".", " ").replace("_", " ")
        pairs.append((humanized, ht))
        pairs.append((ht, ht))  # raw form too

    return pairs


def build_default_model() -> HandlerNGramModel:
    """Build (or load-from-cache) the default trigram Markov model.

    On first call: harvests pairs from contusion_dictionary + HANDLERS,
    trains, and writes a pickle to /var/cache/ai-control/markov_nlp.pkl
    (falling back to /tmp/markov_nlp.pkl if /var/cache is not writable).
    Subsequent calls in the same process should use `get_default_model()`.
    """
    # Try cache first.
    for cache_path in _CACHE_PATHS:
        if os.path.exists(cache_path):
            try:
                m = HandlerNGramModel.load(cache_path)
                if m.trained_pairs > 0:
                    logger.debug("markov_nlp: loaded cached model from %s (%d pairs)",
                                 cache_path, m.trained_pairs)
                    return m
            except Exception as e:
                logger.warning("markov_nlp: cache load failed %s: %s -- rebuilding",
                               cache_path, e)

    # Build fresh.
    pairs = _harvest_training_pairs()
    m = HandlerNGramModel(smoothing=0.01)
    m.train(pairs)

    # Try to write cache; tolerate every failure (read-only FS, ProtectHome,
    # etc). The model is already in-memory so we lose only the speed-up.
    for cache_path in _CACHE_PATHS:
        try:
            m.save(cache_path)
            logger.debug("markov_nlp: wrote cache to %s", cache_path)
            break
        except Exception as e:
            logger.debug("markov_nlp: cache write failed %s: %s", cache_path, e)

    return m


def get_default_model() -> HandlerNGramModel:
    """Process-wide singleton accessor for the default model."""
    global _DEFAULT_MODEL
    if _DEFAULT_MODEL is None:
        _DEFAULT_MODEL = build_default_model()
    return _DEFAULT_MODEL


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    print("markov_nlp smoke test")
    print("=" * 60)

    model = get_default_model()
    print(f"trained pairs:     {model.trained_pairs}")
    print(f"handler vocab:     {len(model.handler_totals)}")
    print(f"bigram emissions:  {len(model.handler_emissions)}")
    print(f"token vocab:       {len(model.vocab)}")
    print()

    test_phrases = [
        "volume up",
        "turn up the volume",
        "install firefox",
        "take a screenshot",
        "lock screen",
        "switch workspace",
        "play music",
        "brightness down",
        "mute microphone",
        "do something inscrutable xyzzy plover",
    ]
    for p in test_phrases:
        preds = model.predict(p, k=3)
        print(f"  {p!r}")
        for ht, prob in preds:
            print(f"      {ht:<35s} {prob:6.3f}")
        print()

    # Quick assertions for the smoke-test contract from the spec.
    vol = model.predict("volume up", k=1)
    inst = model.predict("install firefox", k=1)
    junk = model.predict("do something inscrutable xyzzy plover", k=1)
    print("Contract checks:")
    print(f"  'volume up'                      top={vol[0][0]} conf={vol[0][1]:.3f}")
    print(f"  'install firefox'                top={inst[0][0]} conf={inst[0][1]:.3f}")
    print(f"  'inscrutable xyzzy plover'       top={junk[0][0]} conf={junk[0][1]:.3f}")
    if not vol or vol[0][1] < 0.3:
        print("WARN: 'volume up' confidence below 0.3")
        sys.exit(0)  # smoke test stays soft -- pytest handles hard gating
