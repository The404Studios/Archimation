"""Trigram Markov phrase generator trained on contusion_dictionary phrases.

Used by tests/integration/test_markov_chains.py to fuzz the handler
routing layer.  Generated phrases stay close to the dictionary's
distribution (so they tend to route somewhere) but introduce enough
variation to probe edge cases.

Session 58, Agent 8.

The generator is intentionally small (<200 LOC), zero-dependency, and
seeded so test runs are bit-reproducible. It implements:

  * Trigram (n=3) Markov chain over tokenized seed phrases.
  * Sentinel-bounded walks (start sentinel "<S>", end sentinel "</S>")
    so phrase lengths follow the seed distribution rather than always
    hitting `max_tokens`.
  * `default_phrases()` — a curated ~50-phrase seed set drawn from the
    real contusion_dictionary self-test list, every one of which is
    known to route to a non-`search` handler in production.

Tokenization is deliberately simple: lowercase, split on whitespace,
strip surrounding punctuation. That mirrors what the dictionary's
`parse_request` does at the surface level (it does richer regex
matching internally, but the surface tokens are the same).
"""

from __future__ import annotations

import random
import re
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

# Sentinel tokens — picked so they cannot collide with real words.
_START = "<S>"
_END = "</S>"

# Strip leading/trailing punctuation; keeps internal "/" so paths like
# "/tmp" survive tokenization (though the seed list has none).
_TOKEN_RE = re.compile(r"^[^\w/~.]+|[^\w/~.]+$")


def _tokenize(phrase: str) -> List[str]:
    """Lowercase + whitespace-split + strip surrounding punctuation."""
    if not isinstance(phrase, str):
        return []
    out: List[str] = []
    for raw in phrase.strip().lower().split():
        tok = _TOKEN_RE.sub("", raw)
        if tok:
            out.append(tok)
    return out


class PhraseGenerator:
    """Trigram Markov phrase generator.

    Stores P(token | (token_{-2}, token_{-1})). For n=3 the chain key is
    the 2-tuple of the two preceding tokens; for n=2 (bigram) it's the
    1-tuple of the previous token. Defaults to trigram per the spec.

    The generator is fully deterministic given `seed`. Reseed by
    constructing a new instance — there is intentionally no in-place
    reseed method, because callers that need different streams should
    not share state by accident.
    """

    def __init__(
        self,
        seed_phrases: Optional[List[str]] = None,
        n: int = 3,
        seed: int = 42,
    ) -> None:
        if n < 2:
            raise ValueError(f"n must be >= 2 (got {n})")
        self._n = int(n)
        self._chains: Dict[Tuple[str, ...], List[str]] = defaultdict(list)
        # Distinct start contexts so `generate()` can sample one fairly.
        self._starts: List[Tuple[str, ...]] = []
        # Vocabulary set is exposed so tests can assert "no novel tokens".
        self._vocab: set = set()
        self._rng = random.Random(int(seed))
        if seed_phrases:
            self.train(seed_phrases)

    # -- training ----------------------------------------------------------

    def train(self, phrases: List[str]) -> None:
        """Build the n-gram successor table from `phrases`.

        Pads each phrase with (n-1) `<S>` start tokens and a single `</S>`
        end token so walks have well-defined boundaries. Empty phrases
        and phrases that tokenize to nothing are silently skipped.
        """
        pad_left = [_START] * (self._n - 1)
        for phrase in phrases:
            toks = _tokenize(phrase)
            if not toks:
                continue
            seq = pad_left + toks + [_END]
            self._vocab.update(toks)
            # Slide an n-window: the (n-1)-prefix is the chain key, the
            # n-th token is the successor we record.
            for i in range(len(seq) - self._n + 1):
                key = tuple(seq[i:i + self._n - 1])
                nxt = seq[i + self._n - 1]
                self._chains[key].append(nxt)
            # Record the very first non-padding window as a legal start.
            start_key = tuple(seq[:self._n - 1])
            if start_key not in self._starts:
                self._starts.append(start_key)

    # -- generation --------------------------------------------------------

    def generate(self, max_tokens: int = 12) -> str:
        """Sample one phrase from the chain.

        Walks until either the end sentinel is drawn, max_tokens real
        tokens have been emitted, or the current key has no successors
        (defensive fallback — shouldn't happen for trained chains).
        """
        if not self._chains:
            return ""
        key = self._rng.choice(self._starts)
        out: List[str] = []
        steps = max(1, int(max_tokens))
        for _ in range(steps):
            successors = self._chains.get(key)
            if not successors:
                break
            nxt = self._rng.choice(successors)
            if nxt == _END:
                break
            out.append(nxt)
            # Slide the window: drop the oldest token, append the new one.
            key = tuple(list(key[1:]) + [nxt])
        return " ".join(out)

    def generate_batch(self, n: int) -> List[str]:
        return [self.generate() for _ in range(max(0, int(n)))]

    # -- introspection -----------------------------------------------------

    @property
    def vocab(self) -> set:
        """Read-only view of the trained vocabulary (sentinels excluded)."""
        return frozenset(self._vocab)

    @property
    def chain_size(self) -> int:
        return len(self._chains)


# ---------------------------------------------------------------------------
# Curated seed set: ~50 phrases lifted from contusion_dictionary's own
# self-test list plus a handful of real-world UI phrasings.  Every entry
# here is a known good route in the live dictionary — i.e. parse_request()
# returns at least one Action whose .type != "search".
# ---------------------------------------------------------------------------

def default_phrases() -> List[str]:
    """A curated seed set of ~50 phrases that route correctly."""
    return [
        # script + run
        "list scripts", "show my scripts", "run hello", "run script hello",
        # apt / pacman style
        "install firefox", "install discord", "install steam",
        "search for firefox", "list installed packages", "update the system",
        # launch / open
        "open firefox", "launch steam", "launch steam in big picture mode",
        "open the terminal", "open file manager",
        # screenshot / record
        "take a screenshot", "screenshot now", "record the screen",
        # volume / brightness / media
        "volume up", "turn up the volume", "volume down", "set volume to 50",
        "mute", "brightness up", "brightness down", "brighter",
        "next track", "previous track", "play pause",
        # window / workspace
        "maximize the window", "minimize the window", "close the window",
        "switch to workspace 2", "switch to workspace 3",
        # power / session
        "lock the screen", "lock screen", "suspend",
        "set up claude workspace",
        # filesystem
        "list files in /tmp", "list files in ~/Downloads",
        "create directory foo", "find files named bar",
        # system info
        "is claude installed", "show system info", "cpu usage",
        "show cpu usage", "top processes by cpu", "kernel version",
        "whoami",
        # network
        "ping google.com", "listening ports",
        "restart network", "restart network manager", "restart nginx",
        "is ssh running", "running services",
        # input
        "type hello world", "press enter",
        # download
        "download https://example.com/f.zip",
    ]
