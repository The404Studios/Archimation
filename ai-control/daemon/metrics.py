"""
Session 68: lightweight metrics sink for ai-control daemon.

Tracks counters and latency histograms for hot paths. Exposed via
/metrics (JSON) and /debug/stats (richer diagnostic dump) endpoints.

Thread-safe: all mutations go through a module-level lock. Read paths
snapshot under the same lock.

Not Prometheus-format -- we control both producer and consumer, and
the JSON envelope is easier to compose into the existing auth/trust
fabric. A Prometheus adapter can be added later without touching
call sites.
"""
from __future__ import annotations

import time
import threading
from collections import defaultdict, deque
from typing import Any

_LOCK = threading.Lock()
_COUNTERS: dict[str, int] = defaultdict(int)
_LATENCIES: dict[str, deque] = defaultdict(lambda: deque(maxlen=512))
_START_TS = time.time()


def incr(key: str, amount: int = 1) -> None:
    """Increment a named counter."""
    with _LOCK:
        _COUNTERS[key] += amount


def record_latency_ms(key: str, ms: float) -> None:
    """Record a latency sample (ring buffer of 512)."""
    with _LOCK:
        _LATENCIES[key].append(float(ms))


def snapshot() -> dict[str, Any]:
    """Return a thread-safe snapshot of all counters + latency percentiles."""
    with _LOCK:
        counters = dict(_COUNTERS)
        latencies = {}
        for k, q in _LATENCIES.items():
            if not q:
                latencies[k] = None
                continue
            sorted_q = sorted(q)
            n = len(sorted_q)
            latencies[k] = {
                "n": n,
                "p50": sorted_q[n // 2],
                "p95": sorted_q[min(n - 1, int(n * 0.95))],
                "p99": sorted_q[min(n - 1, int(n * 0.99))],
                "max": sorted_q[-1],
            }
        return {
            "uptime_s": round(time.time() - _START_TS, 2),
            "counters": counters,
            "latencies_ms": latencies,
        }


def reset() -> None:
    """Reset all metrics (test-only -- do not wire to any endpoint)."""
    with _LOCK:
        _COUNTERS.clear()
        _LATENCIES.clear()
