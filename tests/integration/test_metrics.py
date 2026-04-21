"""Session 68 metrics integration tests."""
import sys
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "ai-control" / "daemon"))

import metrics


def test_counter_incr():
    metrics.reset()
    metrics.incr("test.foo")
    metrics.incr("test.foo", 3)
    snap = metrics.snapshot()
    assert snap["counters"]["test.foo"] == 4


def test_latency_percentiles():
    metrics.reset()
    for ms in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
        metrics.record_latency_ms("test.bar", float(ms))
    snap = metrics.snapshot()
    lat = snap["latencies_ms"]["test.bar"]
    assert lat["n"] == 10
    assert 4 <= lat["p50"] <= 6
    assert lat["p95"] >= 9


def test_snapshot_thread_safe():
    """Minimal concurrent-mutation smoke -- just ensure no exception under load."""
    import threading
    metrics.reset()
    stop = threading.Event()
    def writer():
        while not stop.is_set():
            metrics.incr("test.concurrent")
    t = threading.Thread(target=writer)
    t.start()
    try:
        for _ in range(100):
            metrics.snapshot()
    finally:
        stop.set()
        t.join(timeout=2)
