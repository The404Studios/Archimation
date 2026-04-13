#!/usr/bin/env python3
"""
Trust Observer - Unit tests.

Tests the AI observer's oscillation detection, risk classification,
and adaptive threshold logic without requiring /dev/trust.
"""

import sys
import time
from pathlib import Path

# Add daemon to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "ai-control" / "daemon"))

from trust_observer import TrustObserver, SubjectProfile, RiskTier, TrustSnapshot

passed = 0
failed = 0


def test(name, condition):
    global passed, failed
    print(f"  {name:55s}", end=" ")
    if condition:
        print("\033[32mPASS\033[0m")
        passed += 1
    else:
        print("\033[31mFAIL\033[0m")
        failed += 1


def test_register_subject():
    obs = TrustObserver()
    obs.register_subject(100, domain=0)
    subjects = obs.get_all_subjects()
    test("Register subject creates profile", len(subjects) == 1)
    test("Subject ID matches", subjects[0]["subject_id"] == 100)


def test_unregister_subject():
    obs = TrustObserver()
    obs.register_subject(100)
    obs.unregister_subject(100)
    test("Unregister removes profile", len(obs.get_all_subjects()) == 0)


def test_score_update():
    obs = TrustObserver()
    obs.register_subject(100)
    profile = obs._profiles[100]

    # Simulate a score update
    obs._update_subject(100, 300)
    test("Score update recorded", profile.last_score == 300)
    test("History has entry", len(profile.history) == 1)


def test_risk_classification_low():
    obs = TrustObserver()
    obs.register_subject(100, domain=0)
    obs._update_subject(100, 500)
    profile = obs._profiles[100]
    test("High score = LOW risk", profile.risk_tier == RiskTier.LOW)


def test_risk_classification_medium():
    obs = TrustObserver()
    obs.register_subject(100, domain=1)  # WIN32 domain
    obs._update_subject(100, 200)
    profile = obs._profiles[100]
    test("Win32 domain = MEDIUM risk", profile.risk_tier == RiskTier.MEDIUM)


def test_risk_classification_high():
    obs = TrustObserver()
    obs.register_subject(100)
    obs._update_subject(100, -300)
    profile = obs._profiles[100]
    test("Negative score = HIGH risk", profile.risk_tier == RiskTier.HIGH)


def test_oscillation_detection():
    obs = TrustObserver(oscillation_window=10.0, oscillation_threshold=4)
    obs.register_subject(100)
    profile = obs._profiles[100]

    # Simulate rapid oscillation
    scores = [200, 300, 200, 300, 200, 300, 200, 300]  # 7 direction changes
    for s in scores:
        obs._update_subject(100, s)

    test("Oscillation triggers freeze", profile.frozen)
    test("Anomaly count incremented", profile.anomaly_count >= 1)


def test_adaptive_threshold():
    obs = TrustObserver()
    obs.register_subject(100)

    # LOW risk: threshold should be lowered
    obs._profiles[100].risk_tier = RiskTier.LOW
    t = obs.get_adaptive_threshold(100, 200)
    test("LOW risk lowers threshold", t == 150)

    # HIGH risk: threshold should be raised
    obs._profiles[100].risk_tier = RiskTier.HIGH
    t = obs.get_adaptive_threshold(100, 200)
    test("HIGH risk raises threshold", t == 300)

    # CRITICAL risk: threshold raised significantly
    obs._profiles[100].risk_tier = RiskTier.CRITICAL
    t = obs.get_adaptive_threshold(100, 200)
    test("CRITICAL risk raises threshold a lot", t == 500)


def test_event_callback():
    events = []
    obs = TrustObserver()
    obs.add_event_callback(lambda e: events.append(e))
    obs.register_subject(100)
    obs._update_subject(100, 300)

    test("Score change triggers event", any(e["type"] == "score_change" for e in events))


def test_get_subject_detail():
    obs = TrustObserver()
    obs.register_subject(100, domain=2)
    obs._update_subject(100, 400)
    info = obs.get_subject(100)

    test("get_subject returns dict", info is not None)
    test("Domain matches", info["domain"] == 2)
    test("Score matches", info["score"] == 400)


def test_unknown_subject():
    obs = TrustObserver()
    info = obs.get_subject(999)
    test("Unknown subject returns None", info is None)

    threshold = obs.get_adaptive_threshold(999, 200)
    test("Unknown subject uses base threshold", threshold == 200)


def test_anomaly_status():
    obs = TrustObserver(oscillation_window=10.0, oscillation_threshold=4)
    obs.register_subject(100)
    obs.register_subject(200)

    # Freeze subject 100 via oscillation
    for s in [200, 300, 200, 300, 200, 300, 200, 300]:
        obs._update_subject(100, s)

    # Subject 200 stays normal
    obs._update_subject(200, 400)

    status = obs.get_anomaly_status()
    test("Anomaly status returns dict", isinstance(status, dict))
    test("Frozen count is 1", status.get("frozen_count", 0) == 1)
    test("Total subjects is 2", status.get("total_subjects", 0) == 2)


def test_multiple_registrations():
    obs = TrustObserver()
    obs.register_subject(100)
    obs.register_subject(100)  # Re-register same subject
    test("Re-register same subject is idempotent", len(obs.get_all_subjects()) == 1)


def test_score_history_window():
    obs = TrustObserver()
    obs.register_subject(100)

    # Add many score updates
    for i in range(200):
        obs._update_subject(100, i)

    profile = obs._profiles[100]
    test("History is bounded", len(profile.history) <= 100)


def main():
    print("=== Trust Observer Unit Tests ===\n")

    print("-- Registration --")
    test_register_subject()
    test_unregister_subject()
    test_multiple_registrations()

    print("\n-- Score Updates --")
    test_score_update()
    test_score_history_window()

    print("\n-- Risk Classification --")
    test_risk_classification_low()
    test_risk_classification_medium()
    test_risk_classification_high()

    print("\n-- Oscillation Detection --")
    test_oscillation_detection()

    print("\n-- Adaptive Thresholds --")
    test_adaptive_threshold()

    print("\n-- Event Callbacks --")
    test_event_callback()

    print("\n-- Query Interface --")
    test_get_subject_detail()
    test_unknown_subject()

    print("\n-- Anomaly Status --")
    test_anomaly_status()

    print(f"\n=== Results: {passed} passed, {failed} failed ===")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
