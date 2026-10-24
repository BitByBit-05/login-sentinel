from datetime import datetime, timedelta

from login_sentinel.detectors import (
    DetectionConfig,
    detect_brute_force,
    detect_password_spray,
    detect_success_after_failures,
    find_bursts,
)
from login_sentinel.models import LoginEvent, Severity

START = datetime(2026, 10, 12, 3, 0, 0)
WINDOW = timedelta(minutes=10)
CONFIG = DetectionConfig(window_minutes=10, brute_force_threshold=5, spray_user_threshold=5, success_after_failures=3)


def event(seconds, user="root", ip="203.0.113.45", success=False):
    """A login event `seconds` after START. Defaults to a failed login for root."""
    return LoginEvent(START + timedelta(seconds=seconds), user, ip, success, "web01", "linux_auth")


# --- the sliding window ------------------------------------------------------

def test_burst_needs_threshold_events_inside_window():
    events = [event(60 * m) for m in (0, 1, 2, 3)]  # 4 events, 1 minute apart
    assert find_bursts(events, threshold=5, window=WINDOW) == []
    assert find_bursts(events, threshold=4, window=WINDOW) == [events]


def test_long_attack_becomes_one_burst_and_separate_attacks_stay_separate():
    first = [event(10 * i) for i in range(30)]
    second = [event(7200 + 10 * i) for i in range(6)]  # two hours later
    bursts = find_bursts(first + second, threshold=5, window=WINDOW)
    assert [len(b) for b in bursts] == [30, 6]


# --- brute force -------------------------------------------------------------

def test_brute_force_at_threshold_is_flagged():
    findings = detect_brute_force([event(i * 30) for i in range(5)], CONFIG)
    assert len(findings) == 1
    assert findings[0].event_count == 5
    assert findings[0].mitre_technique == "T1110.001"


def test_brute_force_below_threshold_is_ignored():
    assert detect_brute_force([event(i * 30) for i in range(4)], CONFIG) == []


# --- password spray ----------------------------------------------------------

def test_spray_across_many_accounts_is_flagged():
    findings = detect_password_spray([event(i * 40, user=f"user{i}") for i in range(8)], CONFIG)
    assert len(findings) == 1
    assert len(findings[0].users) == 8


def test_many_tries_on_one_account_is_not_a_spray():
    assert detect_password_spray([event(i * 10) for i in range(50)], CONFIG) == []


# --- success after failures --------------------------------------------------

def test_success_after_repeated_failures_is_critical():
    events = [event(i * 20, user="bob") for i in range(4)] + [event(100, user="bob", success=True)]
    findings = detect_success_after_failures(events, CONFIG)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_one_typo_before_success_is_normal():
    events = [event(0, user="carol"), event(15, user="carol", success=True)]
    assert detect_success_after_failures(events, CONFIG) == []
