from datetime import datetime, timedelta

from login_sentinel.detectors import (
    DetectionConfig,
    count_accounts,
    detect_brute_force,
    detect_password_spray,
    detect_success_after_failures,
    find_bursts,
    run_all,
)
from login_sentinel.models import LoginEvent, Severity

START = datetime(2026, 10, 12, 3, 0, 0)
CONFIG = DetectionConfig(window_minutes=10, brute_force_threshold=5, spray_user_threshold=5, success_after_failures=3)


def event(seconds, user="root", ip="203.0.113.45", success=False):
    return LoginEvent(START + timedelta(seconds=seconds), user, ip, success, "web01", "linux_auth")


# --- find_bursts -----------------------------------------------------------

WINDOW = timedelta(minutes=10)


def test_burst_needs_threshold_events_inside_window():
    events = [event(60 * m) for m in (0, 1, 2, 3)]
    assert find_bursts(events, threshold=5, window=WINDOW) == []
    assert find_bursts(events, threshold=4, window=WINDOW) == [events]


def test_events_spread_too_far_apart_are_not_a_burst():
    events = [event(12 * 60 * i) for i in range(10)]
    assert find_bursts(events, threshold=3, window=WINDOW) == []


def test_long_attack_becomes_one_burst_and_separate_attacks_stay_separate():
    first = [event(10 * i) for i in range(30)]
    second = [event(7200 + 10 * i) for i in range(6)]
    bursts = find_bursts(first + second, threshold=5, window=WINDOW)
    assert [len(b) for b in bursts] == [30, 6]


def test_count_accounts_measure_counts_different_users():
    same_user = [event(i * 10) for i in range(6)]
    different_users = [event(i * 10, user=f"user{i}") for i in range(6)]
    assert find_bursts(same_user, threshold=5, window=WINDOW, measure=count_accounts) == []
    assert len(find_bursts(different_users, threshold=5, window=WINDOW, measure=count_accounts)) == 1


# --- brute force -----------------------------------------------------------

def test_brute_force_at_threshold_is_flagged():
    findings = detect_brute_force([event(i * 30) for i in range(5)], CONFIG)
    assert len(findings) == 1
    assert findings[0].event_count == 5
    assert findings[0].mitre_technique == "T1110.001"


def test_brute_force_below_threshold_is_ignored():
    assert detect_brute_force([event(i * 30) for i in range(4)], CONFIG) == []


def test_successful_logins_do_not_count_as_brute_force():
    events = [event(i * 30, success=True) for i in range(10)]
    assert detect_brute_force(events, CONFIG) == []


def test_brute_force_is_tracked_per_account():
    events = [event(i * 30, user=f"user{i}") for i in range(10)]  # 10 accounts, 1 try each
    assert detect_brute_force(events, CONFIG) == []


# --- password spray --------------------------------------------------------

def test_spray_across_many_accounts_is_flagged():
    findings = detect_password_spray([event(i * 40, user=f"user{i}") for i in range(8)], CONFIG)
    assert len(findings) == 1
    assert len(findings[0].users) == 8
    assert findings[0].severity == Severity.HIGH


def test_many_tries_on_one_account_is_not_a_spray():
    assert detect_password_spray([event(i * 10) for i in range(50)], CONFIG) == []


def test_spray_spread_over_hours_is_ignored():
    events = [event(i * 3600, user=f"user{i}") for i in range(8)]
    assert detect_password_spray(events, CONFIG) == []


# --- success after failures ------------------------------------------------

def test_success_after_repeated_failures_is_critical():
    events = [event(i * 20, user="bob") for i in range(4)] + [event(100, user="bob", success=True)]
    findings = detect_success_after_failures(events, CONFIG)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].event_count == 5


def test_one_typo_before_success_is_normal():
    events = [event(0, user="carol"), event(15, user="carol", success=True)]
    assert detect_success_after_failures(events, CONFIG) == []


def test_old_failures_outside_window_do_not_count():
    events = [event(i * 10, user="bob") for i in range(5)] + [event(3600, user="bob", success=True)]
    assert detect_success_after_failures(events, CONFIG) == []


def test_failures_from_other_ip_do_not_count():
    events = [event(i * 10, user="bob", ip="192.0.2.1") for i in range(5)]
    events.append(event(60, user="bob", ip="198.51.100.11", success=True))
    assert detect_success_after_failures(events, CONFIG) == []


# --- run_all ----------------------------------------------------------------

def test_run_all_sorts_most_severe_first():
    events = [event(i * 20, user="bob") for i in range(6)] + [event(130, user="bob", success=True)]
    findings = run_all(events, CONFIG)
    assert [f.rule for f in findings] == ["success_after_failures", "brute_force"]


def test_two_sprays_hours_apart_are_reported_separately():
    first = [event(i * 40, user=f"user{i}") for i in range(6)]
    second = [event(7200 + i * 40, user=f"other{i}") for i in range(6)]
    findings = detect_password_spray(first + second, CONFIG)
    assert [len(f.users) for f in findings] == [6, 6]
