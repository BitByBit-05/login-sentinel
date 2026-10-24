"""Detection rules.

Each rule looks at a list of LoginEvents and returns Findings. Rules are
mapped to MITRE ATT&CK techniques so a security analyst immediately knows
what kind of attack each finding represents.

| Rule                    | What it catches                                   | MITRE     |
|-------------------------|---------------------------------------------------|-----------|
| brute_force             | Many failed logins: one IP, one account           | T1110.001 |
| password_spray          | Failed logins: one IP, many different accounts    | T1110.003 |
| success_after_failures  | A login that works right after repeated failures  | T1078     |
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from .models import Finding, LoginEvent, Severity


@dataclass
class DetectionConfig:
    """Thresholds for every rule. Defaults are deliberately conservative."""

    window_minutes: int = 10
    brute_force_threshold: int = 5  # failures on one account from one IP
    spray_user_threshold: int = 5  # distinct accounts tried from one IP
    success_after_failures: int = 3  # failures before a success that look suspicious

    @property
    def window(self) -> timedelta:
        return timedelta(minutes=self.window_minutes)


def _duration(start: datetime, end: datetime) -> str:
    """Human-readable length of an attack, e.g. '6 min 12 s'."""
    seconds = int((end - start).total_seconds())
    minutes, seconds = divmod(seconds, 60)
    return f"{minutes} min {seconds} s" if minutes else f"{seconds} s"


def find_bursts(events: list[LoginEvent], threshold: int, window: timedelta, measure=len) -> list[list[LoginEvent]]:
    """Find periods where `measure(events in the window)` reaches `threshold`.

    `events` must be sorted by time. Returns one list of events per burst.

    `measure` decides what is counted inside the window:
      * brute force uses the default, len    -> how many failures
      * spraying passes count_accounts       -> how many different accounts

    How it works: a sliding window with two pointers. `right` walks forward
    over every event, and `left` moves up until everything from left to
    right fits inside the window. If the window measures at least
    `threshold`, we are inside a burst. Windows that overlap are merged, so
    one long attack gives one finding instead of dozens. The burst ends once
    the next event is more than a whole window after the burst's last event.
    """
    bursts = []
    left = 0
    burst_start = burst_end = None

    for right in range(len(events)):
        while events[right].timestamp - events[left].timestamp > window:
            left += 1
        if measure(events[left : right + 1]) >= threshold:
            if burst_start is None:
                burst_start = left
            burst_end = right
        elif burst_start is not None and events[right].timestamp - events[burst_end].timestamp > window:
            bursts.append(events[burst_start : burst_end + 1])
            burst_start = None

    if burst_start is not None:
        bursts.append(events[burst_start : burst_end + 1])
    return bursts


def count_accounts(events: list[LoginEvent]) -> int:
    """How many different accounts appear in a list of events."""
    return len({e.user for e in events})


def _failures_grouped_by(events: list[LoginEvent], key) -> dict:
    """Failed logins grouped by `key`, each group sorted by time."""
    groups = defaultdict(list)
    for event in events:
        if not event.success:
            groups[key(event)].append(event)
    for group in groups.values():
        group.sort(key=lambda e: e.timestamp)
    return groups


def detect_brute_force(events: list[LoginEvent], config: DetectionConfig) -> list[Finding]:
    """Repeated failed logins against one account from one IP."""
    findings = []
    groups = _failures_grouped_by(events, key=lambda e: (e.source_ip, e.user))
    for (ip, user), failures in groups.items():
        for burst in find_bursts(failures, config.brute_force_threshold, config.window):
            first, last = burst[0].timestamp, burst[-1].timestamp
            findings.append(
                Finding(
                    rule="brute_force",
                    severity=Severity.HIGH,
                    mitre_technique="T1110.001",
                    source_ip=ip,
                    users=[user],
                    first_seen=first,
                    last_seen=last,
                    event_count=len(burst),
                    description=f"{len(burst)} failed logins for '{user}' from {ip} in {_duration(first, last)}",
                )
            )
    return findings


def detect_password_spray(events: list[LoginEvent], config: DetectionConfig) -> list[Finding]:
    """One IP trying many different accounts, usually with a few common passwords.

    Spraying avoids account lockouts by trying each account only once or
    twice, so the brute-force rule never fires. The signal is the number of
    *different* accounts in the window, so the same find_bursts is used with
    count_accounts as the measure.
    """
    findings = []
    for ip, failures in _failures_grouped_by(events, key=lambda e: e.source_ip).items():
        for burst in find_bursts(failures, config.spray_user_threshold, config.window, measure=count_accounts):
            first, last = burst[0].timestamp, burst[-1].timestamp
            users = sorted({e.user for e in burst})
            findings.append(
                Finding(
                    rule="password_spray",
                    severity=Severity.HIGH,
                    mitre_technique="T1110.003",
                    source_ip=ip,
                    users=users,
                    first_seen=first,
                    last_seen=last,
                    event_count=len(burst),
                    description=f"{len(burst)} failed logins across {len(users)} different accounts "
                    f"from {ip} in {_duration(first, last)}",
                )
            )
    return findings


def detect_success_after_failures(events: list[LoginEvent], config: DetectionConfig) -> list[Finding]:
    """A successful login preceded by repeated failures for the same account and IP.

    This is the most serious rule: it suggests an attacker guessed the
    password and is now inside, so it is rated CRITICAL.
    """
    findings = []
    recent_failures = defaultdict(list)
    for event in sorted(events, key=lambda e: e.timestamp):
        key = (event.source_ip, event.user)
        if not event.success:
            recent_failures[key].append(event.timestamp)
            continue

        cutoff = event.timestamp - config.window
        failures = [t for t in recent_failures[key] if t >= cutoff]
        if len(failures) >= config.success_after_failures:
            findings.append(
                Finding(
                    rule="success_after_failures",
                    severity=Severity.CRITICAL,
                    mitre_technique="T1078",
                    source_ip=event.source_ip,
                    users=[event.user],
                    first_seen=failures[0],
                    last_seen=event.timestamp,
                    event_count=len(failures) + 1,
                    description=f"'{event.user}' logged in from {event.source_ip} after "
                    f"{len(failures)} failed attempts; credentials may be compromised",
                )
            )
        recent_failures[key].clear()  # a success resets the count
    return findings


ALL_RULES = [detect_brute_force, detect_password_spray, detect_success_after_failures]


def run_all(events: list[LoginEvent], config: DetectionConfig | None = None) -> list[Finding]:
    """Run every rule and return findings, most severe and most recent first."""
    config = config or DetectionConfig()
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(events, config))
    return sorted(findings, key=lambda f: (-f.severity, f.first_seen))
