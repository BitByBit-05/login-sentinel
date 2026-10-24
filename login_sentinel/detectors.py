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

from collections import Counter, defaultdict
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


def find_bursts(times: list[datetime], threshold: int, window: timedelta) -> list[tuple[int, int]]:
    """Find periods where at least `threshold` events happen within `window`.

    `times` must be sorted. Returns (start_index, end_index) pairs, inclusive.

    This is a sliding window with two pointers: `right` walks forward over
    every event and `left` moves up until everything between them fits
    inside the window. Whenever the window holds enough events we are inside
    a burst; when it drops below the threshold the burst ends. Overlapping
    windows are merged, so one long attack produces one finding instead of
    dozens. It runs in O(n) time because each pointer only moves forward.
    """
    bursts = []
    left = 0
    burst_start = None
    burst_end = None

    for right in range(len(times)):
        while times[right] - times[left] > window:
            left += 1
        if right - left + 1 >= threshold:
            if burst_start is None:
                burst_start = left
            burst_end = right
        elif burst_start is not None and times[right] - times[burst_end] > window:
            bursts.append((burst_start, burst_end))
            burst_start = None

    if burst_start is not None:
        bursts.append((burst_start, burst_end))
    return bursts


def detect_brute_force(events: list[LoginEvent], config: DetectionConfig) -> list[Finding]:
    """Repeated failed logins against a single account from a single IP."""
    failures = defaultdict(list)
    for event in events:
        if not event.success:
            failures[(event.source_ip, event.user)].append(event.timestamp)

    findings = []
    for (ip, user), times in failures.items():
        times.sort()
        for start, end in find_bursts(times, config.brute_force_threshold, config.window):
            count = end - start + 1
            findings.append(
                Finding(
                    rule="brute_force",
                    severity=Severity.HIGH,
                    mitre_technique="T1110.001",
                    source_ip=ip,
                    users=[user],
                    first_seen=times[start],
                    last_seen=times[end],
                    event_count=count,
                    description=f"{count} failed logins for '{user}' from {ip} "
                    f"in {_duration(times[start], times[end])}",
                )
            )
    return findings


def detect_password_spray(events: list[LoginEvent], config: DetectionConfig) -> list[Finding]:
    """One IP trying many different accounts, usually with a few common passwords.

    Spraying avoids account lockouts by trying each account only once or
    twice, so it slips past the brute-force rule. The signal is the number
    of *distinct* accounts in the window, not the number of attempts. It
    uses the same two-pointer sliding window as find_bursts, with a Counter
    tracking how many times each account appears inside the window.
    """
    failures = defaultdict(list)
    for event in events:
        if not event.success:
            failures[event.source_ip].append(event)

    findings = []
    for ip, ip_events in failures.items():
        ip_events.sort(key=lambda e: e.timestamp)
        users_in_window = Counter()
        bursts = []
        left = 0
        burst_start = burst_end = None

        for right, event in enumerate(ip_events):
            users_in_window[event.user] += 1
            while event.timestamp - ip_events[left].timestamp > config.window:
                users_in_window[ip_events[left].user] -= 1
                if users_in_window[ip_events[left].user] == 0:
                    del users_in_window[ip_events[left].user]
                left += 1

            if len(users_in_window) >= config.spray_user_threshold:
                if burst_start is None:
                    burst_start = left
                burst_end = right
            elif burst_start is not None and event.timestamp - ip_events[burst_end].timestamp > config.window:
                bursts.append((burst_start, burst_end))
                burst_start = None
        if burst_start is not None:
            bursts.append((burst_start, burst_end))

        for start, end in bursts:
            burst = ip_events[start : end + 1]
            users = sorted({e.user for e in burst})
            findings.append(
                Finding(
                    rule="password_spray",
                    severity=Severity.HIGH,
                    mitre_technique="T1110.003",
                    source_ip=ip,
                    users=users,
                    first_seen=burst[0].timestamp,
                    last_seen=burst[-1].timestamp,
                    event_count=len(burst),
                    description=f"{len(burst)} failed logins across {len(users)} different "
                    f"accounts from {ip} in {_duration(burst[0].timestamp, burst[-1].timestamp)}",
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
