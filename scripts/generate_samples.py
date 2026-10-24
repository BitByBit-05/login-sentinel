"""Generate the realistic sample logs in sample_data/.

The logs mix a normal working day with three planted attacks, so you can
see exactly what the detector should catch and what it should ignore:

auth.log (Linux SSH server "web01", 12 Oct 2026)
  * normal staff logins, including a couple of mistyped passwords (should NOT alert)
  * 203.0.113.45  brute-forces "root" with 40 attempts in 6 minutes
  * 203.0.113.77  sprays 12 different account names, one attempt each
  * 192.0.2.99    fails 6 times for "bob", then gets in (account compromise)
  * 203.0.113.200 makes 3 slow attempts over 2 hours (below every threshold)

windows_security.csv (domain controller "DC01", 13 Oct 2026)
  * normal staff logons and local logons with no IP (skipped)
  * 198.51.100.200 sprays 8 domain accounts
  * 203.0.113.12   fails 4 times for "svc_backup", then succeeds

All IP addresses come from the ranges reserved for documentation
(RFC 5737) or private networks, so none of them belong to a real person.

Run:  python scripts/generate_samples.py
"""

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "sample_data"
rng = random.Random(42)  # fixed seed: the same files are produced every time


def sshd(ts: datetime, pid: int, message: str) -> tuple[datetime, str]:
    return ts, f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} web01 sshd[{pid}]: {message}"


def other(ts: datetime, message: str) -> tuple[datetime, str]:
    return ts, f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} web01 {message}"


def linux_log() -> list[str]:
    day = datetime(2026, 10, 12)
    lines = []
    staff = {"alice": "198.51.100.10", "bob": "198.51.100.11", "carol": "198.51.100.12", "dave": "198.51.100.13"}

    # Normal day: each person logs in a few times between 07:30 and 18:00.
    for user, ip in staff.items():
        for _ in range(rng.randint(3, 5)):
            ts = day + timedelta(hours=7.5 + rng.random() * 10.5)
            method = rng.choice(["publickey", "password"])
            pid = rng.randint(2000, 9000)
            lines.append(sshd(ts, pid, f"Accepted {method} for {user} from {ip} port {rng.randint(40000, 65000)} ssh2"))
            lines.append(other(ts + timedelta(seconds=1), f"sshd[{pid}]: pam_unix(sshd:session): session opened for user {user}(uid=1001) by (uid=0)"))

    # Honest typos: carol fails once, dave fails twice, then both get in.
    for user, misses, hour in [("carol", 1, 9.2), ("dave", 2, 13.7)]:
        ts = day + timedelta(hours=hour)
        for i in range(misses):
            lines.append(sshd(ts + timedelta(seconds=20 * i), 4100 + i, f"Failed password for {user} from {staff[user]} port {50000 + i} ssh2"))
        lines.append(sshd(ts + timedelta(seconds=20 * misses + 15), 4200, f"Accepted password for {user} from {staff[user]} port 50100 ssh2"))

    # Background noise every 15 minutes.
    for minute in range(0, 24 * 60, 15):
        lines.append(other(day + timedelta(minutes=minute), "CRON[1187]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"))

    # Attack 1: brute force against root, 40 tries ~9 seconds apart.
    start = day + timedelta(hours=3, minutes=14)
    for i in range(40):
        ts = start + timedelta(seconds=9 * i + rng.randint(0, 3))
        lines.append(sshd(ts, 6001, f"Failed password for root from 203.0.113.45 port {52000 + i} ssh2"))
    lines.append(other(start + timedelta(minutes=6, seconds=30), "sshd[6001]: Disconnected from authenticating user root 203.0.113.45 port 52039 [preauth]"))

    # Attack 2: password spray, one attempt per account.
    start = day + timedelta(hours=2, minutes=5)
    sprayed = ["admin", "test", "oracle", "ubuntu", "postgres", "git", "deploy", "guest", "user", "ftp", "alice", "bob"]
    for i, user in enumerate(sprayed):
        prefix = "" if user in staff else "invalid user "
        ts = start + timedelta(seconds=40 * i)
        lines.append(sshd(ts, 7000 + i, f"Failed password for {prefix}{user} from 203.0.113.77 port {41000 + i} ssh2"))

    # Attack 3: bob's password is guessed after 6 failures.
    start = day + timedelta(hours=22, minutes=41)
    for i in range(6):
        lines.append(sshd(start + timedelta(seconds=30 * i), 8100, f"Failed password for bob from 192.0.2.99 port {60000 + i} ssh2"))
    lines.append(sshd(start + timedelta(minutes=3, seconds=40), 8100, "Accepted password for bob from 192.0.2.99 port 60010 ssh2"))
    lines.append(other(start + timedelta(minutes=3, seconds=41), "sshd[8100]: pam_unix(sshd:session): session opened for user bob(uid=1002) by (uid=0)"))

    # Slow, low-volume probing that should stay below every threshold.
    for i, hour in enumerate([11.0, 12.1, 13.0]):
        lines.append(sshd(day + timedelta(hours=hour), 9100 + i, f"Failed password for root from 203.0.113.200 port {33000 + i} ssh2"))

    return [text for _, text in sorted(lines)]


def windows_log() -> list[dict]:
    day = datetime(2026, 10, 13)
    rows = []

    def row(ts, event_id, user, ip, host):
        rows.append({"TimeCreated": ts.strftime("%Y-%m-%dT%H:%M:%S"), "EventID": event_id,
                     "TargetUserName": user, "IpAddress": ip, "WorkstationName": host})

    staff = {"j.smith": "10.0.5.21", "m.lee": "10.0.5.34", "a.patel": "10.0.5.47", "r.nguyen": "10.0.5.52"}
    for user, ip in staff.items():
        for _ in range(rng.randint(3, 4)):
            row(day + timedelta(hours=8 + rng.random() * 9), 4624, user, ip, f"WS-{user.split('.')[1].upper()}")
    for hour in (6, 12, 18):
        row(day + timedelta(hours=hour), 4624, "SYSTEM", "-", "DC01")  # local logon, no IP

    # Spray against 8 domain accounts.
    start = day + timedelta(hours=1, minutes=30)
    targets = ["administrator", "j.smith", "m.lee", "a.patel", "r.nguyen", "helpdesk", "svc_sql", "guest"]
    for i, user in enumerate(targets):
        row(start + timedelta(seconds=55 * i), 4625, user, "198.51.100.200", "UNKNOWN")

    # svc_backup guessed after 4 failures.
    start = day + timedelta(hours=23, minutes=2)
    for i in range(4):
        row(start + timedelta(seconds=45 * i), 4625, "svc_backup", "203.0.113.12", "UNKNOWN")
    row(start + timedelta(minutes=3, seconds=30), 4624, "svc_backup", "203.0.113.12", "UNKNOWN")

    return sorted(rows, key=lambda r: r["TimeCreated"])


def main() -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / "auth.log").write_text("\n".join(linux_log()) + "\n", encoding="utf-8")
    with open(OUT / "windows_security.csv", "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["TimeCreated", "EventID", "TargetUserName", "IpAddress", "WorkstationName"])
        writer.writeheader()
        writer.writerows(windows_log())
    print(f"Wrote sample logs to {OUT}")


if __name__ == "__main__":
    main()
