from datetime import datetime

from login_sentinel.parsers import parse_linux_auth, parse_windows_csv

FAILED = "Oct 12 03:14:07 web01 sshd[2231]: Failed password for root from 203.0.113.45 port 52344 ssh2"
INVALID = "Oct 12 03:14:09 web01 sshd[2231]: Failed password for invalid user admin from 203.0.113.45 port 52346 ssh2"
NOISE = "Oct 12 03:15:00 web01 CRON[1187]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"


def test_failed_password_line():
    event = parse_linux_auth([FAILED], year=2026).events[0]
    assert event.timestamp == datetime(2026, 10, 12, 3, 14, 7)
    assert (event.user, event.source_ip, event.success) == ("root", "203.0.113.45", False)


def test_invalid_user_prefix_is_removed():
    assert parse_linux_auth([INVALID], year=2026).events[0].user == "admin"


def test_non_login_lines_are_counted_as_skipped():
    result = parse_linux_auth([NOISE, "", FAILED], year=2026)
    assert len(result.events) == 1
    assert result.skipped == 2


def test_year_rolls_over_at_new_year():
    lines = [
        "Dec 31 23:59:58 web01 sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2",
        "Jan  1 00:00:03 web01 sshd[1]: Failed password for root from 192.0.2.1 port 2 ssh2",
    ]
    events = parse_linux_auth(lines, year=2025).events
    assert [e.timestamp.year for e in events] == [2025, 2026]


def test_windows_csv(tmp_path):
    path = tmp_path / "security.csv"
    path.write_text(
        "TimeCreated,EventID,TargetUserName,IpAddress,WorkstationName\n"
        "2026-10-13T01:30:00,4625,j.smith,198.51.100.200,UNKNOWN\n"  # failed logon
        "2026-10-13T08:00:00,4624,j.smith,10.0.5.21,WS-SMITH\n"  # successful logon
        "2026-10-13T09:00:00,4624,SYSTEM,-,DC01\n",  # local logon, no IP: skipped
        encoding="utf-8",
    )
    result = parse_windows_csv(path)
    assert [(e.success, e.source_ip) for e in result.events] == [(False, "198.51.100.200"), (True, "10.0.5.21")]
    assert result.skipped == 1
