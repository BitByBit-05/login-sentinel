"""Unit tests for the SQLite layer."""

import json
from datetime import datetime, timedelta

import pytest

from login_sentinel import storage
from login_sentinel.models import Finding, LoginEvent, Severity

START = datetime(2026, 10, 12, 3, 0, 0)


def event(minutes, user, ip, success):
    return LoginEvent(START + timedelta(minutes=minutes), user, ip, success, "web01", "linux_auth")


@pytest.fixture
def conn():
    connection = storage.connect()  # in-memory database, fresh for every test
    yield connection
    connection.close()


def test_schema_creates_both_tables(conn):
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"events", "findings"} <= tables


def test_summary_of_empty_database(conn):
    stats = storage.summary(conn)
    assert stats["total"] == 0
    assert stats["failed"] == 0 and stats["succeeded"] == 0
    assert stats["first_event"] is None


def test_summary_counts(conn):
    storage.save_events(
        conn,
        [
            event(0, "root", "203.0.113.45", False),
            event(1, "root", "203.0.113.45", False),
            event(2, "alice", "198.51.100.10", True),
        ],
    )
    stats = storage.summary(conn)
    assert (stats["total"], stats["failed"], stats["succeeded"]) == (3, 2, 1)
    assert (stats["unique_ips"], stats["unique_users"]) == (2, 2)
    assert stats["first_event"] == "2026-10-12T03:00:00"
    assert stats["last_event"] == "2026-10-12T03:02:00"


def test_top_failed_ips_ordering_and_limit(conn):
    events = (
        [event(i, "root", "203.0.113.45", False) for i in range(5)]
        + [event(i, f"user{i}", "203.0.113.77", False) for i in range(3)]
        + [event(0, "bob", "192.0.2.99", False)]
        + [event(0, "alice", "198.51.100.10", True)]  # successes are not counted
    )
    storage.save_events(conn, events)
    top = storage.top_failed_ips(conn, limit=2)
    assert top == [
        {"source_ip": "203.0.113.45", "failed_logins": 5, "accounts_tried": 1},
        {"source_ip": "203.0.113.77", "failed_logins": 3, "accounts_tried": 3},
    ]


def test_findings_round_trip(conn):
    finding = Finding(
        rule="password_spray",
        severity=Severity.HIGH,
        mitre_technique="T1110.003",
        source_ip="203.0.113.77",
        users=["admin", "guest"],
        first_seen=START,
        last_seen=START + timedelta(minutes=5),
        event_count=2,
        description="test",
    )
    storage.save_findings(conn, [finding])
    row = conn.execute("SELECT * FROM findings").fetchone()
    assert row["severity"] == "HIGH"
    assert json.loads(row["users"]) == ["admin", "guest"]


def test_log_content_cannot_inject_sql(conn):
    # An attacker controls the username field in a log. It must be stored as plain text.
    nasty = "x'); DROP TABLE events; --"
    storage.save_events(conn, [event(0, nasty, "203.0.113.45", False)])
    assert conn.execute("SELECT user FROM events").fetchone()[0] == nasty
    assert storage.summary(conn)["total"] == 1
