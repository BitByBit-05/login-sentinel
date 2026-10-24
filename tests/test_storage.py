from datetime import datetime, timedelta

from login_sentinel import storage
from login_sentinel.models import LoginEvent

START = datetime(2026, 10, 12, 3, 0, 0)


def event(minutes, user, ip, success):
    return LoginEvent(START + timedelta(minutes=minutes), user, ip, success, "web01", "linux_auth")


def test_top_failed_ips_ordering_and_limit():
    conn = storage.connect()  # in-memory database
    storage.save_events(
        conn,
        [event(i, "root", "203.0.113.45", False) for i in range(5)]
        + [event(i, f"user{i}", "203.0.113.77", False) for i in range(3)]
        + [event(0, "bob", "192.0.2.99", False)]
        + [event(0, "alice", "198.51.100.10", True)],  # successes are not counted
    )
    assert storage.top_failed_ips(conn, limit=2) == [
        {"source_ip": "203.0.113.45", "failed_logins": 5, "accounts_tried": 1},
        {"source_ip": "203.0.113.77", "failed_logins": 3, "accounts_tried": 3},
    ]
    conn.close()


def test_log_content_cannot_inject_sql():
    # An attacker controls the username in a log line, so it must be stored as plain text.
    conn = storage.connect()
    nasty = "x'); DROP TABLE events; --"
    storage.save_events(conn, [event(0, nasty, "203.0.113.45", False)])
    assert conn.execute("SELECT user FROM events").fetchone()[0] == nasty
    assert storage.summary(conn)["total"] == 1
    conn.close()
