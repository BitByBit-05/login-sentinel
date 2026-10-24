"""Store events and findings in SQLite and summarise them with SQL.

By default the database lives in memory and disappears when the program
exits. Pass --db events.db to keep it, so you can query it later with any
SQLite tool, for example:

    sqlite3 events.db "SELECT source_ip, COUNT(*) FROM events WHERE success = 0 GROUP BY source_ip;"
"""

import json
import sqlite3

from .models import Finding, LoginEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    timestamp   TEXT    NOT NULL,
    user        TEXT    NOT NULL,
    source_ip   TEXT    NOT NULL,
    success     INTEGER NOT NULL,   -- 1 = login worked, 0 = failed
    host        TEXT    NOT NULL,
    log_source  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events (source_ip);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY,
    rule            TEXT    NOT NULL,
    severity        TEXT    NOT NULL,
    mitre_technique TEXT    NOT NULL,
    source_ip       TEXT    NOT NULL,
    users           TEXT    NOT NULL,   -- JSON list of account names
    first_seen      TEXT    NOT NULL,
    last_seen       TEXT    NOT NULL,
    event_count     INTEGER NOT NULL,
    description     TEXT    NOT NULL
);
"""


def connect(path: str = ":memory:") -> sqlite3.Connection:
    """Open (or create) the database and make sure the tables exist."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def save_events(conn: sqlite3.Connection, events: list[LoginEvent]) -> None:
    # Parameterised queries (the ? placeholders) stop log content from
    # being interpreted as SQL, which matters when the input is attacker-controlled.
    conn.executemany(
        "INSERT INTO events (timestamp, user, source_ip, success, host, log_source) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [
            (e.timestamp.isoformat(), e.user, e.source_ip, int(e.success), e.host, e.log_source)
            for e in events
        ],
    )
    conn.commit()


def save_findings(conn: sqlite3.Connection, findings: list[Finding]) -> None:
    conn.executemany(
        "INSERT INTO findings (rule, severity, mitre_technique, source_ip, users, "
        "first_seen, last_seen, event_count, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                f.rule,
                str(f.severity),
                f.mitre_technique,
                f.source_ip,
                json.dumps(f.users),
                f.first_seen.isoformat(),
                f.last_seen.isoformat(),
                f.event_count,
                f.description,
            )
            for f in findings
        ],
    )
    conn.commit()


def summary(conn: sqlite3.Connection) -> dict:
    """Overall counts for the report header."""
    row = conn.execute(
        """
        SELECT COUNT(*)                         AS total,
               COALESCE(SUM(success), 0)        AS succeeded,
               COALESCE(SUM(1 - success), 0)    AS failed,
               COUNT(DISTINCT source_ip)        AS unique_ips,
               COUNT(DISTINCT user)             AS unique_users,
               MIN(timestamp)                   AS first_event,
               MAX(timestamp)                   AS last_event
        FROM events
        """
    ).fetchone()
    return dict(row)


def top_failed_ips(conn: sqlite3.Connection, limit: int = 5) -> list[dict]:
    """Source IPs with the most failed logins, and how many accounts each one tried."""
    rows = conn.execute(
        """
        SELECT source_ip,
               COUNT(*)             AS failed_logins,
               COUNT(DISTINCT user) AS accounts_tried
        FROM events
        WHERE success = 0
        GROUP BY source_ip
        ORDER BY failed_logins DESC, source_ip
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]
