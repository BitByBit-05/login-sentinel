"""End-to-end tests: run the real command on the sample logs."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path

from login_sentinel.cli import main

SAMPLES = Path(__file__).resolve().parent.parent / "sample_data"
BOTH_LOGS = [str(SAMPLES / "auth.log"), str(SAMPLES / "windows_security.csv")]


def run_json(capsys, *extra):
    assert main([*BOTH_LOGS, "--year", "2026", "--format", "json", *extra]) == 0
    return json.loads(capsys.readouterr().out)


def test_sample_logs_produce_exactly_the_planted_attacks(capsys):
    report = run_json(capsys)
    found = sorted((f["rule"], f["source_ip"]) for f in report["findings"])
    assert found == [
        ("brute_force", "192.0.2.99"),
        ("brute_force", "203.0.113.45"),
        ("password_spray", "198.51.100.200"),
        ("password_spray", "203.0.113.77"),
        ("success_after_failures", "192.0.2.99"),
        ("success_after_failures", "203.0.113.12"),
    ]


def test_normal_users_and_slow_probing_are_not_flagged(capsys):
    flagged_ips = {f["source_ip"] for f in run_json(capsys)["findings"]}
    assert flagged_ips.isdisjoint({"198.51.100.12", "198.51.100.13", "203.0.113.200"})


def test_top_ips_come_from_sql_summary(capsys):
    top = run_json(capsys)["top_failed_ips"]
    assert top[0] == {"source_ip": "203.0.113.45", "failed_logins": 40, "accounts_tried": 1}


def test_raising_threshold_removes_smaller_attacks(capsys):
    rules = {f["rule"] for f in run_json(capsys, "--brute-threshold", "50", "--spray-threshold", "50")["findings"]}
    assert rules == {"success_after_failures"}


def test_fail_on_returns_exit_code_1(capsys):
    assert main([*BOTH_LOGS, "--year", "2026", "--fail-on", "critical"]) == 1


def test_markdown_report_written_to_file(tmp_path, capsys):
    out = tmp_path / "report.md"
    assert main([*BOTH_LOGS, "--year", "2026", "--format", "markdown", "-o", str(out)]) == 0
    text = out.read_text()
    assert text.startswith("# Login Sentinel Report")
    assert "| CRITICAL |" in text


def test_database_file_can_be_queried_afterwards(tmp_path, capsys):
    db = tmp_path / "events.db"
    main([*BOTH_LOGS, "--year", "2026", "--db", str(db)])
    # closing() actually closes the connection; sqlite3's own `with` only commits.
    with closing(sqlite3.connect(db)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 6
        assert conn.execute("SELECT COUNT(*) FROM events WHERE success = 1").fetchone()[0] > 0


def test_missing_file_returns_exit_code_2(tmp_path, capsys):
    assert main([str(tmp_path / "nope.log")]) == 2
    assert "not found" in capsys.readouterr().err


def test_file_with_no_login_events_returns_exit_code_2(tmp_path, capsys):
    path = tmp_path / "empty.log"
    path.write_text("nothing to see here\n")
    assert main([str(path)]) == 2


def test_threshold_below_one_is_rejected(capsys):
    assert main([*BOTH_LOGS, "--window", "0"]) == 2
    assert "--window must be at least 1" in capsys.readouterr().err


def test_csv_with_wrong_columns_returns_exit_code_2(tmp_path, capsys):
    bad = tmp_path / "bad.csv"
    bad.write_text("Time,Event\n2026-10-13T01:30:00,4625\n")
    assert main([str(bad)]) == 2
    assert "missing columns" in capsys.readouterr().err


def test_runs_as_python_module():
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-m", "login_sentinel", "--version"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0
    assert "login-sentinel 1.0.0" in result.stdout
