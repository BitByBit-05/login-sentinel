"""End-to-end tests: run the real command on the sample logs."""

import json
from pathlib import Path

from login_sentinel.cli import main

SAMPLES = Path(__file__).resolve().parent.parent / "sample_data"
BOTH_LOGS = [str(SAMPLES / "auth.log"), str(SAMPLES / "windows_security.csv")]


def run_json(capsys):
    assert main([*BOTH_LOGS, "--year", "2026", "--format", "json"]) == 0
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
    # carol and dave mistype passwords; 203.0.113.200 probes slowly over two hours
    assert flagged_ips.isdisjoint({"198.51.100.12", "198.51.100.13", "203.0.113.200"})


def test_markdown_report_written_to_file(tmp_path, capsys):
    out = tmp_path / "report.md"
    assert main([*BOTH_LOGS, "--year", "2026", "--format", "markdown", "-o", str(out)]) == 0
    assert out.read_text().startswith("# Login Sentinel Report")


def test_fail_on_returns_exit_code_1(capsys):
    assert main([*BOTH_LOGS, "--year", "2026", "--fail-on", "critical"]) == 1


def test_missing_file_returns_exit_code_2(tmp_path, capsys):
    assert main([str(tmp_path / "nope.log")]) == 2
    assert "not found" in capsys.readouterr().err
