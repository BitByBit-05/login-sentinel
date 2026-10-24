"""Unit tests for the three report formats."""

import json
from datetime import datetime, timedelta

import pytest

from login_sentinel import report
from login_sentinel.models import Finding, Severity

START = datetime(2026, 10, 12, 22, 41, 0)
STATS = {
    "total": 10, "succeeded": 3, "failed": 7, "unique_ips": 2, "unique_users": 3,
    "first_event": "2026-10-12T22:00:00", "last_event": "2026-10-12T23:00:00",
}
TOP_IPS = [{"source_ip": "192.0.2.99", "failed_logins": 6, "accounts_tried": 1}]


def finding(severity=Severity.CRITICAL, users=("bob",), end=START + timedelta(minutes=3)):
    return Finding(
        rule="success_after_failures", severity=severity, mitre_technique="T1078",
        source_ip="192.0.2.99", users=list(users), first_seen=START, last_seen=end,
        event_count=7, description="'bob' logged in after 6 failed attempts",
    )


@pytest.mark.parametrize("fmt", ["text", "markdown", "json"])
def test_every_format_handles_no_findings(fmt):
    output = report.FORMATTERS[fmt](STATS, [], [], skipped=0)
    if fmt == "json":
        assert json.loads(output)["findings"] == []
    else:
        assert "No suspicious activity found." in output


def test_text_report_contains_finding_details():
    text = report.to_text(STATS, [finding()], TOP_IPS, skipped=4)
    assert "CRITICAL | success_after_failures | MITRE T1078" in text
    assert "Lines skipped   : 4" in text
    assert "192.0.2.99" in text
    assert "Seen: 2026-10-12 22:41:00 to 22:44:00" in text


def test_text_report_shows_full_date_when_attack_crosses_midnight():
    text = report.to_text(STATS, [finding(end=datetime(2026, 10, 13, 0, 5, 0))], [], skipped=0)
    assert "to 2026-10-13 00:05:00" in text


def test_long_account_lists_are_shortened():
    users = [f"user{i}" for i in range(10)]
    text = report.to_text(STATS, [finding(users=users)], [], skipped=0)
    assert "user0, user1, user2, user3 (+6 more)" in text


def test_markdown_report_has_tables():
    md = report.to_markdown(STATS, [finding()], TOP_IPS, skipped=0)
    assert md.startswith("# Login Sentinel Report")
    assert "| 1 | CRITICAL | `success_after_failures` | T1078 | 192.0.2.99 | bob | 7 |" in md
    assert "| 192.0.2.99 | 6 | 1 |" in md


def test_json_report_structure():
    data = json.loads(report.to_json(STATS, [finding(), finding(Severity.HIGH)], TOP_IPS, skipped=2))
    assert data["summary"]["lines_skipped"] == 2
    assert data["severity_counts"] == {"CRITICAL": 1, "HIGH": 1}
    assert data["findings"][0]["first_seen"] == "2026-10-12T22:41:00"
    assert data["top_failed_ips"] == TOP_IPS
