"""Format the results as plain text, Markdown or JSON."""

import json

from .models import Finding, Severity


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {str(s): 0 for s in sorted(Severity, reverse=True)}
    for f in findings:
        counts[str(f.severity)] += 1
    return counts


def _users(finding: Finding, limit: int = 4) -> str:
    shown = ", ".join(finding.users[:limit])
    extra = len(finding.users) - limit
    return f"{shown} (+{extra} more)" if extra > 0 else shown


def to_text(stats: dict, findings: list[Finding], top_ips: list[dict], skipped: int) -> str:
    lines = [
        "LOGIN SENTINEL REPORT",
        "=" * 60,
        f"Events analysed : {stats['total']} ({stats['failed']} failed, {stats['succeeded']} succeeded)",
        f"Time range      : {stats['first_event']}  to  {stats['last_event']}",
        f"Unique IPs      : {stats['unique_ips']}    Unique accounts: {stats['unique_users']}",
        f"Lines skipped   : {skipped} (not login attempts)",
        "",
        "Findings: " + "  ".join(f"{k} {v}" for k, v in _severity_counts(findings).items()),
        "-" * 60,
    ]
    if not findings:
        lines.append("No suspicious activity found.")
    for i, f in enumerate(findings, 1):
        lines += [
            f"[{i}] {f.severity} | {f.rule} | MITRE {f.mitre_technique}",
            f"    {f.description}",
            f"    Source IP: {f.source_ip}   Accounts: {_users(f)}",
            f"    Seen: {f.first_seen:%Y-%m-%d %H:%M:%S} to "
            + (f"{f.last_seen:%H:%M:%S}" if f.last_seen.date() == f.first_seen.date() else f"{f.last_seen:%Y-%m-%d %H:%M:%S}"),
            "",
        ]
    if top_ips:
        lines += ["Top source IPs by failed logins", "-" * 60]
        lines += [
            f"  {row['source_ip']:<18} {row['failed_logins']:>4} failed   {row['accounts_tried']:>3} accounts"
            for row in top_ips
        ]
    return "\n".join(lines) + "\n"


def to_markdown(stats: dict, findings: list[Finding], top_ips: list[dict], skipped: int) -> str:
    counts = _severity_counts(findings)
    lines = [
        "# Login Sentinel Report",
        "",
        f"- **Events analysed:** {stats['total']} ({stats['failed']} failed, {stats['succeeded']} succeeded)",
        f"- **Time range:** {stats['first_event']} to {stats['last_event']}",
        f"- **Unique IPs:** {stats['unique_ips']} · **Unique accounts:** {stats['unique_users']}",
        f"- **Lines skipped:** {skipped}",
        "- **Findings:** " + ", ".join(f"{v} {k.lower()}" for k, v in counts.items()),
        "",
        "## Findings",
        "",
    ]
    if findings:
        lines += [
            "| # | Severity | Rule | MITRE | Source IP | Accounts | Events | First seen |",
            "|---|----------|------|-------|-----------|----------|-------:|------------|",
        ]
        lines += [
            f"| {i} | {f.severity} | `{f.rule}` | {f.mitre_technique} | {f.source_ip} | "
            f"{_users(f)} | {f.event_count} | {f.first_seen:%Y-%m-%d %H:%M} |"
            for i, f in enumerate(findings, 1)
        ]
    else:
        lines.append("No suspicious activity found.")
    if top_ips:
        lines += [
            "",
            "## Top source IPs by failed logins",
            "",
            "| Source IP | Failed logins | Accounts tried |",
            "|-----------|--------------:|---------------:|",
        ]
        lines += [
            f"| {r['source_ip']} | {r['failed_logins']} | {r['accounts_tried']} |" for r in top_ips
        ]
    return "\n".join(lines) + "\n"


def to_json(stats: dict, findings: list[Finding], top_ips: list[dict], skipped: int) -> str:
    return json.dumps(
        {
            "summary": {**stats, "lines_skipped": skipped},
            "severity_counts": _severity_counts(findings),
            "findings": [f.to_dict() for f in findings],
            "top_failed_ips": top_ips,
        },
        indent=2,
    ) + "\n"


FORMATTERS = {"text": to_text, "markdown": to_markdown, "json": to_json}
