"""Command-line interface.

    python -m login_sentinel sample_data/auth.log
    python -m login_sentinel sample_data/auth.log sample_data/windows_security.csv --format markdown -o report.md
    python -m login_sentinel /var/log/auth.log --db events.db --fail-on high

Exit codes: 0 = finished (and nothing at or above --fail-on), 1 = findings at
or above --fail-on, 2 = bad input. The non-zero codes let a script or a
scheduled job react to an attack automatically.
"""

import argparse
import sys
from datetime import date
from pathlib import Path

from . import __version__, detectors, report, storage
from .models import Severity
from .parsers import parse_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="login-sentinel",
        description="Detect brute-force, password-spraying and account-compromise patterns in login logs.",
    )
    parser.add_argument("logs", nargs="+", type=Path, help="Linux auth.log files and/or Windows Security .csv exports")
    parser.add_argument("-f", "--format", choices=report.FORMATTERS, default="text", help="report format (default: text)")
    parser.add_argument("-o", "--output", type=Path, help="write the report to a file instead of the screen")
    parser.add_argument("--db", default=":memory:", help="SQLite file to keep events and findings in (default: in memory)")
    parser.add_argument("--year", type=int, default=date.today().year, help="year the auth.log starts in (auth.log has no year)")
    parser.add_argument("--window", type=int, default=10, help="detection window in minutes (default: 10)")
    parser.add_argument("--brute-threshold", type=int, default=5, help="failures on one account to flag brute force (default: 5)")
    parser.add_argument("--spray-threshold", type=int, default=5, help="distinct accounts from one IP to flag spraying (default: 5)")
    parser.add_argument(
        "--fail-on",
        choices=[s.name.lower() for s in Severity],
        help="exit with code 1 if any finding is at or above this severity",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for value, name in [(args.window, "--window"), (args.brute_threshold, "--brute-threshold"), (args.spray_threshold, "--spray-threshold")]:
        if value < 1:
            print(f"error: {name} must be at least 1", file=sys.stderr)
            return 2

    events, skipped = [], 0
    for path in args.logs:
        if not path.is_file():
            print(f"error: {path} not found", file=sys.stderr)
            return 2
        try:
            result = parse_file(path, args.year)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        events.extend(result.events)
        skipped += result.skipped

    if not events:
        print("error: no login events found in the input", file=sys.stderr)
        return 2

    config = detectors.DetectionConfig(
        window_minutes=args.window,
        brute_force_threshold=args.brute_threshold,
        spray_user_threshold=args.spray_threshold,
    )
    findings = detectors.run_all(events, config)

    conn = storage.connect(args.db)
    storage.save_events(conn, events)
    storage.save_findings(conn, findings)
    output = report.FORMATTERS[args.format](storage.summary(conn), findings, storage.top_failed_ips(conn), skipped)
    conn.close()

    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"Report written to {args.output} ({len(findings)} findings)")
    else:
        sys.stdout.write(output)

    if args.fail_on and any(f.severity >= Severity[args.fail_on.upper()] for f in findings):
        return 1
    return 0
