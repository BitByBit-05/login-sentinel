"""Turn raw log files into LoginEvent objects.

Two formats are supported:

* Linux ``/var/log/auth.log`` lines written by the SSH server (sshd).
* Windows Security event log exported to CSV (event 4624 = successful
  logon, 4625 = failed logon). ``scripts/export_windows_events.ps1``
  produces this CSV on a Windows machine.

Lines that are not login attempts (cron jobs, session messages, etc.) are
counted as skipped rather than treated as errors, because real logs are
full of them.
"""

import csv
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .models import LoginEvent

# Example lines this matches:
#   Oct 12 03:14:07 web01 sshd[2231]: Failed password for root from 203.0.113.45 port 52344 ssh2
#   Oct 12 03:14:09 web01 sshd[2231]: Failed password for invalid user admin from 203.0.113.45 port 52346 ssh2
#   Oct 12 08:01:22 web01 sshd[3302]: Accepted publickey for alice from 198.51.100.7 port 50122 ssh2
SSHD_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) sshd\[\d+\]: "
    r"(?P<result>Failed|Accepted) (?:password|publickey|keyboard-interactive/pam) "
    r"for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9A-Fa-f.:]+) port \d+"
)

WINDOWS_SUCCESS_ID = "4624"
WINDOWS_FAILURE_ID = "4625"
WINDOWS_COLUMNS = {"TimeCreated", "EventID", "TargetUserName", "IpAddress", "WorkstationName"}


@dataclass
class ParseResult:
    """Events that were parsed, plus how many lines were ignored."""

    events: list[LoginEvent] = field(default_factory=list)
    skipped: int = 0


def parse_linux_auth(lines, year: int) -> ParseResult:
    """Parse sshd lines from a Linux auth.log.

    auth.log timestamps have no year ("Oct 12 03:14:07"), so the caller
    supplies the year the log starts in. If the month goes backwards
    (Dec -> Jan), the log has crossed New Year and the year is bumped.
    """
    result = ParseResult()
    current_year = year
    previous_month = None

    for line in lines:
        match = SSHD_PATTERN.match(line.strip())
        if not match:
            result.skipped += 1
            continue

        parsed = datetime.strptime(f"{current_year} {match['timestamp']}", "%Y %b %d %H:%M:%S")
        if previous_month is not None and parsed.month < previous_month:
            current_year += 1
            parsed = parsed.replace(year=current_year)
        previous_month = parsed.month

        result.events.append(
            LoginEvent(
                timestamp=parsed,
                user=match["user"],
                source_ip=match["ip"],
                success=match["result"] == "Accepted",
                host=match["host"],
                log_source="linux_auth",
            )
        )
    return result


def parse_windows_csv(path: Path) -> ParseResult:
    """Parse a CSV export of Windows Security events 4624 and 4625."""
    result = ParseResult()
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        missing = WINDOWS_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"{path} is missing columns: {', '.join(sorted(missing))}")

        for row in reader:
            event_id = row["EventID"].strip()
            ip = row["IpAddress"].strip()
            # "-" means a local logon with no network address; it can't be an
            # attack from another machine, so it is skipped.
            if event_id not in (WINDOWS_SUCCESS_ID, WINDOWS_FAILURE_ID) or ip in ("", "-"):
                result.skipped += 1
                continue
            try:
                timestamp = datetime.fromisoformat(row["TimeCreated"].strip())
            except ValueError:
                result.skipped += 1
                continue

            result.events.append(
                LoginEvent(
                    timestamp=timestamp.replace(tzinfo=None),
                    user=row["TargetUserName"].strip(),
                    source_ip=ip,
                    success=event_id == WINDOWS_SUCCESS_ID,
                    host=row["WorkstationName"].strip(),
                    log_source="windows_security",
                )
            )
    return result


def parse_file(path: Path, year: int) -> ParseResult:
    """Pick the right parser from the file extension: .csv is Windows, anything else is Linux."""
    path = Path(path)
    if path.suffix.lower() == ".csv":
        return parse_windows_csv(path)
    with open(path, encoding="utf-8", errors="replace") as handle:
        return parse_linux_auth(handle, year)
