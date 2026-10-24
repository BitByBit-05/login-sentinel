"""Data models shared by every part of Login Sentinel.

Every log format gets converted into the same LoginEvent shape, so the
detection rules never need to know where an event came from.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum


@dataclass(frozen=True)
class LoginEvent:
    """One login attempt, successful or not, from any log source."""

    timestamp: datetime
    user: str
    source_ip: str
    success: bool
    host: str
    log_source: str  # "linux_auth" or "windows_security"


class Severity(IntEnum):
    """How serious a finding is. IntEnum makes them comparable: CRITICAL > HIGH."""

    HIGH = 1  # an attack is happening
    CRITICAL = 2  # an attack probably worked

    def __str__(self) -> str:
        return self.name


@dataclass
class Finding:
    """A suspicious pattern found by one detection rule."""

    rule: str
    severity: Severity
    mitre_technique: str  # MITRE ATT&CK technique ID, e.g. "T1110.001"
    source_ip: str
    users: list[str]
    first_seen: datetime
    last_seen: datetime
    event_count: int
    description: str
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Plain dictionary version, used for JSON output and storage."""
        return {
            "rule": self.rule,
            "severity": str(self.severity),
            "mitre_technique": self.mitre_technique,
            "source_ip": self.source_ip,
            "users": self.users,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "event_count": self.event_count,
            "description": self.description,
        }
