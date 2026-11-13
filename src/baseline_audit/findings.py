from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum


class Status(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"  # could not prove pass or fail, a person should look
    SKIP = "skip"  # check not applicable or not run


@dataclass(frozen=True, slots=True)
class Finding:
    control: str
    status: Status
    message: str
    location: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "control": self.control,
            "status": self.status.value,
            "message": self.message,
            "location": self.location,
        }


def fingerprint(value: str) -> str:
    """Stable short id for a matched secret, for allowlisting without storing it."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def redact(value: str) -> str:
    """Length and fingerprint only. No characters of the secret are kept."""
    return f"<redacted len={len(value)} fp={fingerprint(value)}>"
