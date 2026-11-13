from __future__ import annotations

import hashlib
import hmac
import os
import secrets
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


FINGERPRINT_KEY_ENV = "BASELINE_FINGERPRINT_KEY"
MIN_KEY_LEN = 16


@dataclass(frozen=True, slots=True)
class FingerprintKey:
    """HMAC key for secret fingerprints.

    An unkeyed hash of a secret is a guessing oracle: anyone holding the
    report can hash candidate values (a weak password, a key from another
    leak) and check for a match offline. Keying the hash closes that. With
    no configured key a random one is drawn per run, so fingerprints are not
    comparable across runs; set ``BASELINE_FINGERPRINT_KEY`` (16+ characters,
    kept as secret as the report's subject) to get stable fingerprints for
    ``.baseline-ignore``.
    """

    key: bytes
    configured: bool

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> FingerprintKey:
        raw = (env if env is not None else os.environ).get(FINGERPRINT_KEY_ENV, "")
        if raw:
            if len(raw) < MIN_KEY_LEN:
                raise ValueError(f"{FINGERPRINT_KEY_ENV} must be at least {MIN_KEY_LEN} characters")
            return cls(raw.encode("utf-8"), True)
        return cls.random()

    @classmethod
    def random(cls) -> FingerprintKey:
        return cls(secrets.token_bytes(32), False)

    def __repr__(self) -> str:  # never print the key
        return f"FingerprintKey(configured={self.configured})"


def fingerprint(value: str, key: FingerprintKey) -> str:
    """Keyed short id for a matched secret, for allowlisting without storing it."""
    digest = hmac.new(key.key, value.encode("utf-8"), hashlib.sha256).hexdigest()
    return "h1:" + digest[:16]


def redact(value: str, key: FingerprintKey) -> str:
    """Length and keyed fingerprint only. No characters of the secret are kept."""
    return f"<redacted len={len(value)} fp={fingerprint(value, key)}>"
