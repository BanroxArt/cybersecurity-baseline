"""Committed secret detection for a local checkout.

This is a fast first pass, not a replacement for gitleaks or GitHub secret
scanning. It only reads the working tree, so a secret that was committed and
then deleted is invisible here. Run a history scanner as well.
"""

from __future__ import annotations

import fnmatch
import math
import re
import subprocess
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from baseline_audit.findings import Finding, Status, fingerprint, redact

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".terraform"}
MAX_BYTES = 1_000_000


@dataclass(frozen=True, slots=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    group: int = 0
    min_entropy: float = 0.0


RULES = [
    Rule("aws-access-key-id", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 1),
    Rule(
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY( BLOCK)?-----"),
    ),
    Rule(
        "github-token",
        re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b"),
        1,
    ),
    Rule("gitlab-token", re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"), 1),
    Rule("slack-token", re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"), 1),
    Rule("stripe-live-key", re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b"), 1),
    Rule("twilio-api-key", re.compile(r"\b(SK[0-9a-f]{32})\b"), 1),
    Rule("google-api-key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), 1),
    Rule(
        "generic-assignment",
        re.compile(
            r"""(?i)\b(?:api[_-]?key|secret|token|passw(?:or)?d|client[_-]?secret)\b"""
            r"""\s*[:=]\s*["']([^"'\s$<>{}]{16,})["']"""
        ),
        1,
        min_entropy=3.5,
    ),
]

# Values that look like secrets but are obviously placeholders.
PLACEHOLDER = re.compile(
    r"(?i)(example|changeme|placeholder|dummy|your[_-]|xxxx|\*\*\*\*|test|fake)"
)

ENV_GLOBS = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_rsa",
    "id_rsa*",
    "id_ed25519*",
    "*.p12",
    "*.pfx",
)
ENV_ALLOWED = (".env.example", ".env.sample", ".env.template")


def entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())


def _is_binary(chunk: bytes) -> bool:
    return b"\x00" in chunk


def iter_files(root: Path) -> Iterator[Path]:
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts[:-1]) or rel.parts[0] in SKIP_DIRS:
            continue
        if path.is_file() and not path.is_symlink():
            yield path


def load_ignore(root: Path) -> set[str]:
    """Fingerprints listed in .baseline-ignore, one per line, # comments allowed."""
    path = root / ".baseline-ignore"
    if not path.is_file():
        return set()
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(line)
    return out


def scan_text(text: str) -> Iterator[tuple[int, str, str]]:
    """Yield ``(line_number, rule_name, matched_value)``."""
    for i, line in enumerate(text.splitlines(), 1):
        for rule in RULES:
            for m in rule.pattern.finditer(line):
                value = m.group(rule.group)
                if rule.min_entropy and (
                    entropy(value) < rule.min_entropy or PLACEHOLDER.search(value)
                ):
                    continue
                yield i, rule.name, value


def scan_secrets(root: Path) -> list[Finding]:
    ignored = load_ignore(root)
    findings: list[Finding] = []
    for path in iter_files(root):
        try:
            if path.stat().st_size > MAX_BYTES:
                continue
            raw = path.read_bytes()
        except OSError:
            continue
        if _is_binary(raw[:4096]):
            continue
        text = raw.decode("utf-8", errors="replace")
        rel = path.relative_to(root).as_posix()
        for line, rule, value in scan_text(text):
            if fingerprint(value) in ignored:
                continue
            findings.append(
                Finding("SEC-01", Status.FAIL, f"{rule} {redact(value)}", f"{rel}:{line}")
            )
    if not findings:
        findings.append(Finding("SEC-01", Status.PASS, "no credential patterns in working tree"))
    return findings


def tracked_files(root: Path) -> list[str] | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True, timeout=30
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return [p for p in out.decode("utf-8", errors="replace").split("\0") if p]


def _matches_env(name: str) -> bool:
    if name in ENV_ALLOWED:
        return False
    return any(fnmatch.fnmatch(name, g) for g in ENV_GLOBS)


def scan_env_files(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    tracked = tracked_files(root)
    if tracked is None:
        findings.append(Finding("SEC-02", Status.SKIP, "not a git checkout, tracked files unknown"))
    else:
        bad = [p for p in tracked if _matches_env(Path(p).name)]
        for p in bad:
            findings.append(Finding("SEC-02", Status.FAIL, "env or key file is tracked", p))
        if not bad:
            findings.append(Finding("SEC-02", Status.PASS, "no env or key files tracked"))

    gitignore = root / ".gitignore"
    patterns = []
    if gitignore.is_file():
        patterns = [
            ln.strip()
            for ln in gitignore.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.startswith("#")
        ]
    missing = [
        want
        for want in (".env", "*.pem", "*.key")
        if not any(fnmatch.fnmatch(want, p.lstrip("/")) or p.lstrip("/") == want for p in patterns)
    ]
    if missing:
        findings.append(
            Finding(
                "SEC-03",
                Status.FAIL,
                f".gitignore does not cover {', '.join(missing)}",
                ".gitignore",
            )
        )
    else:
        findings.append(Finding("SEC-03", Status.PASS, ".gitignore covers env and key files"))
    return findings
