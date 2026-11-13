"""Committed secret detection for a local checkout.

This is a fast first pass, not a replacement for gitleaks or GitHub secret
scanning. It only reads the working tree, so a secret that was committed and
then deleted is invisible here. Run a history scanner as well.

Findings carry a keyed fingerprint (see ``findings.FingerprintKey``), never
the value or a plain hash of it. Files that were not read (too large,
symlinks, unreadable) are reported as WARN rather than skipped silently.
"""

from __future__ import annotations

import fnmatch
import math
import os
import re
import subprocess
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from baseline_check.findings import Finding, FingerprintKey, Status, fingerprint, redact

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

# Values that look like secrets but are obviously placeholders. Matched as
# whole words split on punctuation, so "your-secret-here" is skipped but a
# random string that happens to contain "test" is still reported.
PLACEHOLDER_WORDS = frozenset(
    {"example", "changeme", "placeholder", "dummy", "test", "fake", "sample", "redacted", "todo"}
)
PLACEHOLDER_SHAPES = re.compile(r"(?i)^your[_-]|xxxx|\*\*\*\*|<[^>]*>")


def is_placeholder(value: str) -> bool:
    if PLACEHOLDER_SHAPES.search(value):
        return True
    words = {w.lower() for w in re.split(r"[^A-Za-z0-9]+", value) if w}
    return bool(words & PLACEHOLDER_WORDS)


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


def iter_files(root: Path, skipped: list[str] | None = None) -> Iterator[Path]:
    """Regular files under ``root``, pruning SKIP_DIRS during the walk.

    Symlinks are never followed (a link can point outside the checkout).
    Their paths are appended to ``skipped`` so the caller can say so.
    """
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        keep = []
        for d in sorted(dirnames):
            if d in SKIP_DIRS:
                continue
            if (base / d).is_symlink():
                if skipped is not None:
                    skipped.append((base / d).relative_to(root).as_posix())
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            path = base / name
            if path.is_symlink():
                if skipped is not None:
                    skipped.append(path.relative_to(root).as_posix())
                continue
            if path.is_file():
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
                    entropy(value) < rule.min_entropy or is_placeholder(value)
                ):
                    continue
                yield i, rule.name, value


def scan_secrets(root: Path, key: FingerprintKey | None = None) -> list[Finding]:
    key = key or FingerprintKey.random()
    ignored = load_ignore(root)
    findings: list[Finding] = []
    skipped: list[str] = []
    too_big: list[str] = []
    unreadable: list[str] = []
    for path in iter_files(root, skipped):
        rel = path.relative_to(root).as_posix()
        try:
            if path.stat().st_size > MAX_BYTES:
                too_big.append(rel)
                continue
            raw = path.read_bytes()
        except OSError:
            unreadable.append(rel)
            continue
        if _is_binary(raw[:4096]):
            continue
        text = raw.decode("utf-8", errors="replace")
        for line, rule, value in scan_text(text):
            if fingerprint(value, key) in ignored:
                continue
            findings.append(
                Finding("SEC-01", Status.FAIL, f"{rule} {redact(value, key)}", f"{rel}:{line}")
            )
    # A scanner that silently skips files reads as clean. Say what was not read.
    for what, paths in (
        (f"over {MAX_BYTES // 1_000_000} MB, not scanned", too_big),
        ("symlinks, not followed", skipped),
        ("unreadable", unreadable),
    ):
        if paths:
            sample = ", ".join(paths[:3]) + (" ..." if len(paths) > 3 else "")
            findings.append(
                Finding("SEC-01", Status.WARN, f"{len(paths)} file(s) {what}: {sample}")
            )
    if ignored and not key.configured:
        findings.append(
            Finding(
                "SEC-01",
                Status.WARN,
                ".baseline-ignore is present but BASELINE_FINGERPRINT_KEY is not set, "
                "so fingerprints are per-run and no entries can match",
                ".baseline-ignore",
            )
        )
    if not any(f.status is Status.FAIL for f in findings):
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


def _ignored_by(name: str, patterns: list[str]) -> bool:
    """Whether a root-level ``name`` ends up ignored, honouring ``!`` negations.

    Only root ``.gitignore`` patterns that can apply to a top-level file are
    considered; patterns scoped to a subdirectory (``config/.env``) do not
    count as covering the root.
    """
    covered = False
    for raw in patterns:
        negate = raw.startswith("!")
        pat = raw[1:] if negate else raw
        pat = pat.lstrip("/").rstrip("/")
        if "/" in pat.strip("*").strip("/"):
            continue
        pat = pat.removeprefix("**/")
        if fnmatch.fnmatch(name, pat) or pat == name:
            covered = not negate
    return covered


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
    patterns: list[str] = []
    if gitignore.is_file():
        patterns = [
            ln.strip()
            for ln in gitignore.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")
        ]
    missing = [want for want in (".env", "*.pem", "*.key") if not _ignored_by(want, patterns)]
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
