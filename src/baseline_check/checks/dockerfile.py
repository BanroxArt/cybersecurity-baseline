"""Dockerfile checks. A line-level parser, not a full BuildKit frontend."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from baseline_check.checks.secrets import SKIP_DIRS
from baseline_check.findings import Finding, Status

SECRETISH = re.compile(r"(?i)(passw(or)?d|secret|token|api[_-]?key|private[_-]?key|access[_-]?key)")
CURL_PIPE = re.compile(r"(?i)\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b")


def instructions(text: str) -> list[tuple[int, str, str]]:
    """``(line, INSTRUCTION, args)`` with continuations joined and comments dropped."""
    out: list[tuple[int, str, str]] = []
    buf, start = "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not buf and (not line or line.startswith("#")):
            continue
        if not buf:
            start = i
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        parts = buf.split(None, 1)
        out.append((start, parts[0].upper(), parts[1] if len(parts) > 1 else ""))
        buf = ""
    return out


def _image_pinned(image: str) -> bool:
    if "@sha256:" in image:
        return True
    name = image.rsplit("/", 1)[-1]
    if ":" not in name:
        return False
    return name.rsplit(":", 1)[1] not in ("latest", "")


def _assignments(op: str, args: str) -> list[tuple[str, bool]]:
    """Names set by an ENV or ARG line, and whether each gets a value.

    Handles ``ENV A=1 B="x y"`` (several pairs) and the legacy ``ENV A value``.
    """
    try:
        tokens = shlex.split(args, posix=True)
    except ValueError:
        tokens = args.split()
    if not tokens:
        return []
    if op == "ENV" and "=" not in tokens[0]:
        return [(tokens[0], len(tokens) > 1)]
    out = []
    for tok in tokens:
        name, eq, _ = tok.partition("=")
        if name:
            out.append((name, bool(eq)))
    return out


def check_dockerfile(path: Path, rel: str) -> list[Finding]:
    ins = instructions(path.read_text(encoding="utf-8", errors="replace"))
    out: list[Finding] = []
    # stage name -> USER in effect at the end of that stage
    stage_users: dict[str, str | None] = {}
    current: str | None = None
    last_user: str | None = None
    for line, op, args in ins:
        loc = f"{rel}:{line}"
        if op == "FROM":
            if current is not None:
                stage_users[current] = last_user
            tokens = [t for t in args.split() if not t.startswith("--")]
            image = tokens[0] if tokens else ""
            current = tokens[2].lower() if len(tokens) >= 3 and tokens[1].lower() == "as" else None
            if image.lower() in stage_users:
                # Built on an earlier stage: inherits that stage's USER.
                last_user = stage_users[image.lower()]
                continue
            # An external image or scratch starts as root as far as we can tell.
            last_user = None
            if image == "scratch":
                continue
            if "$" in image:
                out.append(
                    Finding("CT-02", Status.WARN, f"base image {image} comes from a build arg", loc)
                )
                continue
            if not _image_pinned(image):
                out.append(Finding("CT-02", Status.FAIL, f"base image {image} not pinned", loc))
        elif op == "USER":
            last_user = args.split(":", 1)[0].strip()
        elif op == "ADD" and re.search(r"https?://", args):
            out.append(Finding("CT-03", Status.FAIL, "ADD from a URL skips integrity checks", loc))
        elif op == "RUN" and CURL_PIPE.search(args):
            out.append(Finding("CT-03", Status.FAIL, "remote script piped to a shell", loc))
        elif op in ("ENV", "ARG"):
            for name, has_value in _assignments(op, args):
                if SECRETISH.search(name) and (has_value or op == "ARG"):
                    out.append(
                        Finding(
                            "CT-04",
                            Status.FAIL,
                            f"{op} {name} looks like a secret in the image",
                            loc,
                        )
                    )
    if last_user in (None, "root", "0"):
        out.append(Finding("CT-01", Status.FAIL, "final stage runs as root", rel))
    else:
        out.append(Finding("CT-01", Status.PASS, f"final stage runs as {last_user}", rel))
    for cid in ("CT-02", "CT-03", "CT-04"):
        if not any(f.control == cid for f in out):
            out.append(Finding(cid, Status.PASS, "ok", rel))
    return out


def find_dockerfiles(root: Path) -> list[Path]:
    out = []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if p.is_file() and (
            p.name == "Dockerfile"
            or p.name.endswith(".Dockerfile")
            or p.name.startswith("Dockerfile.")
        ):
            out.append(p)
    return out


def scan_dockerfiles(root: Path) -> list[Finding]:
    files = find_dockerfiles(root)
    if not files:
        return [
            Finding(c, Status.SKIP, "no Dockerfiles") for c in ("CT-01", "CT-02", "CT-03", "CT-04")
        ]
    out: list[Finding] = []
    for f in files:
        out += check_dockerfile(f, f.relative_to(root).as_posix())
    return out
