"""GitHub Actions workflow checks.

Covers the workflow mistakes that have actually been used to steal
repository secrets: mutable action refs, over-broad tokens,
``pull_request_target`` jobs that run fork code, and expression injection
from issue or PR text into shell steps.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from baseline_audit.findings import Finding, Status

SHA_REF = re.compile(r"^[0-9a-f]{40}$")
# Fields an outside contributor controls. Interpolating them into run: is
# shell injection.
UNTRUSTED = re.compile(
    r"\$\{\{\s*github\.(?:event\.(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body"
    r"|pull_request\.head\.ref|pull_request\.head\.label|comment\.body|review\.body"
    r"|review_comment\.body|head_commit\.message|commits\[\d+\]\.message|pages\[\d+\]\.page_name"
    r"|workflow_run\.head_branch)|head_ref)\s*\}\}"
)
HEAD_REF = re.compile(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|refs/pull/")
TRUSTED_OWNERS = ("actions/", "github/")


def _load(path: Path) -> dict[str, Any] | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError):
        return None
    return data if isinstance(data, dict) else None


def _triggers(doc: dict[str, Any]) -> set[str]:
    # PyYAML reads a bare `on:` key as boolean True.
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(x) for x in on}
    if isinstance(on, dict):
        return {str(k) for k in on}
    return set()


def _steps(doc: dict[str, Any]):
    for job_id, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        for idx, step in enumerate(job.get("steps") or []):
            if isinstance(step, dict):
                yield job_id, job, idx, step


def check_workflow(path: Path, rel: str) -> list[Finding]:
    doc = _load(path)
    if doc is None:
        return [Finding("CI-01", Status.WARN, "workflow does not parse as YAML", rel)]
    out: list[Finding] = []
    triggers = _triggers(doc)

    unpinned = []
    for job_id, _job, idx, step in _steps(doc):
        uses = step.get("uses")
        if not isinstance(uses, str) or uses.startswith(("./", "docker://")):
            continue
        ref = uses.rsplit("@", 1)[1] if "@" in uses else ""
        if not SHA_REF.match(ref):
            unpinned.append((f"{rel}:jobs.{job_id}.steps[{idx}]", uses))
    for loc, uses in unpinned:
        # First-party actions still move tags, but a compromised third-party
        # action is the realistic threat; rate those as the failure.
        status = Status.WARN if uses.startswith(TRUSTED_OWNERS) else Status.FAIL
        out.append(Finding("CI-01", status, f"{uses} not pinned to a commit SHA", loc))
    if not unpinned:
        out.append(Finding("CI-01", Status.PASS, "all actions pinned", rel))

    top = doc.get("permissions")
    jobs = doc.get("jobs") or {}
    if top == "write-all":
        out.append(Finding("CI-02", Status.FAIL, "top-level permissions: write-all", rel))
    elif top is None:
        missing = [j for j, v in jobs.items() if isinstance(v, dict) and "permissions" not in v]
        if missing:
            out.append(
                Finding(
                    "CI-02",
                    Status.FAIL,
                    f"no permissions block; jobs {', '.join(missing)} get the repo default",
                    rel,
                )
            )
        else:
            out.append(Finding("CI-02", Status.PASS, "every job declares permissions", rel))
    else:
        out.append(Finding("CI-02", Status.PASS, "top-level permissions declared", rel))

    if "pull_request_target" in triggers or "workflow_run" in triggers:
        risky = []
        for job_id, _job, idx, step in _steps(doc):
            uses = str(step.get("uses", ""))
            ref = str((step.get("with") or {}).get("ref", ""))
            if uses.startswith("actions/checkout") and HEAD_REF.search(ref):
                risky.append(f"{rel}:jobs.{job_id}.steps[{idx}]")
        for loc in risky:
            out.append(
                Finding(
                    "CI-03",
                    Status.FAIL,
                    "privileged trigger checks out the PR head; fork code runs with secrets",
                    loc,
                )
            )
        if not risky:
            out.append(
                Finding("CI-03", Status.PASS, "privileged trigger does not check out PR code", rel)
            )

    injected = []
    for job_id, _job, idx, step in _steps(doc):
        for key in ("run", "script"):
            body = step.get(key) if key == "run" else (step.get("with") or {}).get("script")
            if isinstance(body, str) and UNTRUSTED.search(body):
                injected.append(f"{rel}:jobs.{job_id}.steps[{idx}]")
    for loc in injected:
        out.append(
            Finding("CI-04", Status.FAIL, "untrusted event field interpolated into a script", loc)
        )
    if not injected:
        out.append(Finding("CI-04", Status.PASS, "no untrusted interpolation in scripts", rel))
    return out


def scan_workflows(root: Path) -> list[Finding]:
    wf_dir = root / ".github" / "workflows"
    files = sorted([*wf_dir.glob("*.yml"), *wf_dir.glob("*.yaml")]) if wf_dir.is_dir() else []
    if not files:
        return [Finding(c, Status.SKIP, "no workflows") for c in ("CI-01", "CI-02", "CI-04")]
    out: list[Finding] = []
    for f in files:
        out += check_workflow(f, f.relative_to(root).as_posix())
    return out
