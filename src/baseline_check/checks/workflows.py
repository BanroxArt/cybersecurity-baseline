"""GitHub Actions workflow checks.

Covers the workflow mistakes that have actually been used to steal
repository secrets: mutable action refs, over-broad tokens,
``pull_request_target`` and ``workflow_run`` jobs that run fork code or
artifacts, and expression injection from issue or PR text into shell steps.

This reads the YAML; it does not evaluate expressions or follow reusable
workflows into other repositories. A reusable workflow call is checked for
pinning only.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

from baseline_check.findings import Finding, Status

SHA_REF = re.compile(r"^[0-9a-f]{40}$")
DIGEST_REF = re.compile(r"@sha256:[0-9a-f]{64}$")
# Fields an outside contributor controls, anywhere inside a ${{ }} expression.
# Interpolating them into run: or a github-script body is script injection.
UNTRUSTED_FIELD = (
    r"github\s*\.\s*(?:event\s*\.\s*(?:"
    r"issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.\w+)"
    r"|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)"
    r"|discussion_comment\.body|release\.(?:name|body|tag_name)"
    r"|head_commit\.(?:message|author\.\w+)|commits(?:\[[^\]]*\])?\.(?:message|author\.\w+)"
    r"|pages(?:\[[^\]]*\])?\.page_name|workflow_run\.(?:head_branch|display_title|head_commit\.\w+)"
    r")|head_ref)"
    r"|github\s*\[\s*'event'\s*\]"
)
UNTRUSTED = re.compile(r"\$\{\{(?:(?!\}\}).)*?(?:" + UNTRUSTED_FIELD + r")(?:(?!\}\}).)*\}\}", re.S)
HEAD_REF = re.compile(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|refs/pull/")
FORK_REPO = re.compile(r"github\.event\.pull_request\.head\.repo\.full_name")
PR_FETCH = re.compile(r"\bgh\s+pr\s+checkout\b|\bgit\s+fetch\b[^\n]*\brefs/pull/|\bpull/\$\{\{")
ARTIFACT_DOWNLOAD = ("actions/download-artifact", "dawidd6/action-download-artifact")
TRUSTED_OWNERS = ("actions/", "github/")


def _load(path: Path) -> dict[str, Any] | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError):
        return None
    return data if isinstance(data, dict) else None


def _triggers(doc: dict[Any, Any]) -> set[str]:
    # PyYAML reads a bare `on:` key as boolean True.
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(x) for x in on}
    if isinstance(on, dict):
        return {str(k) for k in on}
    return set()


def _jobs(doc: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return
    for job_id, job in jobs.items():
        if isinstance(job, dict):
            yield str(job_id), job


def _steps(doc: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any], int, dict[str, Any]]]:
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
    refs = [(f"{rel}:jobs.{job_id}", job.get("uses")) for job_id, job in _jobs(doc)]
    refs += [(f"{rel}:jobs.{j}.steps[{i}]", step.get("uses")) for j, _, i, step in _steps(doc)]
    for where, uses in refs:
        if not isinstance(uses, str) or uses.startswith("./"):
            continue
        if uses.startswith("docker://"):
            if not DIGEST_REF.search(uses):
                unpinned.append((where, uses))
            continue
        ref = uses.rsplit("@", 1)[1] if "@" in uses else ""
        if not SHA_REF.match(ref):
            unpinned.append((where, uses))
    for loc, uses in unpinned:
        # First-party actions still move tags, but a compromised third-party
        # action is the realistic threat; rate those as the failure.
        status = Status.WARN if uses.startswith(TRUSTED_OWNERS) else Status.FAIL
        what = "an image digest" if uses.startswith("docker://") else "a commit SHA"
        out.append(Finding("CI-01", status, f"{uses} not pinned to {what}", loc))
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
    for job_id, job in _jobs(doc):
        if job.get("permissions") == "write-all":
            out.append(
                Finding("CI-02", Status.FAIL, "job permissions: write-all", f"{rel}:jobs.{job_id}")
            )

    privileged = sorted(triggers & {"pull_request_target", "workflow_run"})
    if privileged:
        risky: list[tuple[str, str, Status]] = []
        for job_id, _job, idx, step in _steps(doc):
            where = f"{rel}:jobs.{job_id}.steps[{idx}]"
            uses = str(step.get("uses", ""))
            with_ = step.get("with") or {}
            if uses.startswith("actions/checkout") and (
                HEAD_REF.search(str(with_.get("ref", "")))
                or FORK_REPO.search(str(with_.get("repository", "")))
            ):
                risky.append(
                    (
                        where,
                        "privileged trigger checks out PR code; it runs with secrets",
                        Status.FAIL,
                    )
                )
            run = step.get("run")
            if isinstance(run, str) and PR_FETCH.search(run):
                risky.append(
                    (where, "privileged trigger fetches PR code in a run step", Status.FAIL)
                )
            if "workflow_run" in triggers and uses.startswith(ARTIFACT_DOWNLOAD):
                risky.append(
                    (
                        where,
                        "workflow_run downloads artifacts from the triggering run; treat them "
                        "as untrusted and never execute them",
                        Status.WARN,
                    )
                )
        for where, msg, status in risky:
            out.append(Finding("CI-03", status, msg, where))
        if not risky:
            out.append(
                Finding(
                    "CI-03",
                    Status.PASS,
                    f"{', '.join(privileged)} does not check out or fetch PR code",
                    rel,
                )
            )
    else:
        out.append(
            Finding("CI-03", Status.PASS, "no pull_request_target or workflow_run trigger", rel)
        )

    injected = []
    for job_id, _job, idx, step in _steps(doc):
        bodies = [step.get("run")]
        if str(step.get("uses", "")).startswith("actions/github-script"):
            bodies.append((step.get("with") or {}).get("script"))
        if any(isinstance(b, str) and UNTRUSTED.search(b) for b in bodies):
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
        return [
            Finding(c, Status.SKIP, "no workflows") for c in ("CI-01", "CI-02", "CI-03", "CI-04")
        ]
    out: list[Finding] = []
    for f in files:
        out += check_workflow(f, f.relative_to(root).as_posix())
    return out
