"""Roll findings up into per-control results, a score and a report.

Score: each control has a severity weight (low 1, medium 3, high 5,
critical 10). Only controls that were actually checked count. The score is
passed weight over checked weight, as a percentage. WARN counts as half.
It is a way to track your own progress between runs, not a grade to
compare companies with.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime

from baseline_check.controls import CONTROLS, Control, Severity
from baseline_check.findings import Finding, Status

ORDER = {Status.FAIL: 0, Status.WARN: 1, Status.PASS: 2, Status.SKIP: 3}


@dataclass(slots=True)
class ControlResult:
    control: Control
    status: Status
    findings: list[Finding]


def roll_up(findings: list[Finding]) -> list[ControlResult]:
    by_id: dict[str, list[Finding]] = {cid: [] for cid in CONTROLS}
    for f in findings:
        by_id.setdefault(f.control, []).append(f)
    results = []
    for cid, items in by_id.items():
        if cid not in CONTROLS:
            continue
        statuses = {f.status for f in items}
        if Status.FAIL in statuses:
            status = Status.FAIL
        elif Status.WARN in statuses:
            status = Status.WARN
        elif Status.PASS in statuses:
            status = Status.PASS
        else:
            status = Status.SKIP
        results.append(ControlResult(CONTROLS[cid], status, items))
    results.sort(key=lambda r: (ORDER[r.status], -r.control.severity, r.control.id))
    return results


def score(results: list[ControlResult]) -> float | None:
    checked = [r for r in results if r.status != Status.SKIP]
    total = sum(int(r.control.severity) for r in checked)
    if not total:
        return None
    got = sum(
        int(r.control.severity)
        * (1.0 if r.status == Status.PASS else 0.5 if r.status == Status.WARN else 0)
        for r in checked
    )
    return round(100.0 * got / total, 1)


def worst_failure(results: list[ControlResult]) -> Severity | None:
    fails = [r.control.severity for r in results if r.status == Status.FAIL]
    return max(fails) if fails else None


def to_json(results: list[ControlResult], target: str) -> str:
    doc = {
        "target": target,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "score": score(results),
        "summary": {s.value: sum(1 for r in results if r.status == s) for s in Status},
        "controls": [
            {
                "id": r.control.id,
                "area": r.control.area,
                "title": r.control.title,
                "severity": r.control.severity.name.lower(),
                "status": r.status.value,
                "fix": r.control.fix if r.status in (Status.FAIL, Status.WARN) else "",
                "refs": list(r.control.refs),
                "findings": [f.to_dict() for f in r.findings if f.status != Status.PASS],
            }
            for r in results
        ],
    }
    return json.dumps(doc, indent=2)


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def to_markdown(results: list[ControlResult], target: str) -> str:
    s = score(results)
    counts = {st: sum(1 for r in results if r.status == st) for st in Status}
    lines = [
        f"# Baseline check: {target}",
        "",
        f"Score {s if s is not None else 'n/a'} / 100 over checked controls. "
        f"{counts[Status.FAIL]} fail, {counts[Status.WARN]} warn, {counts[Status.PASS]} pass, "
        f"{counts[Status.SKIP]} not checked.",
        "",
        "This is a self-check against a short baseline. It is not a penetration test, an audit "
        "opinion or a certification.",
        "",
        "| Control | Severity | Status | Title |",
        "| --- | --- | --- | --- |",
    ]
    for r in results:
        lines.append(
            f"| {r.control.id} | {r.control.severity.name.lower()} | {r.status.value} | {_cell(r.control.title)} |"
        )
    problems = [r for r in results if r.status in (Status.FAIL, Status.WARN)]
    if problems:
        lines += ["", "## What to fix", ""]
        for r in problems:
            lines.append(f"### {r.control.id} {r.control.title}")
            lines.append("")
            for f in r.findings:
                if f.status in (Status.FAIL, Status.WARN):
                    where = f" (`{f.location}`)" if f.location else ""
                    lines.append(f"- {f.status.value}: {f.message}{where}")
            lines += ["", f"Fix: {r.control.fix}", ""]
    return "\n".join(lines).rstrip() + "\n"
