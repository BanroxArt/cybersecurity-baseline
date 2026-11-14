"""SARIF 2.1.0 output, for GitHub code scanning and other SARIF consumers.

One run, one rule per control in ``CONTROLS`` (so ``ruleIndex`` is stable
across runs), and one result per FAIL or WARN finding. PASS and SKIP are not
emitted: code scanning turns every result into an alert, and an alert that
says "this is fine" trains people to dismiss alerts.

Mapping decisions:

- FAIL is ``kind: fail`` with a level from the control severity (critical and
  high are ``error``, medium ``warning``, low ``note``).
- WARN is ``kind: review``. The spec (3.27.9) requires ``level: none`` for any
  kind other than ``fail``, so it is set explicitly rather than left to a
  consumer's default.
- ``security-severity`` on each rule is the number GitHub uses to bucket
  alerts (critical >= 9.0, high >= 7.0, medium >= 4.0).
- Locations. ``path:line`` becomes a physical location with a region,
  ``path:jobs.x.steps[2]`` a physical location plus a logical one for the
  YAML path, and ``org:`` / ``repo:`` locations are logical only, because
  there is no file to point at. File URIs are relative to ``%SRCROOT%`` and
  no absolute path from the machine running the scan is written.
- ``partialFingerprints`` uses the control, location and message with the
  per-run secret fingerprint removed. Without a configured fingerprint key the
  ``fp=h1:...`` part changes every run, and a fingerprint built on it would
  open a fresh alert for the same finding on every scan.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from baseline_check import __version__
from baseline_check.controls import CONTROLS, Control, Severity
from baseline_check.findings import Finding, Status
from baseline_check.report import ControlResult

SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
INFORMATION_URI = "https://github.com/BanroxArt/cybersecurity-baseline"
FINGERPRINT_NAME = "baselineCheck/v1"
SRCROOT = "%SRCROOT%"

LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
}

_LOGICAL_PREFIXES = ("org:", "repo:")
_PATH_LINE = re.compile(r"^(?P<path>[^:]+?):(?P<line>\d+)(?:\s+(?P<what>\S.*))?$")
_PATH_YAML = re.compile(r"^(?P<path>[^:]+):(?P<what>[A-Za-z_][\w.\[\]-]*)$")
_RUN_FINGERPRINT = re.compile(r"\s*fp=h1:[0-9a-f]+")


@dataclass(frozen=True, slots=True)
class ParsedLocation:
    path: str | None = None
    line: int | None = None
    logical: str | None = None
    # SARIF logicalLocation.kind: "resource" for org, repo and Terraform
    # addresses, "property" for a YAML path inside a workflow.
    logical_kind: str = "resource"


def parse_location(location: str) -> ParsedLocation:
    """Split a finding location into a file path, a line and a logical name."""
    loc = location.strip()
    if not loc:
        return ParsedLocation()
    if loc.startswith(_LOGICAL_PREFIXES):
        return ParsedLocation(logical=loc)
    m = _PATH_LINE.match(loc)
    if m:
        line = int(m.group("line"))
        return ParsedLocation(m.group("path"), line if line >= 1 else None, m.group("what"))
    m = _PATH_YAML.match(loc)
    if m:
        return ParsedLocation(m.group("path"), None, m.group("what"), "property")
    if ":" not in loc:
        # A bare relative path; file names may contain spaces.
        return ParsedLocation(path=loc)
    return ParsedLocation(logical=loc)


def _uri(path: str) -> str:
    # Relative URI reference: forward slashes, percent-encoded, never absolute.
    clean = path.replace("\\", "/").lstrip("/")
    return quote(clean, safe="/-._~")


def _locations(finding: Finding) -> list[dict[str, Any]]:
    parsed = parse_location(finding.location)
    loc: dict[str, Any] = {}
    if parsed.path:
        physical: dict[str, Any] = {
            "artifactLocation": {"uri": _uri(parsed.path), "uriBaseId": SRCROOT}
        }
        if parsed.line:
            physical["region"] = {"startLine": parsed.line}
        loc["physicalLocation"] = physical
    if parsed.logical:
        loc["logicalLocations"] = [
            {"fullyQualifiedName": parsed.logical, "kind": parsed.logical_kind}
        ]
    return [loc] if loc else []


def stable_fingerprint(finding: Finding) -> str:
    message = _RUN_FINGERPRINT.sub("", finding.message)
    raw = "\x1f".join((finding.control, finding.location, message))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _rule_name(control: Control) -> str:
    words = re.findall(r"[A-Za-z0-9]+", control.title)
    return "".join(w[:1].upper() + w[1:] for w in words)


def _rule(control: Control) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": control.id,
        "name": _rule_name(control),
        "shortDescription": {"text": control.title},
        "fullDescription": {"text": f"{control.title}. Area: {control.area}."},
        "help": {"text": control.fix, "markdown": f"**Fix:** {control.fix}"},
        "defaultConfiguration": {"level": LEVEL[control.severity]},
        "properties": {
            "tags": ["security", control.area],
            "security-severity": SECURITY_SEVERITY[control.severity],
            "precision": "medium",
        },
    }
    if control.refs:
        rule["helpUri"] = control.refs[0]
    return rule


def _result(finding: Finding, control: Control, index: int) -> dict[str, Any]:
    if finding.status == Status.FAIL:
        kind, level = "fail", LEVEL[control.severity]
    else:
        kind, level = "review", "none"
    result: dict[str, Any] = {
        "ruleId": control.id,
        "ruleIndex": index,
        "kind": kind,
        "level": level,
        "message": {"text": finding.message},
        "partialFingerprints": {FINGERPRINT_NAME: stable_fingerprint(finding)},
    }
    locations = _locations(finding)
    if locations:
        result["locations"] = locations
    return result


def to_sarif(results: list[ControlResult], target: str) -> str:
    controls = list(CONTROLS.values())
    index = {c.id: i for i, c in enumerate(controls)}
    sarif_results: list[dict[str, Any]] = []
    for r in sorted(results, key=lambda r: index[r.control.id]):
        for f in r.findings:
            if f.status in (Status.FAIL, Status.WARN):
                sarif_results.append(_result(f, r.control, index[r.control.id]))
    doc = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "baseline-check",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": [_rule(c) for c in controls],
                    }
                },
                "automationDetails": {"id": f"baseline-check/{target}/"},
                "columnKind": "unicodeCodePoints",
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
