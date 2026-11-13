"""The baseline control list.

Short on purpose. Each control is something a five to fifty person team can
check and fix itself, and that, when missing, has led to real account or data
takeovers. The ``refs`` point at public guidance so a reader can see where an
item comes from; they are not a claim of conformance to any framework.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 3
    HIGH = 5
    CRITICAL = 10

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity {value!r}") from exc


@dataclass(frozen=True, slots=True)
class Control:
    id: str
    area: str
    title: str
    severity: Severity
    fix: str
    refs: tuple[str, ...] = ()


_CONTROLS = [
    # Source and secrets
    Control(
        "SEC-01",
        "secrets",
        "No credentials committed to the repository",
        Severity.CRITICAL,
        "Rotate the credential first, then remove it. Deleting it from HEAD is not enough; "
        "it stays in history and in every clone.",
    ),
    Control(
        "SEC-02",
        "secrets",
        "No .env or key files tracked by git",
        Severity.HIGH,
        "git rm --cached the file, add it to .gitignore, rotate whatever was in it.",
    ),
    Control(
        "SEC-03",
        "secrets",
        ".gitignore covers env and key files",
        Severity.LOW,
        "Add .env, .env.*, *.pem, *.key and id_rsa* to .gitignore.",
    ),
    # GitHub org
    Control(
        "GH-01",
        "github",
        "Organization requires two-factor authentication",
        Severity.CRITICAL,
        "Org settings > Authentication security > Require two-factor authentication.",
    ),
    Control(
        "GH-02",
        "github",
        "Members cannot create public repositories",
        Severity.MEDIUM,
        "Org settings > Member privileges > Repository creation: private only.",
    ),
    Control(
        "GH-03",
        "github",
        "Default member permission is read or none",
        Severity.MEDIUM,
        "Org settings > Member privileges > Base permissions: Read or No permission.",
    ),
    # GitHub repo
    Control(
        "GH-10",
        "github",
        "Default branch is protected",
        Severity.HIGH,
        "Add a branch protection rule or ruleset for the default branch.",
        ("OpenSSF Scorecard Branch-Protection",),
    ),
    Control(
        "GH-11",
        "github",
        "Changes to the default branch need an approving review",
        Severity.HIGH,
        "Require at least one approving review and dismiss stale approvals.",
    ),
    Control(
        "GH-12",
        "github",
        "Force pushes and deletion blocked on the default branch",
        Severity.HIGH,
        "Untick 'Allow force pushes' and 'Allow deletions' on the protection rule.",
    ),
    Control(
        "GH-13",
        "github",
        "Protection applies to admins",
        Severity.MEDIUM,
        "Tick 'Do not allow bypassing the above settings'.",
    ),
    Control(
        "GH-14",
        "github",
        "Secret scanning and push protection on",
        Severity.HIGH,
        "Repo settings > Code security > Secret scanning and Push protection.",
    ),
    Control(
        "GH-15",
        "github",
        "Dependabot alerts on",
        Severity.MEDIUM,
        "Repo settings > Code security > Dependabot alerts. Turn on security updates too.",
    ),
    Control(
        "GH-16",
        "github",
        "Default GITHUB_TOKEN is read-only",
        Severity.MEDIUM,
        "Repo or org settings > Actions > Workflow permissions: Read repository contents.",
    ),
    # CI workflows
    Control(
        "CI-01",
        "ci",
        "Third-party actions pinned to a full commit SHA",
        Severity.MEDIUM,
        "Replace @v4 style refs with the 40 character commit SHA and keep the tag in a comment.",
        ("OpenSSF Scorecard Pinned-Dependencies",),
    ),
    Control(
        "CI-02",
        "ci",
        "Workflows declare least-privilege permissions",
        Severity.MEDIUM,
        "Add a top-level 'permissions: contents: read' and widen per job only where needed.",
        ("OpenSSF Scorecard Token-Permissions",),
    ),
    Control(
        "CI-03",
        "ci",
        "Privileged workflow triggers do not run untrusted PR code",
        Severity.CRITICAL,
        "Use pull_request instead, or never check out or fetch the PR head in a "
        "pull_request_target or workflow_run job. Treat artifacts from workflow_run as data, "
        "never as code.",
        ("OpenSSF Scorecard Dangerous-Workflow",),
    ),
    Control(
        "CI-04",
        "ci",
        "No untrusted event fields interpolated into run steps",
        Severity.HIGH,
        "Pass github.event values through env: and quote them in the shell, never ${{ }} inline.",
        ("OpenSSF Scorecard Dangerous-Workflow",),
    ),
    # Containers
    Control(
        "CT-01",
        "container",
        "Container runs as a non-root user",
        Severity.MEDIUM,
        "Add a USER instruction with a non-zero UID after installing packages.",
        ("CIS Docker Benchmark 4.1",),
    ),
    Control(
        "CT-02",
        "container",
        "Base images pinned to a version or digest",
        Severity.LOW,
        "Use image:1.2.3 or image@sha256:..., not :latest or no tag.",
    ),
    Control(
        "CT-03",
        "container",
        "No remote ADD or curl-pipe-shell in builds",
        Severity.MEDIUM,
        "Download with a checksum check, or COPY a vendored file.",
    ),
    Control(
        "CT-04",
        "container",
        "No secrets baked into image ENV or ARG",
        Severity.HIGH,
        "Use build secrets (RUN --mount=type=secret) and runtime env, not ENV/ARG.",
    ),
    # Infrastructure as code
    Control(
        "IAC-01",
        "iac",
        "No publicly readable storage buckets",
        Severity.HIGH,
        "Remove public-read ACLs and enable a public access block.",
    ),
    Control(
        "IAC-02",
        "iac",
        "No admin ports open to the internet",
        Severity.HIGH,
        "Restrict 22, 3389 and database ports to a VPN or bastion range.",
    ),
    Control(
        "IAC-03",
        "iac",
        "Storage and databases encrypted at rest",
        Severity.MEDIUM,
        "Set encrypted / storage_encrypted = true.",
    ),
]

CONTROLS: dict[str, Control] = {c.id: c for c in _CONTROLS}


def get(control_id: str) -> Control:
    return CONTROLS[control_id]
