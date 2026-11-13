"""GitHub organization and repository settings.

Reads settings through the REST API with a token from the environment
(``GITHUB_TOKEN``). The token only needs read access: a fine-grained token
with read-only "Administration" on the org and on the repos you want checked.
Some org fields are only returned to owners; when they are missing the check
reports WARN rather than guessing. Nothing here writes to GitHub.

For tests and dry runs the HTTP layer is swappable. ``FixtureTransport``
serves recorded JSON from a directory, ``DryRunTransport`` just records which
requests would have been made.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from baseline_audit.findings import Finding, Status

API = "https://api.github.com"


@dataclass(slots=True)
class Response:
    status: int
    body: Any = None


Transport = Callable[[str], Response]


class GitHubError(RuntimeError):
    pass


class UrllibTransport:
    def __init__(self, token: str, base: str = API, timeout: float = 15.0) -> None:
        if not token:
            raise GitHubError("GITHUB_TOKEN is not set")
        self._token = token
        self.base = base.rstrip("/")
        self.timeout = timeout

    def __repr__(self) -> str:  # keep the token out of logs and tracebacks
        return f"UrllibTransport(base={self.base!r})"

    def __call__(self, path: str) -> Response:
        req = urllib.request.Request(
            self.base + path,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "baseline-audit",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                return Response(resp.status, json.loads(raw) if raw else None)
        except urllib.error.HTTPError as exc:
            body = None
            with contextlib.suppress(ValueError, OSError):
                body = json.loads(exc.read() or b"null")
            return Response(exc.code, body)
        except urllib.error.URLError as exc:
            raise GitHubError(f"request failed: {exc.reason}") from exc


def _fixture_name(path: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", path.strip("/")) + ".json"


class FixtureTransport:
    """Serve ``{"status": 200, "body": ...}`` files. Missing file means 404."""

    def __init__(self, directory: str | Path) -> None:
        self.dir = Path(directory)
        self.requests: list[str] = []

    def __call__(self, path: str) -> Response:
        self.requests.append(path)
        f = self.dir / _fixture_name(path)
        if not f.is_file():
            return Response(404, {"message": "Not Found"})
        data = json.loads(f.read_text(encoding="utf-8"))
        return Response(int(data.get("status", 200)), data.get("body"))


@dataclass
class DryRunTransport:
    requests: list[str] = field(default_factory=list)

    def __call__(self, path: str) -> Response:
        self.requests.append(path)
        return Response(0, None)


def transport_from_env() -> UrllibTransport:
    return UrllibTransport(
        os.environ.get("GITHUB_TOKEN", ""), os.environ.get("GITHUB_API_URL", API)
    )


def _denied(r: Response) -> bool:
    return r.status in (401, 403)


def check_org(get: Transport, org: str) -> list[Finding]:
    r = get(f"/orgs/{org}")
    loc = f"org:{org}"
    if r.status == 0:
        return []
    if r.status != 200 or not isinstance(r.body, dict):
        msg = "token cannot read org settings" if _denied(r) else f"GET org returned {r.status}"
        return [Finding(c, Status.WARN, msg, loc) for c in ("GH-01", "GH-02", "GH-03")]
    b = r.body
    out = []
    # These fields are only returned to org owners. Missing means "could not tell".
    tfa = b.get("two_factor_requirement_enabled")
    if tfa is None:
        out.append(
            Finding(
                "GH-01", Status.WARN, "2FA requirement not visible; token is not an org owner", loc
            )
        )
    else:
        out.append(
            Finding(
                "GH-01",
                Status.PASS if tfa else Status.FAIL,
                "2FA required" if tfa else "2FA not required for members",
                loc,
            )
        )
    public = b.get("members_can_create_public_repositories")
    if public is None:
        out.append(Finding("GH-02", Status.WARN, "repo creation policy not visible", loc))
    else:
        out.append(
            Finding(
                "GH-02",
                Status.FAIL if public else Status.PASS,
                "members can create public repos" if public else "public repo creation restricted",
                loc,
            )
        )
    perm = b.get("default_repository_permission")
    if perm is None:
        out.append(Finding("GH-03", Status.WARN, "base permission not visible", loc))
    else:
        ok = perm in ("read", "none")
        out.append(
            Finding("GH-03", Status.PASS if ok else Status.FAIL, f"base permission is {perm}", loc)
        )
    return out


def check_repo(get: Transport, full_name: str) -> list[Finding]:
    loc = f"repo:{full_name}"
    r = get(f"/repos/{full_name}")
    if r.status == 0:
        # Dry run: still walk the other endpoints so the request list is complete.
        for p in (
            "/branches/main/protection",
            "/vulnerability-alerts",
            "/actions/permissions/workflow",
        ):
            get(f"/repos/{full_name}{p}")
        return []
    if r.status != 200 or not isinstance(r.body, dict):
        return [Finding("GH-10", Status.WARN, f"GET repo returned {r.status}", loc)]
    repo = r.body
    branch = repo.get("default_branch", "main")
    out: list[Finding] = []
    out += _protection(get, full_name, branch, loc)
    out += _security_analysis(repo, loc, private=bool(repo.get("private")))
    out += _dependabot(get, full_name, loc)
    out += _workflow_token(get, full_name, loc)
    return out


def _protection(get: Transport, full_name: str, branch: str, loc: str) -> list[Finding]:
    r = get(f"/repos/{full_name}/branches/{branch}/protection")
    bloc = f"{loc}@{branch}"
    if r.status == 404:
        # 404 means no classic protection rule. Rulesets are a separate API and
        # are reported as a limitation, see README.
        fail = Finding("GH-10", Status.FAIL, "no branch protection rule on default branch", bloc)
        return [fail] + [
            Finding(c, Status.FAIL, "branch not protected", bloc)
            for c in ("GH-11", "GH-12", "GH-13")
        ]
    if r.status != 200 or not isinstance(r.body, dict):
        msg = (
            "token cannot read branch protection"
            if _denied(r)
            else f"protection returned {r.status}"
        )
        return [Finding(c, Status.WARN, msg, bloc) for c in ("GH-10", "GH-11", "GH-12", "GH-13")]
    p = r.body
    out = [Finding("GH-10", Status.PASS, "default branch protected", bloc)]
    reviews = p.get("required_pull_request_reviews") or {}
    count = int(reviews.get("required_approving_review_count") or 0)
    out.append(
        Finding(
            "GH-11",
            Status.PASS if count >= 1 else Status.FAIL,
            f"{count} approving review(s) required",
            bloc,
        )
    )
    force = (p.get("allow_force_pushes") or {}).get("enabled", False)
    delete = (p.get("allow_deletions") or {}).get("enabled", False)
    if force or delete:
        what = " and ".join(w for w, on in (("force pushes", force), ("deletions", delete)) if on)
        out.append(Finding("GH-12", Status.FAIL, f"{what} allowed", bloc))
    else:
        out.append(Finding("GH-12", Status.PASS, "force pushes and deletions blocked", bloc))
    admins = (p.get("enforce_admins") or {}).get("enabled", False)
    out.append(
        Finding(
            "GH-13",
            Status.PASS if admins else Status.FAIL,
            "admins included" if admins else "admins can bypass",
            bloc,
        )
    )
    return out


def _security_analysis(repo: dict, loc: str, private: bool) -> list[Finding]:
    sa = repo.get("security_and_analysis")
    if not isinstance(sa, dict):
        return [
            Finding("GH-14", Status.WARN, "security_and_analysis not visible to this token", loc)
        ]

    def on(key: str) -> bool:
        return (sa.get(key) or {}).get("status") == "enabled"

    scanning, push = on("secret_scanning"), on("secret_scanning_push_protection")
    if scanning and push:
        return [Finding("GH-14", Status.PASS, "secret scanning and push protection enabled", loc)]
    missing = [n for n, v in (("secret scanning", scanning), ("push protection", push)) if not v]
    note = " (private repos need GitHub Secret Protection)" if private else ""
    return [Finding("GH-14", Status.FAIL, f"{' and '.join(missing)} off{note}", loc)]


def _dependabot(get: Transport, full_name: str, loc: str) -> list[Finding]:
    r = get(f"/repos/{full_name}/vulnerability-alerts")
    if r.status == 204 or r.status == 200:
        return [Finding("GH-15", Status.PASS, "Dependabot alerts enabled", loc)]
    if r.status == 404:
        return [Finding("GH-15", Status.FAIL, "Dependabot alerts disabled", loc)]
    return [Finding("GH-15", Status.WARN, f"vulnerability-alerts returned {r.status}", loc)]


def _workflow_token(get: Transport, full_name: str, loc: str) -> list[Finding]:
    r = get(f"/repos/{full_name}/actions/permissions/workflow")
    if r.status != 200 or not isinstance(r.body, dict):
        return [Finding("GH-16", Status.WARN, f"workflow permissions returned {r.status}", loc)]
    perm = r.body.get("default_workflow_permissions")
    approve = r.body.get("can_approve_pull_request_reviews")
    if perm == "read" and not approve:
        return [Finding("GH-16", Status.PASS, "GITHUB_TOKEN defaults to read", loc)]
    bits = []
    if perm != "read":
        bits.append(f"default token permission is {perm}")
    if approve:
        bits.append("Actions can approve pull requests")
    return [Finding("GH-16", Status.FAIL, "; ".join(bits), loc)]
