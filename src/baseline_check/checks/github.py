"""GitHub organization and repository settings.

Reads settings through the REST API with a token from the environment
(``GITHUB_TOKEN``). The token only needs read access: a fine-grained token
with read-only "Administration" on the org and on the repos you want checked.
Some org fields are only returned to owners; when they are missing the check
reports WARN rather than guessing. Nothing here writes to GitHub.

The token only ever goes to the configured API origin. ``GITHUB_API_URL``
must be an ``https`` URL with no credentials, query or fragment, and
redirects are followed only when they stay on the same scheme, host and port.
urllib forwards the ``Authorization`` header on redirects by default, so a
cross-host redirect would otherwise hand the token to whoever answered it.

Branch protection is read from both places GitHub keeps it: classic branch
protection and repository rulesets (``/rules/branches/{branch}``). A branch
counts as protected if either source protects it.

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
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from baseline_check.findings import Finding, Status

API = "https://api.github.com"


@dataclass(slots=True)
class Response:
    status: int
    body: Any = None


Transport = Callable[[str], Response]


class GitHubError(RuntimeError):
    pass


def validate_api_url(url: str) -> str:
    """Return ``url`` without a trailing slash, or raise if a token must not go there."""
    parts = urllib.parse.urlsplit(url.strip())
    if parts.scheme != "https":
        raise GitHubError("GITHUB_API_URL must use https")
    if not parts.hostname:
        raise GitHubError("GITHUB_API_URL has no host")
    if parts.username or parts.password:
        raise GitHubError("GITHUB_API_URL must not contain credentials")
    if parts.query or parts.fragment:
        raise GitHubError("GITHUB_API_URL must not have a query or fragment")
    return urllib.parse.urlunsplit(parts._replace(path=parts.path.rstrip("/")))


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urllib.parse.urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.scheme, (parts.hostname or "").lower(), port


class SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only within the origin the request started on."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        if _origin(newurl) != _origin(req.full_url):
            raise GitHubError(
                f"refusing {code} redirect to another origin "
                f"({urllib.parse.urlsplit(newurl).hostname}); the token is not sent there"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class UrllibTransport:
    def __init__(self, token: str, base: str = API, timeout: float = 15.0) -> None:
        if not token:
            raise GitHubError("GITHUB_TOKEN is not set")
        self._token = token
        self.base = validate_api_url(base)
        self.timeout = timeout
        self._opener = urllib.request.build_opener(SameOriginRedirectHandler())

    def __repr__(self) -> str:  # keep the token out of logs and tracebacks
        return f"UrllibTransport(base={self.base!r})"

    def __call__(self, path: str) -> Response:
        req = urllib.request.Request(
            self.base + path,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "baseline-check",
            },
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
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
        os.environ.get("GITHUB_TOKEN", ""), os.environ.get("GITHUB_API_URL") or API
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
        # Dry run: no response, so the default branch is unknown. List the
        # endpoints with placeholders rather than guess "main".
        for p in (
            "/branches/{default_branch}/protection",
            "/rules/branches/{default_branch}",
            "/rulesets/{ruleset_id}",
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


@dataclass(slots=True)
class _Protection:
    """What one source (classic protection or rulesets) says about a branch."""

    source: str
    reviews: int = 0
    blocks_force_push: bool = False
    blocks_deletion: bool = False
    # True: admins cannot bypass. False: they can. None: could not tell.
    admins_included: bool | None = None


def _classic(r: Response) -> _Protection | None:
    if r.status != 200 or not isinstance(r.body, dict):
        return None
    p = r.body
    reviews = p.get("required_pull_request_reviews") or {}
    return _Protection(
        source="branch protection",
        reviews=int(reviews.get("required_approving_review_count") or 0),
        blocks_force_push=not (p.get("allow_force_pushes") or {}).get("enabled", False),
        blocks_deletion=not (p.get("allow_deletions") or {}).get("enabled", False),
        admins_included=bool((p.get("enforce_admins") or {}).get("enabled", False)),
    )


# Built-in repository role ids GitHub uses in ruleset bypass lists.
_ADMIN_ROLE_IDS = {5}  # admin
_ADMIN_ACTOR_TYPES = {"OrganizationAdmin", "EnterpriseOwner"}


def _ruleset_admins_included(get: Transport, full_name: str, ids: set[int]) -> bool | None:
    verdict: bool | None = True
    for rid in sorted(ids):
        r = get(f"/repos/{full_name}/rulesets/{rid}")
        if r.status != 200 or not isinstance(r.body, dict):
            verdict = None
            continue
        rs = r.body
        if rs.get("enforcement") not in (None, "active"):
            continue
        actors = rs.get("bypass_actors")
        if actors is None:
            # Only returned to callers who can edit the ruleset.
            verdict = None
            continue
        for a in actors:
            if not isinstance(a, dict):
                continue
            if a.get("actor_type") in _ADMIN_ACTOR_TYPES or (
                a.get("actor_type") == "RepositoryRole" and a.get("actor_id") in _ADMIN_ROLE_IDS
            ):
                return False
    return verdict


def _rulesets(get: Transport, full_name: str, branch: str, r: Response) -> _Protection | None:
    if r.status != 200 or not isinstance(r.body, list):
        return None
    rules = [x for x in r.body if isinstance(x, dict)]
    if not rules:
        return _Protection(source="rulesets", admins_included=None)
    prot = _Protection(source="rulesets")
    ids: set[int] = set()
    for rule in rules:
        kind = rule.get("type")
        if isinstance(rule.get("ruleset_id"), int):
            ids.add(rule["ruleset_id"])
        if kind == "pull_request":
            params = rule.get("parameters") or {}
            prot.reviews = max(
                prot.reviews, int(params.get("required_approving_review_count") or 0)
            )
        elif kind == "non_fast_forward":
            prot.blocks_force_push = True
        elif kind == "deletion":
            prot.blocks_deletion = True
    prot.admins_included = _ruleset_admins_included(get, full_name, ids)
    return prot


def _protection(get: Transport, full_name: str, branch: str, loc: str) -> list[Finding]:
    bloc = f"{loc}@{branch}"
    classic_r = get(f"/repos/{full_name}/branches/{branch}/protection")
    rules_r = get(f"/repos/{full_name}/rules/branches/{branch}")
    classic = _classic(classic_r)
    rulesets = _rulesets(get, full_name, branch, rules_r)
    has_rules = rulesets is not None and (
        rulesets.reviews or rulesets.blocks_force_push or rulesets.blocks_deletion
    )
    sources = [p for p in (classic, rulesets if has_rules else None) if p is not None]
    # Could we see enough to say "unprotected"? Classic 404 is "no rule"; the
    # rules endpoint answers 200 with an empty list when nothing applies.
    classic_known = classic is not None or classic_r.status == 404
    rules_known = rulesets is not None
    controls = ("GH-10", "GH-11", "GH-12", "GH-13")

    if not sources:
        if classic_known and rules_known:
            return [
                Finding(
                    "GH-10",
                    Status.FAIL,
                    "no branch protection rule or ruleset on default branch",
                    bloc,
                )
            ] + [Finding(c, Status.FAIL, "branch not protected", bloc) for c in controls[1:]]
        denied = _denied(classic_r) or _denied(rules_r)
        msg = (
            "token cannot read branch protection or rulesets"
            if denied
            else f"protection returned {classic_r.status}, rules returned {rules_r.status}"
        )
        return [Finding(c, Status.WARN, msg, bloc) for c in controls]

    via = " and ".join(p.source for p in sources)
    partial = "" if classic_known and rules_known else " (one source was not readable)"
    out = [Finding("GH-10", Status.PASS, f"default branch protected by {via}{partial}", bloc)]

    reviews = max(p.reviews for p in sources)
    out.append(
        Finding(
            "GH-11",
            Status.PASS if reviews >= 1 else Status.FAIL,
            f"{reviews} approving review(s) required",
            bloc,
        )
    )
    force_ok = any(p.blocks_force_push for p in sources)
    delete_ok = any(p.blocks_deletion for p in sources)
    if force_ok and delete_ok:
        out.append(Finding("GH-12", Status.PASS, "force pushes and deletions blocked", bloc))
    else:
        what = " and ".join(
            w
            for w, blocked in (("force pushes", force_ok), ("deletions", delete_ok))
            if not blocked
        )
        out.append(Finding("GH-12", Status.FAIL, f"{what} allowed", bloc))

    admin = [p.admins_included for p in sources]
    if any(a is True for a in admin):
        out.append(Finding("GH-13", Status.PASS, "admins included", bloc))
    elif any(a is None for a in admin):
        out.append(
            Finding("GH-13", Status.WARN, "ruleset bypass list not visible to this token", bloc)
        )
    else:
        out.append(Finding("GH-13", Status.FAIL, "admins can bypass", bloc))
    return out


def _security_analysis(repo: dict[str, Any], loc: str, private: bool) -> list[Finding]:
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
