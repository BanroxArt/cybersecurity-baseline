import urllib.request

import pytest

from baseline_check.checks.github import (
    DryRunTransport,
    FixtureTransport,
    GitHubError,
    Response,
    SameOriginRedirectHandler,
    UrllibTransport,
    check_org,
    check_repo,
    transport_from_env,
    validate_api_url,
)
from baseline_check.findings import Status


def by_control(findings):
    out = {}
    for f in findings:
        out.setdefault(f.control, []).append(f.status)
    return out


def test_weak_org(fixtures):
    got = by_control(check_org(FixtureTransport(fixtures / "github"), "example-org"))
    assert got == {"GH-01": [Status.FAIL], "GH-02": [Status.FAIL], "GH-03": [Status.FAIL]}


def test_good_org(fixtures):
    got = by_control(check_org(FixtureTransport(fixtures / "github"), "good-org"))
    assert set(got) == {"GH-01", "GH-02", "GH-03"}
    assert all(v == [Status.PASS] for v in got.values())


def test_non_owner_token_gets_warn_not_pass(fixtures):
    got = by_control(check_org(FixtureTransport(fixtures / "github"), "limited-org"))
    assert all(v == [Status.WARN] for v in got.values())


def test_missing_org_is_warn(fixtures):
    got = by_control(check_org(FixtureTransport(fixtures / "github"), "nope"))
    assert all(v == [Status.WARN] for v in got.values())


def test_unprotected_repo(fixtures):
    got = by_control(check_repo(FixtureTransport(fixtures / "github"), "example-org/api"))
    for cid in ("GH-10", "GH-11", "GH-12", "GH-13", "GH-14", "GH-15", "GH-16"):
        assert got[cid] == [Status.FAIL], cid


def test_well_configured_repo_uses_its_default_branch(fixtures):
    t = FixtureTransport(fixtures / "github")
    got = by_control(check_repo(t, "example-org/web"))
    assert all(v == [Status.PASS] for v in got.values()), got
    assert "/repos/example-org/web/branches/trunk/protection" in t.requests


def test_partial_protection(fixtures):
    findings = check_repo(FixtureTransport(fixtures / "github"), "example-org/partial")
    got = by_control(findings)
    assert got["GH-10"] == [Status.PASS]
    assert got["GH-11"] == [Status.FAIL]
    assert got["GH-12"] == [Status.FAIL]
    assert got["GH-13"] == [Status.FAIL]
    assert got["GH-14"] == [Status.WARN]
    assert got["GH-15"] == [Status.PASS]
    assert got["GH-16"] == [Status.WARN]
    msg = next(f.message for f in findings if f.control == "GH-12")
    assert msg == "force pushes allowed"


def test_denied_repo(fixtures):
    got = by_control(check_repo(FixtureTransport(fixtures / "github"), "example-org/denied"))
    assert got == {"GH-10": [Status.WARN]}


def test_dry_run_lists_requests_and_makes_no_findings():
    t = DryRunTransport()
    assert check_org(t, "acme") == []
    assert check_repo(t, "acme/app") == []
    # Regression: this used to list /branches/main/protection whatever the
    # repo's default branch was.
    assert t.requests == [
        "/orgs/acme",
        "/repos/acme/app",
        "/repos/acme/app/branches/{default_branch}/protection",
        "/repos/acme/app/rules/branches/{default_branch}",
        "/repos/acme/app/rulesets/{ruleset_id}",
        "/repos/acme/app/vulnerability-alerts",
        "/repos/acme/app/actions/permissions/workflow",
    ]


def test_transport_requires_token_and_hides_it():
    try:
        UrllibTransport("")
    except GitHubError:
        pass
    else:
        raise AssertionError("empty token accepted")
    t = UrllibTransport("not-a-real-token-value")
    assert "not-a-real" not in repr(t)


def test_ruleset_only_repo_passes_branch_controls(fixtures):
    # Regression: a branch protected only by a ruleset used to FAIL GH-10..13
    # because classic protection answers 404.
    t = FixtureTransport(fixtures / "github")
    findings = check_repo(t, "example-org/ruled")
    got = by_control(findings)
    for cid in ("GH-10", "GH-11", "GH-12", "GH-13"):
        assert got[cid] == [Status.PASS], cid
    assert "rulesets" in next(f.message for f in findings if f.control == "GH-10")
    assert "/repos/example-org/ruled/rulesets/42" in t.requests


def test_ruleset_admin_bypass_fails_gh13_and_missing_deletion_rule_fails_gh12(fixtures):
    got = by_control(check_repo(FixtureTransport(fixtures / "github"), "example-org/bypass"))
    assert got["GH-10"] == [Status.PASS]
    assert got["GH-11"] == [Status.PASS]
    assert got["GH-12"] == [Status.FAIL]
    assert got["GH-13"] == [Status.FAIL]


def test_ruleset_bypass_list_not_visible_is_warn(fixtures):
    got = by_control(check_repo(FixtureTransport(fixtures / "github"), "example-org/hidden"))
    assert got["GH-12"] == [Status.PASS]
    assert got["GH-13"] == [Status.WARN]


def test_unreadable_rulesets_with_no_classic_rule_is_warn_not_fail():
    def get(path):
        if path == "/repos/o/r":
            return Response(200, {"default_branch": "main"})
        if path.endswith("/protection"):
            return Response(404, {"message": "Branch not protected"})
        if "/rules/branches/" in path:
            return Response(403, {"message": "Resource not accessible"})
        return Response(404, None)

    got = by_control(check_repo(get, "o/r"))
    for cid in ("GH-10", "GH-11", "GH-12", "GH-13"):
        assert got[cid] == [Status.WARN], cid


@pytest.mark.parametrize(
    "url",
    [
        "http://api.github.com",
        "ftp://api.github.com",
        "https://",
        "https://user:pw@ghe.example.com/api/v3",
        "https://ghe.example.com/api/v3?x=1",
        "https://ghe.example.com/api/v3#frag",
        "api.github.com",
    ],
)
def test_api_url_must_be_plain_https(url):
    with pytest.raises(GitHubError):
        validate_api_url(url)
    with pytest.raises(GitHubError):
        UrllibTransport("tok", url)


def test_api_url_accepts_ghes_and_strips_slash():
    assert validate_api_url("https://ghe.example.com/api/v3/") == "https://ghe.example.com/api/v3"


def test_env_api_url_is_validated(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("GITHUB_API_URL", "http://evil.example.com")
    with pytest.raises(GitHubError):
        transport_from_env()
    monkeypatch.setenv("GITHUB_API_URL", "")
    assert transport_from_env().base == "https://api.github.com"


def _redirect(src, dst):
    req = urllib.request.Request(src, headers={"Authorization": "Bearer s3kr1t-value"})
    return SameOriginRedirectHandler().redirect_request(req, None, 302, "Found", {}, dst)


@pytest.mark.parametrize(
    "dst",
    [
        "https://evil.example.com/repos/o/r",
        "http://api.github.com/repos/o/r",
        "https://api.github.com:8443/repos/o/r",
    ],
)
def test_cross_origin_redirect_is_refused(dst):
    with pytest.raises(GitHubError) as exc:
        _redirect("https://api.github.com/repos/o/r", dst)
    assert "s3kr1t" not in str(exc.value)


def test_same_origin_redirect_keeps_working():
    new = _redirect("https://api.github.com/repos/o/old", "https://api.github.com/repos/o/new")
    assert new is not None and new.full_url == "https://api.github.com/repos/o/new"
