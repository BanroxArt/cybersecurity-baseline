from baseline_check.checks.github import (
    DryRunTransport,
    FixtureTransport,
    GitHubError,
    UrllibTransport,
    check_org,
    check_repo,
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
    assert t.requests == [
        "/orgs/acme",
        "/repos/acme/app",
        "/repos/acme/app/branches/main/protection",
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
