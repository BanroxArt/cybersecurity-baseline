import json
import string

from hypothesis import given
from hypothesis import strategies as st

from baseline_check.cli import main
from baseline_check.controls import CONTROLS
from baseline_check.findings import Finding, FingerprintKey, Status, redact
from baseline_check.report import roll_up
from baseline_check.sarif import (
    FINGERPRINT_NAME,
    SECURITY_SEVERITY,
    parse_location,
    stable_fingerprint,
    to_sarif,
)


def sarif(findings):
    return json.loads(to_sarif(roll_up(findings), "t"))


def results(findings):
    return sarif(findings)["runs"][0]["results"]


def test_envelope_and_rules():
    doc = sarif([])
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == list(CONTROLS)
    for rule in rules:
        assert rule["shortDescription"]["text"]
        assert rule["help"]["text"]
        assert rule["defaultConfiguration"]["level"] in {"error", "warning", "note"}
        assert float(rule["properties"]["security-severity"]) <= 10
    assert run["results"] == []


def test_rule_index_points_at_the_rule():
    doc = sarif(
        [
            Finding("IAC-02", Status.FAIL, "ssh open", "infra/main.tf:5 aws_security_group.web"),
            Finding("SEC-01", Status.FAIL, "key", "app/settings.py:3"),
        ]
    )
    run = doc["runs"][0]
    for r in run["results"]:
        assert run["tool"]["driver"]["rules"][r["ruleIndex"]]["id"] == r["ruleId"]


def test_pass_and_skip_are_not_emitted():
    out = results(
        [
            Finding("GH-10", Status.PASS, "ok", "repo:a/b"),
            Finding("IAC-01", Status.SKIP, "no Terraform files"),
        ]
    )
    assert out == []


def test_fail_level_follows_severity_and_warn_is_review_with_level_none():
    out = {
        r["ruleId"]: r
        for r in results(
            [
                Finding("SEC-01", Status.FAIL, "x", "a.py:1"),  # critical
                Finding("SEC-03", Status.FAIL, "x", ".gitignore"),  # low
                Finding("CT-01", Status.WARN, "x", "Dockerfile"),
            ]
        )
    }
    assert (out["SEC-01"]["kind"], out["SEC-01"]["level"]) == ("fail", "error")
    assert (out["SEC-03"]["kind"], out["SEC-03"]["level"]) == ("fail", "note")
    # SARIF 3.27.9: any kind other than fail must have level none.
    assert (out["CT-01"]["kind"], out["CT-01"]["level"]) == ("review", "none")


def test_file_line_location():
    (r,) = results([Finding("CT-03", Status.FAIL, "ADD url", "docker/api/Dockerfile:12")])
    phys = r["locations"][0]["physicalLocation"]
    assert phys["artifactLocation"] == {"uri": "docker/api/Dockerfile", "uriBaseId": "%SRCROOT%"}
    assert phys["region"] == {"startLine": 12}


def test_workflow_yaml_path_is_file_plus_logical():
    (r,) = results([Finding("CI-04", Status.FAIL, "x", ".github/workflows/pr.yml:jobs.b.steps[2]")])
    loc = r["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == ".github/workflows/pr.yml"
    assert "region" not in loc["physicalLocation"]
    assert loc["logicalLocations"] == [
        {"fullyQualifiedName": "jobs.b.steps[2]", "kind": "property"}
    ]


def test_settings_findings_are_logical_only():
    (r,) = results([Finding("GH-01", Status.FAIL, "2FA off", "org:example-org")])
    assert r["locations"] == [
        {"logicalLocations": [{"fullyQualifiedName": "org:example-org", "kind": "resource"}]}
    ]


def test_findings_without_location_have_no_locations_key():
    (r,) = results([Finding("CT-01", Status.FAIL, "root")])
    assert "locations" not in r


def test_uris_are_relative_and_encoded():
    (r,) = results([Finding("SEC-02", Status.FAIL, "x", "/conf/my keys.pem")])
    uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "conf/my%20keys.pem"


def test_fingerprint_is_stable_across_random_keys():
    # Without BASELINE_FINGERPRINT_KEY each run draws a new key, so the
    # redacted message differs. The SARIF fingerprint must not.
    secret = "not-a-real-credential-value"
    a = Finding("SEC-01", Status.FAIL, f"aws {redact(secret, FingerprintKey.random())}", "x:1")
    b = Finding("SEC-01", Status.FAIL, f"aws {redact(secret, FingerprintKey.random())}", "x:1")
    assert a.message != b.message
    assert stable_fingerprint(a) == stable_fingerprint(b)
    (ra,) = results([a])
    assert ra["partialFingerprints"][FINGERPRINT_NAME] == stable_fingerprint(a)


def test_fingerprint_separates_locations():
    a = Finding("SEC-01", Status.FAIL, "aws", "x:1")
    b = Finding("SEC-01", Status.FAIL, "aws", "x:2")
    assert stable_fingerprint(a) != stable_fingerprint(b)


def test_security_severity_buckets_match_github():
    assert float(SECURITY_SEVERITY[max(SECURITY_SEVERITY)]) >= 9.0


_path_chars = string.ascii_letters + string.digits + "._-/"


@given(
    st.text(alphabet=_path_chars, min_size=1, max_size=40).filter(lambda s: s.strip("/")),
    st.integers(min_value=1, max_value=10**6),
)
def test_parse_location_round_trips_path_and_line(path, line):
    parsed = parse_location(f"{path}:{line}")
    assert (parsed.path, parsed.line) == (path, line)


@given(st.text(max_size=80))
def test_parse_location_never_raises(text):
    parse_location(text)


def test_cli_writes_sarif_for_the_demo(tmp_path, capsys):
    out = tmp_path / "r.sarif"
    code = main(
        [
            "scan",
            "tests/fixtures/sample-repo",
            "--github-org",
            "example-org",
            "--github-repo",
            "example-org/api",
            "--fixtures",
            "tests/fixtures/github",
            "--format",
            "sarif",
            "-o",
            str(out),
        ]
    )
    assert code == 1
    doc = json.loads(out.read_text())
    ids = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert {"GH-01", "CI-03", "IAC-02"} <= ids
    text = out.read_text()
    assert str(tmp_path) not in text
    assert "file://" not in text
