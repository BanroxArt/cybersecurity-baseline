import json

from baseline_check.controls import CONTROLS, Severity
from baseline_check.findings import Finding, FingerprintKey, Status, redact
from baseline_check.report import roll_up, score, to_json, to_markdown, worst_failure


def test_roll_up_worst_status_wins_and_unrun_is_skip():
    results = roll_up(
        [
            Finding("GH-10", Status.PASS, "ok", "repo:a"),
            Finding("GH-10", Status.FAIL, "no", "repo:b"),
            Finding("CT-01", Status.WARN, "?"),
        ]
    )
    by_id = {r.control.id: r.status for r in results}
    assert by_id["GH-10"] == Status.FAIL
    assert by_id["CT-01"] == Status.WARN
    assert by_id["IAC-01"] == Status.SKIP
    assert len(results) == len(CONTROLS)
    assert results[0].status == Status.FAIL


def test_unknown_control_ids_are_dropped():
    assert all(r.control.id != "NOPE" for r in roll_up([Finding("NOPE", Status.FAIL, "x")]))


def test_score_weights_by_severity_and_ignores_skips():
    results = roll_up(
        [
            Finding("SEC-01", Status.PASS, ""),  # critical 10
            Finding("CT-02", Status.FAIL, ""),  # low 1
            Finding("CT-01", Status.WARN, ""),  # medium 3 -> 1.5
        ]
    )
    assert score(results) == round(100 * 11.5 / 14, 1)
    assert score(roll_up([])) is None


def test_worst_failure():
    assert worst_failure(roll_up([Finding("CT-02", Status.FAIL, "")])) == Severity.LOW
    assert worst_failure(roll_up([Finding("SEC-01", Status.PASS, "")])) is None


def test_json_report_shape():
    doc = json.loads(to_json(roll_up([Finding("GH-01", Status.FAIL, "2FA off", "org:x")]), "x"))
    gh01 = next(c for c in doc["controls"] if c["id"] == "GH-01")
    assert gh01["status"] == "fail"
    assert gh01["fix"]
    assert gh01["findings"] == [
        {"control": "GH-01", "status": "fail", "message": "2FA off", "location": "org:x"}
    ]
    assert doc["summary"]["fail"] == 1


def test_markdown_escapes_and_lists_fixes():
    md = to_markdown(
        roll_up([Finding("CT-03", Status.FAIL, "pipe | to sh", "Dockerfile:3")]), "svc"
    )
    assert md.startswith("# Baseline check: svc")
    assert "not a penetration test" in md
    assert "### CT-03" in md
    assert "`Dockerfile:3`" in md


def test_redact_keeps_no_characters():
    out = redact("abcdefghijklmnop", FingerprintKey.random())
    assert "abcd" not in out and "len=16" in out


def test_warns_are_called_out_next_to_the_score():
    results = roll_up([Finding("GH-01", Status.WARN, "not visible")])
    md = to_markdown(results, "x")
    assert "could not be verified" in md
    assert json.loads(to_json(results, "x"))["unverified"] == 1
