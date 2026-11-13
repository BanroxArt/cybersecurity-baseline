import json

from baseline_check.cli import main


def test_sample_repo_offline(fixtures, capsys):
    code = main(
        [
            "scan",
            str(fixtures / "sample-repo"),
            "--github-org",
            "example-org",
            "--github-repo",
            "example-org/api",
            "--fixtures",
            str(fixtures / "github"),
            "--format",
            "json",
        ]
    )
    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    status = {c["id"]: c["status"] for c in doc["controls"]}
    for cid in (
        "CI-03",
        "CI-04",
        "CT-01",
        "CT-02",
        "CT-03",
        "CT-04",
        "IAC-01",
        "IAC-02",
        "IAC-03",
        "GH-01",
        "GH-10",
        "GH-14",
        "SEC-03",
    ):
        assert status[cid] == "fail", cid
    assert status["SEC-01"] == "pass"
    assert doc["score"] < 30


def test_fail_on_threshold(tmp_path, capsys):
    (tmp_path / "Dockerfile").write_text("FROM a:latest\nUSER 1\n")  # one low failure
    assert main(["scan", str(tmp_path)]) == 0
    assert main(["scan", str(tmp_path), "--fail-on", "low"]) == 1
    capsys.readouterr()


def test_dry_run_prints_requests_only(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert (
        main(
            [
                "scan",
                str(tmp_path),
                "--github-org",
                "acme",
                "--github-repo",
                "acme/app",
                "--dry-run",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "GET /orgs/acme" in out and "GET /repos/acme/app/vulnerability-alerts" in out


def test_missing_token_is_a_clean_error(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert main(["scan", str(tmp_path), "--github-org", "acme"]) == 2
    assert "GITHUB_TOKEN" in capsys.readouterr().err


def test_output_file_and_controls_list(tmp_path, capsys):
    out = tmp_path / "r.md"
    main(["scan", str(tmp_path), "-o", str(out)])
    assert out.read_text().startswith("# Baseline check")
    assert main(["controls"]) == 0
    assert "SEC-01" in capsys.readouterr().out


def test_not_a_directory(tmp_path):
    assert main(["scan", str(tmp_path / "missing")]) == 2
