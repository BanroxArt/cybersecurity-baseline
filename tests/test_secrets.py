from conftest import fake_aws_key, fake_github_token, fake_private_key_header, git_add

from baseline_check.checks.secrets import entropy, scan_env_files, scan_secrets, scan_text
from baseline_check.findings import Status, fingerprint


def statuses(findings, control):
    return [f.status for f in findings if f.control == control]


def test_scan_text_finds_known_shapes():
    text = "\n".join(
        [
            f"aws = {fake_aws_key()}",
            f"token: {fake_github_token()}",
            fake_private_key_header(),
            "nothing here",
        ]
    )
    hits = [(line, rule) for line, rule, _ in scan_text(text)]
    assert hits == [(1, "aws-access-key-id"), (2, "github-token"), (3, "private-key")]


def test_generic_assignment_needs_entropy_and_skips_placeholders():
    real = 'api_key = "' + "q8Zk3vX0rJ2mTw7pLs9d" + '"'
    low = 'password = "' + "aaaaaaaaaaaaaaaaaaaa" + '"'
    placeholder = 'secret = "' + "your-secret-goes-here-123" + '"'
    assert [r for _, r, _ in scan_text(real)] == ["generic-assignment"]
    assert list(scan_text(low)) == []
    assert list(scan_text(placeholder)) == []


def test_findings_never_contain_the_secret(tmp_path):
    key = fake_aws_key()
    (tmp_path / "config.py").write_text(f"KEY = '{key}'\n")
    findings = scan_secrets(tmp_path)
    assert statuses(findings, "SEC-01") == [Status.FAIL]
    blob = repr(findings)
    assert key not in blob
    assert key[4:] not in blob
    assert findings[0].location == "config.py:1"


def test_ignore_file_suppresses_by_fingerprint(tmp_path):
    key = fake_aws_key()
    (tmp_path / "a.txt").write_text(key)
    (tmp_path / ".baseline-ignore").write_text(f"# rotated test key\n{fingerprint(key)}\n")
    assert statuses(scan_secrets(tmp_path), "SEC-01") == [Status.PASS]


def test_binary_and_vendored_dirs_skipped(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text(fake_aws_key())
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01" + fake_aws_key().encode())
    assert statuses(scan_secrets(tmp_path), "SEC-01") == [Status.PASS]


def test_tracked_env_file_fails(git_repo):
    (git_repo / ".env").write_text("X=1\n")
    (git_repo / ".env.example").write_text("X=\n")
    (git_repo / "deploy.pem").write_text("x")
    git_add(git_repo, ".env", ".env.example", "deploy.pem")
    findings = scan_env_files(git_repo)
    failed = sorted(f.location for f in findings if f.control == "SEC-02")
    assert failed == [".env", "deploy.pem"]


def test_gitignore_coverage(git_repo):
    (git_repo / ".gitignore").write_text(".env\n*.pem\n")
    f = next(x for x in scan_env_files(git_repo) if x.control == "SEC-03")
    assert f.status == Status.FAIL and "*.key" in f.message
    (git_repo / ".gitignore").write_text(".env\n*.pem\n*.key\n")
    f = next(x for x in scan_env_files(git_repo) if x.control == "SEC-03")
    assert f.status == Status.PASS


def test_not_a_git_repo_is_skip(tmp_path):
    assert statuses(scan_env_files(tmp_path), "SEC-02") == [Status.SKIP]


def test_entropy():
    assert entropy("") == 0
    assert entropy("abab") == 1.0
