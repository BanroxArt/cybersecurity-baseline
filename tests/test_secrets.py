import os

import pytest
from conftest import fake_aws_key, fake_github_token, fake_private_key_header, git_add

from baseline_check.checks.secrets import entropy, scan_env_files, scan_secrets, scan_text
from baseline_check.findings import FingerprintKey, Status, fingerprint, redact


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


KEY = FingerprintKey(b"k" * 32, configured=True)


def test_ignore_file_suppresses_by_keyed_fingerprint(tmp_path):
    secret = fake_aws_key()
    (tmp_path / "a.txt").write_text(secret)
    (tmp_path / ".baseline-ignore").write_text(f"# rotated test key\n{fingerprint(secret, KEY)}\n")
    assert statuses(scan_secrets(tmp_path, KEY), "SEC-01") == [Status.PASS]


def test_ignore_file_without_configured_key_warns(tmp_path):
    (tmp_path / "a.txt").write_text("nothing")
    (tmp_path / ".baseline-ignore").write_text("h1:0123456789abcdef\n")
    assert statuses(scan_secrets(tmp_path), "SEC-01") == [Status.WARN, Status.PASS]


def test_fingerprint_is_keyed_not_a_plain_hash():
    # Regression: a bare SHA-256 prefix let anyone holding a report confirm a
    # guessed secret offline.
    import hashlib

    secret = fake_aws_key()
    plain = hashlib.sha256(secret.encode()).hexdigest()
    a, b = FingerprintKey.random(), FingerprintKey.random()
    assert fingerprint(secret, a) != fingerprint(secret, b)
    assert plain[:12] not in fingerprint(secret, a)
    assert fingerprint(secret, KEY) == fingerprint(secret, KEY)
    assert secret not in redact(secret, KEY)


def test_fingerprint_key_from_env():
    assert not FingerprintKey.from_env({}).configured
    assert FingerprintKey.from_env({"BASELINE_FINGERPRINT_KEY": "x" * 16}).configured
    with pytest.raises(ValueError):
        FingerprintKey.from_env({"BASELINE_FINGERPRINT_KEY": "short"})
    assert "x" * 16 not in repr(FingerprintKey.from_env({"BASELINE_FINGERPRINT_KEY": "x" * 16}))


def test_value_containing_test_is_still_reported():
    # Regression: any value with "test" anywhere in it was treated as a placeholder.
    value = "q8Zk3vXtest0rJ2mTw7pLs9d"
    assert [r for _, r, _ in scan_text('api_key = "' + value + '"')] == ["generic-assignment"]
    assert list(scan_text('api_key = "' + "test-key-q8Zk3vX0rJ2m" + '"')) == []


def test_skipped_files_are_reported_not_silent(tmp_path):
    (tmp_path / "big.txt").write_bytes(b"a" * 1_100_000)
    if hasattr(os, "symlink"):
        (tmp_path / "real.txt").write_text("ok")
        os.symlink(tmp_path / "real.txt", tmp_path / "link.txt")
    findings = [f for f in scan_secrets(tmp_path) if f.control == "SEC-01"]
    warns = [f.message for f in findings if f.status == Status.WARN]
    assert any("big.txt" in m for m in warns)
    assert any("link.txt" in m for m in warns)


def test_walk_prunes_vendored_dirs(tmp_path, monkeypatch):
    from baseline_check.checks import secrets

    deep = tmp_path / "node_modules" / "a" / "b"
    deep.mkdir(parents=True)
    (deep / "x.js").write_text("x")
    (tmp_path / "keep.txt").write_text("x")
    assert [p.name for p in secrets.iter_files(tmp_path)] == ["keep.txt"]


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


def test_gitignore_negation_uncovers(git_repo):
    (git_repo / ".gitignore").write_text(".env*\n!.env\n*.pem\n*.key  \r\n")
    f = next(x for x in scan_env_files(git_repo) if x.control == "SEC-03")
    assert f.status == Status.FAIL and ".env" in f.message and "*.key" not in f.message
    (git_repo / ".gitignore").write_text("config/.env\n*.pem\n*.key\n")
    f = next(x for x in scan_env_files(git_repo) if x.control == "SEC-03")
    assert f.status == Status.FAIL


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
