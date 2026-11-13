from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    return tmp_path


def git_add(repo: Path, *paths: str) -> None:
    subprocess.run(["git", "-C", str(repo), "add", "-f", *paths], check=True)


# Test secrets are assembled at runtime so that no scanner (ours, gitleaks,
# GitHub push protection) ever sees a credential-shaped literal in this repo.
def fake_aws_key() -> str:
    return "AKIA" + "Q" * 4 + "7" * 4 + "EXMPLTST"


def fake_github_token() -> str:
    return "ghp" + "_" + "a1B2c3D4e5" * 3 + "f6G7h8"


def fake_private_key_header() -> str:
    return "-----BEGIN " + "RSA PRIVATE" + " KEY-----"
