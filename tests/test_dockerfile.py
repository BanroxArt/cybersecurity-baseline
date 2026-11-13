from baseline_check.checks.dockerfile import check_dockerfile, instructions, scan_dockerfiles
from baseline_check.findings import Status


def run(tmp_path, text):
    p = tmp_path / "Dockerfile"
    p.write_text(text)
    out = {}
    for f in check_dockerfile(p, "Dockerfile"):
        out.setdefault(f.control, []).append(f.status)
    return out


def test_instructions_join_continuations_and_skip_comments():
    text = "# c\nFROM a:1\nRUN apt-get update && \\\n    apt-get install -y x\n\nUSER app\n"
    assert instructions(text) == [
        (2, "FROM", "a:1"),
        (3, "RUN", "apt-get update &&  apt-get install -y x"),
        (6, "USER", "app"),
    ]


def test_good_multistage(tmp_path):
    got = run(
        tmp_path,
        "FROM python:3.12-slim AS build\nRUN pip wheel .\n"
        "FROM python:3.12-slim@sha256:" + "0" * 64 + "\nCOPY --from=build /w /w\nUSER 10001\n",
    )
    assert all(v == [Status.PASS] for v in got.values()), got


def test_user_resets_per_stage(tmp_path):
    got = run(tmp_path, "FROM a:1 AS b\nUSER app\nFROM a:1\nCMD x\n")
    assert got["CT-01"] == [Status.FAIL]


def test_root_user_explicit(tmp_path):
    assert run(tmp_path, "FROM a:1\nUSER root\n")["CT-01"] == [Status.FAIL]


def test_unpinned_images(tmp_path):
    got = run(
        tmp_path, "FROM ubuntu\nFROM node:latest\nFROM registry.example.com:5000/app\nUSER 1\n"
    )
    assert got["CT-02"] == [Status.FAIL] * 3


def test_remote_fetches(tmp_path):
    got = run(
        tmp_path,
        "FROM a:1\nADD https://example.com/x.tgz /x\nRUN wget -qO- https://example.com/i | bash\nUSER 1\n",
    )
    assert got["CT-03"] == [Status.FAIL, Status.FAIL]


def test_secret_env_and_arg(tmp_path):
    got = run(tmp_path, "FROM a:1\nARG NPM_TOKEN\nENV DB_PASSWORD=x\nENV LOG_LEVEL=info\nUSER 1\n")
    assert got["CT-04"] == [Status.FAIL, Status.FAIL]


def test_scan_finds_named_dockerfiles(tmp_path):
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "api.Dockerfile").write_text("FROM a:1\nUSER 1\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "Dockerfile").write_text("FROM a\n")
    findings = scan_dockerfiles(tmp_path)
    assert {f.location for f in findings} == {"svc/api.Dockerfile"}


def test_stage_from_build_arg_resets_user(tmp_path):
    # Regression: FROM ${BASE} skipped the USER reset, so a root final stage
    # inherited the previous stage's USER and passed CT-01.
    got = run(
        tmp_path,
        "ARG BASE=python:3.12-slim\nFROM python:3.12-slim AS build\nUSER 10001\nFROM ${BASE}\n",
    )
    assert got["CT-01"] == [Status.FAIL]
    assert got["CT-02"] == [Status.WARN]


def test_stage_built_on_earlier_stage_inherits_its_user(tmp_path):
    got = run(tmp_path, "FROM alpine:3.20 AS base\nUSER 10001\nFROM base\nRUN true\n")
    assert got["CT-01"] == [Status.PASS]


def test_env_with_several_pairs_checks_every_name(tmp_path):
    got = run(tmp_path, 'FROM alpine:3.20\nENV A=1 DB_PASSWORD="x y"\nUSER app\n')
    assert got["CT-04"] == [Status.FAIL]
    got = run(tmp_path, "FROM alpine:3.20\nENV API_TOKEN abc\nUSER app\n")
    assert got["CT-04"] == [Status.FAIL]
