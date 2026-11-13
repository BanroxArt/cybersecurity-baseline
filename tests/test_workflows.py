import textwrap

from baseline_audit.checks.workflows import check_workflow, scan_workflows
from baseline_audit.findings import Status

SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"


def run(tmp_path, body):
    p = tmp_path / "wf.yml"
    p.write_text(textwrap.dedent(body))
    out = {}
    for f in check_workflow(p, "wf.yml"):
        out.setdefault(f.control, []).append(f.status)
    return out


def test_clean_workflow(tmp_path):
    got = run(
        tmp_path,
        f"""
        on: [push]
        permissions:
          contents: read
        jobs:
          t:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@{SHA}
              - uses: ./local-action
              - run: echo "$TITLE"
                env:
                  TITLE: ${{{{ github.event.pull_request.title }}}}
        """,
    )
    assert got == {"CI-01": [Status.PASS], "CI-02": [Status.PASS], "CI-04": [Status.PASS]}


def test_unpinned_third_party_fails_first_party_warns(tmp_path):
    got = run(
        tmp_path,
        """
        on: push
        permissions: read-all
        jobs:
          t:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: vendor/thing@v1.2.0
        """,
    )
    assert got["CI-01"] == [Status.WARN, Status.FAIL]


def test_missing_permissions_and_write_all(tmp_path):
    got = run(tmp_path, "on: push\njobs:\n  a:\n    runs-on: x\n    steps: []\n")
    assert got["CI-02"] == [Status.FAIL]
    got = run(tmp_path, "on: push\npermissions: write-all\njobs: {}\n")
    assert got["CI-02"] == [Status.FAIL]
    got = run(tmp_path, "on: push\njobs:\n  a:\n    permissions: {}\n    steps: []\n")
    assert got["CI-02"] == [Status.PASS]


def test_pull_request_target_checkout_of_head(tmp_path):
    got = run(
        tmp_path,
        f"""
        on:
          pull_request_target:
        permissions:
          contents: read
        jobs:
          t:
            steps:
              - uses: actions/checkout@{SHA}
                with:
                  ref: ${{{{ github.event.pull_request.head.sha }}}}
        """,
    )
    assert got["CI-03"] == [Status.FAIL]


def test_pull_request_target_without_checkout_passes(tmp_path):
    got = run(
        tmp_path,
        """
        on: pull_request_target
        permissions: {}
        jobs:
          label:
            steps:
              - run: echo labelling
        """,
    )
    assert got["CI-03"] == [Status.PASS]


def test_script_injection(tmp_path):
    got = run(
        tmp_path,
        """
        on: issues
        permissions: {}
        jobs:
          t:
            steps:
              - run: echo "${{ github.event.issue.title }}"
              - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea
                with:
                  script: console.log("${{ github.event.comment.body }}")
              - run: echo "${{ github.sha }}"
        """,
    )
    assert got["CI-04"] == [Status.FAIL, Status.FAIL]


def test_bad_yaml_is_warn(tmp_path):
    assert run(tmp_path, "on: [push\n") == {"CI-01": [Status.WARN]}


def test_no_workflows_dir(tmp_path):
    assert {f.status for f in scan_workflows(tmp_path)} == {Status.SKIP}
