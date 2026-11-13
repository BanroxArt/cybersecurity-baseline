import textwrap

from baseline_check.checks.workflows import check_workflow, scan_workflows
from baseline_check.findings import Status

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
    assert got == {
        "CI-01": [Status.PASS],
        "CI-02": [Status.PASS],
        "CI-03": [Status.PASS],
        "CI-04": [Status.PASS],
    }


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


def test_no_workflows_skips_ci03_too(tmp_path):
    # Regression: CI-03 was missing from the SKIP list.
    got = {f.control: f.status for f in scan_workflows(tmp_path)}
    assert got == {c: Status.SKIP for c in ("CI-01", "CI-02", "CI-03", "CI-04")}


def test_ci03_is_pass_not_skip_when_no_privileged_trigger(tmp_path):
    got = run(tmp_path, "on: push\npermissions: {}\njobs: {}\n")
    assert got["CI-03"] == [Status.PASS]


def test_fork_checkout_by_repository_and_gh_pr_checkout(tmp_path):
    got = run(
        tmp_path,
        f"""
        on: pull_request_target
        permissions: {{}}
        jobs:
          t:
            steps:
              - uses: actions/checkout@{SHA}
                with:
                  repository: ${{{{ github.event.pull_request.head.repo.full_name }}}}
              - run: gh pr checkout ${{{{ github.event.number }}}}
        """,
    )
    assert got["CI-03"] == [Status.FAIL, Status.FAIL]


def test_workflow_run_artifact_download_warns(tmp_path):
    got = run(
        tmp_path,
        f"""
        on:
          workflow_run:
            workflows: [ci]
        permissions: {{}}
        jobs:
          t:
            steps:
              - uses: actions/download-artifact@{SHA}
        """,
    )
    assert got["CI-03"] == [Status.WARN]


def test_job_level_write_all_fails_even_with_top_level_block(tmp_path):
    got = run(
        tmp_path,
        """
        on: push
        permissions:
          contents: read
        jobs:
          release:
            permissions: write-all
            steps: []
        """,
    )
    assert got["CI-02"] == [Status.PASS, Status.FAIL]


def test_docker_actions_and_reusable_workflows_are_checked_for_pins(tmp_path):
    digest = "docker://alpine@sha256:" + "a" * 64
    got = run(
        tmp_path,
        f"""
        on: push
        permissions: {{}}
        jobs:
          call:
            uses: some-org/shared/.github/workflows/build.yml@main
          t:
            steps:
              - uses: docker://alpine:3.20
              - uses: {digest}
        """,
    )
    assert got["CI-01"] == [Status.FAIL, Status.FAIL]


def test_injection_variants(tmp_path):
    got = run(
        tmp_path,
        """
        on: [pull_request_target, release, discussion]
        permissions: {}
        jobs:
          t:
            steps:
              - run: echo "${{ github.event.pull_request.head.repo.description }}"
              - run: echo "${{ github.event.release.body }}"
              - run: echo "${{ format('{0}', github.event.discussion.title) }}"
              - run: echo "${{ github.event.pull_request.number }}"
        """,
    )
    assert got["CI-04"] == [Status.FAIL, Status.FAIL, Status.FAIL]


def test_script_key_only_counts_for_github_script(tmp_path):
    got = run(
        tmp_path,
        f"""
        on: issues
        permissions: {{}}
        jobs:
          t:
            steps:
              - uses: some/action@{SHA}
                with:
                  script: "${{{{ github.event.issue.title }}}}"
        """,
    )
    assert got["CI-04"] == [Status.PASS]
