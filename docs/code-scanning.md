# SARIF output and GitHub code scanning

`baseline-check scan . --format sarif -o baseline.sarif` writes a SARIF 2.1.0 log. Any SARIF viewer reads it (the VS Code SARIF extension, GitHub code scanning, most CI dashboards).

## What ends up in the file

- One rule per control, in the order `baseline-check controls` prints them. Rule ids are the control ids (`SEC-01`, `GH-10`, ...), so suppressions and dashboards keyed on them survive upgrades.
- One result per `fail` or `warn` finding. `pass` and `skip` are left out; code scanning opens an alert for every result it receives.
- `fail` results have `kind: fail` and a level from severity: critical and high are `error`, medium `warning`, low `note`.
- `warn` results have `kind: review` and `level: none`. The spec requires `none` for every kind other than `fail`. A `warn` means the tool could not tell, so a person should look; it is not a failure.
- Each rule carries `security-severity` (critical 9.5, high 8.0, medium 5.5, low 3.0), which GitHub uses to sort alerts into its critical, high, medium and low buckets.
- File locations are relative to `%SRCROOT%`. The file never contains an absolute path from the machine that ran the scan, and `originalUriBaseIds` is not written for the same reason.
- Secret findings keep the same redaction as the other formats: rule, length and keyed fingerprint, never the value.

## Fingerprints

Code scanning matches a result to an existing alert by fingerprint. `partialFingerprints["baselineCheck/v1"]` is a SHA-256 over the control id, the location and the message with the per-run secret fingerprint (`fp=h1:...`) removed. Without `BASELINE_FINGERPRINT_KEY` that part is random per run, and keeping it in the fingerprint would close and reopen the same alert on every scan.

Moving a finding to another line changes its fingerprint, so the old alert closes and a new one opens. That is the same trade GitHub's own line-hash fingerprint makes.

## Settings findings

GitHub org and repo findings (`GH-*`) have no file to point at. They are written with a logical location only (`org:example-org`, `repo:example-org/api@main`). Code scanning is built around files and may not show them; other SARIF consumers do. The Markdown and JSON reports remain the complete record.

## Uploading from GitHub Actions

The upload step needs `security-events: write`, so give it only to the job that uploads. Pin both actions to a commit, and pin the tool to a commit as well:

```yaml
name: baseline
on:
  push:
    branches: [main]
  schedule:
    - cron: "17 6 * * 1"
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - run: python -m pip install "baseline-check @ git+https://github.com/BanroxArt/cybersecurity-baseline@<commit sha>"
      - run: baseline-check scan . --format sarif -o baseline.sarif --fail-on critical || true
      - uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066 # v4.39.3
        with:
          sarif_file: baseline.sarif
          category: baseline-check
```

`|| true` keeps the upload running when the scan exits 1; let code scanning's branch protection rule do the gating instead, or drop it to fail the job as well. Uploading to code scanning on a private repository needs GitHub Advanced Security or GitHub Code Security on that repository.

The GitHub settings checks are left out of this example on purpose. They need a token with read access to org administration, and that token should not sit in a workflow that runs on every push.
