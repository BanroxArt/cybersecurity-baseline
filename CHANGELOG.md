# Changelog

All notable changes to this project are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/) once it reaches 1.0.

## [Unreleased]

### Changed

- Renamed the package and command from `baseline-audit` to `baseline-check` (module `baseline_check`). The tool is a self-check, and "audit" suggested an opinion it does not give. Nothing was published under the old name.
- Secret fingerprints are now keyed: `h1:` plus 16 hex characters of HMAC-SHA256. Set `BASELINE_FINGERPRINT_KEY` for stable fingerprints; existing `.baseline-ignore` entries need regenerating.
- `GITHUB_API_URL` must be a plain `https` URL.
- `--dry-run` lists `{default_branch}` and `{ruleset_id}` placeholders instead of assuming `main`.

### Fixed

- GH-10 to GH-13 no longer fail repos protected only by rulesets. Rules from `/rules/branches/{branch}` are combined with classic protection, and ruleset bypass lists are checked for admin roles (`warn` when not visible). When neither source can be read the controls are `warn`, not `fail`.
- The token could follow a redirect to another host, because urllib forwards `Authorization` on redirects. Cross-origin redirects are now refused.
- The plain SHA-256 fingerprint let anyone holding a report test guessed secrets offline.
- The placeholder filter skipped any value containing "test"; it now matches whole words only.
- CI-03 was missing from the SKIP list when a repo has no workflows, and showed as SKIP rather than PASS for workflows with no privileged trigger.
- CI-03 now catches fork checkouts via `repository:`, `gh pr checkout` and `refs/pull` fetches, and warns on `workflow_run` artifact downloads.
- CI-01 checks reusable workflow calls and requires a digest on `docker://` steps; CI-02 flags job-level `write-all`; CI-04 covers more untrusted fields and only reads `script` on `actions/github-script`.
- Terraform: comments containing quotes or braces no longer break block matching; heredoc bucket policies with `Principal: "*"` are caught; unset public access block settings fail; `aws_vpc_security_group_ingress_rule` with `ip_protocol = "-1"` is caught; computed `storage_encrypted` is `warn` instead of `fail`; `dynamic "ingress"` blocks are `warn`.
- Dockerfiles: a stage built from a build arg no longer inherits the previous stage's `USER`; a stage built on an earlier stage does inherit it; every name on a multi-pair `ENV` line is checked.
- SEC-01 reports files it did not read (over 1 MB, symlinks, unreadable) as `warn` instead of skipping them silently. Vendored directories are pruned during the walk.
- SEC-03 honours `!` negations and ignores patterns scoped to subdirectories.

### Added

- `--format sarif`: SARIF 2.1.0 with one rule per control, `kind`/`level` mapped per the spec, `security-severity` for GitHub's buckets, relative `%SRCROOT%` locations and run-stable `partialFingerprints`. See docs/code-scanning.md.
- Optional `python-hcl2` backend for Terraform (`pip install 'baseline-check[hcl]'`).
- An "unverified" count next to the score in both report formats.
- mypy (strict) in CI, a `py.typed` marker, and a Hypothesis test that the Terraform reader never raises.
- SECURITY.md, CONTRIBUTING.md and this file.

## [0.1.0] - 2026-11-12

First public version: secrets, GitHub org and repo settings, Actions workflows, Dockerfiles and Terraform checks, Markdown and JSON reports with a severity-weighted score, fixture and dry-run transports.
