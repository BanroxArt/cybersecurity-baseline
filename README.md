# cybersecurity-baseline

`baseline-audit` checks a small team's own setup against a short security baseline and writes a scored report. It looks at a local checkout (committed credentials, tracked `.env` files, GitHub Actions workflows, Dockerfiles, Terraform) and, with a read-only token, at GitHub org and repo settings (2FA, branch protection, secret scanning, Dependabot, default token permissions).

It is defensive and read-only. It does not scan anyone else's systems, does not exploit anything, and writes nothing to GitHub. It is also not a penetration test, an audit opinion or a certification of any kind.

The repo also contains `SKILL.md`, an agent skill for running a broader baseline review (people, vendors, incident path) that the tool cannot see.

Author: Art Akopian ([Banrox](https://banrox.com))

## Quick start

Python 3.11+, PyYAML.

```sh
python -m pip install -e '.[dev]'
baseline-audit scan .                                  # local checks only
baseline-audit scan . --format json -o report.json
GITHUB_TOKEN=... baseline-audit scan . --github-org your-org --github-repo your-org/api
baseline-audit scan . --github-org your-org --github-repo your-org/api --dry-run   # list API calls, send none
make demo                                              # offline run against recorded fixtures
```

Exit code is 1 when any failing control is at or above `--fail-on` (default `high`), so it can gate CI. Use `--fail-on critical` while you work through an existing backlog.

## Controls

`baseline-audit controls` prints the list. In short:

| Area | Controls |
| --- | --- |
| Secrets | SEC-01 no credential patterns in the tree, SEC-02 no tracked env or key files, SEC-03 `.gitignore` covers them |
| GitHub org | GH-01 2FA required, GH-02 members cannot create public repos, GH-03 base permission read or none |
| GitHub repo | GH-10 default branch protected, GH-11 approving review required, GH-12 no force push or delete, GH-13 admins included, GH-14 secret scanning and push protection, GH-15 Dependabot alerts, GH-16 read-only default `GITHUB_TOKEN` |
| CI | CI-01 actions pinned to a commit SHA, CI-02 explicit least-privilege permissions, CI-03 no `pull_request_target` checkout of PR code, CI-04 no `${{ github.event.* }}` text interpolated into scripts |
| Containers | CT-01 non-root final stage, CT-02 pinned base images, CT-03 no remote `ADD` or curl-pipe-shell, CT-04 no secrets in `ENV`/`ARG` |
| Terraform | IAC-01 no public buckets, IAC-02 no admin ports open to `0.0.0.0/0`, IAC-03 encryption at rest |

Why these and not a longer list: every item is something a team can check and fix in a day, and each one has been the root cause of real breaches (leaked keys in public repos, CI secrets stolen through `pull_request_target`, open database ports). [docs/controls.md](docs/controls.md) has the reasoning per control and where it comes from.

## Report

Markdown by default, JSON with `--format json`. Each control gets `pass`, `fail`, `warn` (could not tell, a person should look) or `skip` (not checked). The score is passed severity weight over checked weight (low 1, medium 3, high 5, critical 10; warn counts half). It is for tracking your own progress between runs. Skipped controls do not count, so a repo with no Terraform is not penalised or rewarded for it.

Excerpt from `make demo`:

```text
| CI-03 | critical | fail | pull_request_target does not check out untrusted code |
| GH-01 | critical | fail | Organization requires two-factor authentication |
| CI-04 | high     | fail | No untrusted event fields interpolated into run steps |
...
### IAC-02 No admin ports open to the internet

- fail: ssh (22) open to the internet (`infra/main.tf:5 aws_security_group.web`)

Fix: Restrict 22, 3389 and database ports to a VPN or bastion range.
```

## GitHub token

A fine-grained personal access token with read-only **Administration** on the org and on the repos you check is enough. Org fields like `two_factor_requirement_enabled` are only returned to owners; with a lesser token those controls come back as `warn`, not `pass`. The token is read from `GITHUB_TOKEN`, sent only to `api.github.com` (or `GITHUB_API_URL` for GitHub Enterprise Server), and kept out of `repr()` and error messages. See [docs/github-token.md](docs/github-token.md).

## Design decisions

- **Secret findings never contain the secret.** The report shows the rule, file, line, length and a 12 character SHA-256 fingerprint. To accept a known false positive, put the fingerprint in `.baseline-ignore`. The file never has to hold the value.
- **Fixtures instead of mocks.** The HTTP layer is a single callable. Tests and `make demo` use `FixtureTransport`, which maps request paths to recorded JSON files in `tests/fixtures/github`. Adding a case is adding a file.
- **First-party actions warn, third-party actions fail** on CI-01. `actions/checkout@v4` is a moving tag too, but the realistic risk is a compromised third-party action (as with `tj-actions/changed-files` in 2025).
- **Line-level Dockerfile and Terraform parsing.** No HCL or BuildKit dependency. Literal values are checked; anything computed through variables or modules is not. Pair it with tfsec, checkov or trivy for IaC you depend on.

## Limitations

- Working tree only for secrets. Something committed and later deleted is still in history; run `gitleaks git` or similar as well, and rotate anything that was ever committed.
- Only classic branch protection is read. Repository rulesets are a different API and are not checked yet, so a branch protected only by a ruleset reports as unprotected. Check that by hand.
- No checks for SSO, audit log streaming, deploy keys, outside collaborators, or GitHub Apps with broad scopes.
- Terraform coverage is AWS-heavy and literal-only. No CloudFormation, Pulumi, Kubernetes manifests or Helm.
- None of this covers people, laptops, vendors or incident response. `SKILL.md` does.

## The agent skill

Copy `SKILL.md` to `.cursor/skills/cybersecurity-baseline/SKILL.md` or your agent's equivalent. It runs `baseline-audit` where it can and covers the rest as an interview. [examples/sample-review.md](examples/sample-review.md) shows the report shape for a made-up company.

## License

MIT. See [LICENSE](LICENSE). Copyright 2026 Banrox Inc.

Issues and patches welcome. Do not send exploit code or attack tooling.
