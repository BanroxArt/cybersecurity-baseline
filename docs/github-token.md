# GitHub token for baseline-audit

1. GitHub > Settings > Developer settings > Fine-grained tokens > Generate new token.
2. Resource owner: the org. Repository access: only the repos you want checked.
3. Repository permissions: Administration read-only, Metadata read-only.
4. Organization permissions: Administration read-only.
5. Expiry: short. Seven days is plenty for a one-off audit.

Then:

```sh
read -rs GITHUB_TOKEN && export GITHUB_TOKEN
baseline-audit scan . --github-org your-org --github-repo your-org/api
unset GITHUB_TOKEN
```

`read -s` keeps the token out of shell history. Do not put it in a file in the repo.

Run `--dry-run` first if you want to see exactly which endpoints will be called. All are `GET`:

```text
GET /orgs/{org}
GET /repos/{owner}/{repo}
GET /repos/{owner}/{repo}/branches/{default_branch}/protection
GET /repos/{owner}/{repo}/vulnerability-alerts
GET /repos/{owner}/{repo}/actions/permissions/workflow
```

Some fields are only visible to org owners. When a field is missing the control reports `warn` instead of guessing.

In CI, the built-in `GITHUB_TOKEN` cannot read org settings or branch protection on most plans. Use a dedicated read-only token stored as an Actions secret, or run the GitHub part locally.
