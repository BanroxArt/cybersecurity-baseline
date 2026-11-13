# GitHub token for baseline-check

1. GitHub > Settings > Developer settings > Fine-grained tokens > Generate new token.
2. Resource owner: the org. Repository access: only the repos you want checked.
3. Repository permissions: Administration read-only, Metadata read-only.
4. Organization permissions: Administration read-only.
5. Expiry: short. Seven days is plenty for a one-off check.

Then:

```sh
read -rs GITHUB_TOKEN && export GITHUB_TOKEN
baseline-check scan . --github-org your-org --github-repo your-org/api
unset GITHUB_TOKEN
```

`read -s` keeps the token out of shell history. Do not put it in a file in the repo.

Run `--dry-run` first if you want to see exactly which endpoints will be called. All are `GET`:

```text
GET /orgs/{org}
GET /repos/{owner}/{repo}
GET /repos/{owner}/{repo}/branches/{default_branch}/protection
GET /repos/{owner}/{repo}/rules/branches/{default_branch}
GET /repos/{owner}/{repo}/rulesets/{ruleset_id}        (once per ruleset that applies)
GET /repos/{owner}/{repo}/vulnerability-alerts
GET /repos/{owner}/{repo}/actions/permissions/workflow
```

Some fields are only visible to org owners. When a field is missing the control reports `warn` instead of guessing. The same goes for a ruleset's bypass list, which GitHub only returns to people who can edit the ruleset: without it GH-13 is `warn`.

## Where the token goes

The token is sent to `https://api.github.com`, or to `GITHUB_API_URL` for GitHub Enterprise Server. That variable must be a plain `https` URL: no `http`, no credentials, query or fragment. Redirects are followed only when they stay on the same scheme, host and port. Python's urllib would otherwise forward the `Authorization` header to wherever a redirect points, so a misconfigured proxy or a hostile server could collect the token. A refused redirect stops the run with an error that names the target host and never the token.

In CI, the built-in `GITHUB_TOKEN` cannot read org settings or branch protection on most plans. Use a dedicated read-only token stored as an Actions secret, or run the GitHub part locally.
