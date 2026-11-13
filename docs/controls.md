# Controls, reasoning and sources

References are to public guidance the control lines up with. Listing a source does not mean this tool implements that standard or that passing these checks satisfies it.

## Secrets

**SEC-01 No credentials in the tree (critical).** Public and private repos are both scraped; a private repo becomes public by mistake, or a laptop with a clone is lost. Patterns cover AWS key ids, private key headers, GitHub, GitLab, Slack, Stripe live, Twilio and Google API keys, plus `key = "..."` assignments with high entropy. The generic rule skips values under 3.5 bits of entropy per character and obvious placeholders (a whole word such as `example`, `changeme` or `test`, or shapes like `your-...` and `xxxx`; a random value that merely contains "test" is still reported). Files that are not read, because they are over 1 MB, are symlinks or cannot be opened, turn SEC-01 into `warn` with a count, so a clean result is never silently partial.

Findings show a keyed fingerprint (`h1:` plus 16 hex characters of an HMAC-SHA256), never the value. A plain hash would let anyone holding the report test guesses offline. Set `BASELINE_FINGERPRINT_KEY` (16+ characters) to make fingerprints stable between runs so `.baseline-ignore` works; without it a random key is drawn per run.

**SEC-02 No tracked env or key files (high).** `.env`, `.env.*` (except `.example`, `.sample`, `.template`), `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `*.p12`, `*.pfx`. Uses `git ls-files`, so ignored local files are fine.

**SEC-03 `.gitignore` coverage (low).** Prevention for SEC-02.

## GitHub org

**GH-01 2FA required (critical).** Without it, one phished password is write access to every repo that member can reach.

**GH-02 No member-created public repos (medium).** Most accidental leaks of internal code start as "I'll just make this public for a minute".

**GH-03 Base permission read or none (medium).** Write as the default means every new hire can push to every repo.

## GitHub repo

**GH-10 to GH-13 Branch protection (high, medium).** Requires a PR with at least one approval, blocks force pushes and branch deletion, and applies to admins. Both classic branch protection and repository rulesets are read, and a branch counts as protected if either protects it: the highest required review count from either source, force pushes blocked by classic protection or a `non_fast_forward` rule, deletions blocked by classic protection or a `deletion` rule. For GH-13, a ruleset fails if its bypass list includes the repository admin role, org admins or enterprise owners; if the token cannot see the bypass list the control is `warn`. When neither source can be read the controls are `warn`, never `fail`. OpenSSF Scorecard's Branch-Protection check covers similar ground.

**GH-14 Secret scanning with push protection (high).** Push protection blocks the commit; scanning alone tells you after the key is already out. Free for public repos; private repos need GitHub's paid Secret Protection.

**GH-15 Dependabot alerts (medium).** The minimum for knowing a dependency has a published vulnerability.

**GH-16 Read-only `GITHUB_TOKEN` and Actions cannot approve PRs (medium).** A write default means any workflow step, including a third-party action, can push to the repo. OpenSSF Scorecard Token-Permissions.

## CI

**CI-01 Actions pinned by SHA (medium).** Tags can be moved to malicious commits. Scorecard Pinned-Dependencies.

**CI-02 Explicit permissions (medium).** Workflows without a `permissions:` block get the repo default, which on older repos is write-all.

**CI-03 `pull_request_target` and `workflow_run` running PR code (critical).** Those triggers run with secrets and a write token. Checking out the PR head (`ref:` set to the head sha or ref, or `repository:` set to the head repo), `gh pr checkout`, or fetching `refs/pull/...` in a run step then runs a stranger's code with both: `fail`. A `workflow_run` job that downloads artifacts from the triggering run is `warn`: the artifacts were built from untrusted code and must not be executed or unpacked into the workspace. A workflow with neither trigger passes CI-03; a repo with no workflows skips it. Scorecard Dangerous-Workflow.

**CI-04 Expression injection (high).** `run: echo "${{ github.event.issue.title }}"` puts attacker-chosen text into a shell script before the shell sees it. Pass it through `env:` instead. Scorecard Dangerous-Workflow.

## Containers

**CT-01 Non-root (medium).** CIS Docker Benchmark 4.1. A container escape from root is far worse than from an unprivileged UID.

**CT-02 Pinned base image (low).** Reproducibility first, security second: `:latest` changes underneath you.

**CT-03 No remote ADD or curl-pipe-shell (medium).** No integrity check on what got executed.

**CT-04 No secrets in ENV/ARG (high).** Both end up in image metadata and layer history (`docker history`). Use `RUN --mount=type=secret`.

## Terraform

**IAC-01 Public buckets (high).** `public-read` ACLs, public access blocks with any of the four settings off or left unset (unset means false), bucket policies that allow `Principal: "*"` (`warn` when a `Condition` narrows it), and `allUsers` grants on GCS.

**IAC-02 Admin ports open (high).** 22, 3389, 3306, 5432, 6379, 27017 from `0.0.0.0/0` or `::/0`, including all-protocol rules, in `aws_security_group` ingress blocks, `aws_security_group_rule` and `aws_vpc_security_group_ingress_rule` (`cidr_ipv4`, `cidr_ipv6`, `ip_protocol`). `dynamic "ingress"` blocks and computed sources or ports are `warn`.

**IAC-03 Encryption at rest (medium).** RDS instances and clusters and EBS volumes without encryption set. A computed value (`storage_encrypted = var.enc`) is `warn`, not `fail`.

Terraform files are parsed with `python-hcl2` when it is installed (`pip install 'baseline-check[hcl]'`), and with a small built-in reader otherwise. The built-in reader handles comments, heredocs and nested blocks but does not evaluate expressions. If `python-hcl2` cannot parse a file, the built-in reader is used for it and IAC-01 gets a `warn` saying so.
