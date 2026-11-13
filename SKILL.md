---
name: cybersecurity-baseline
description: Run a defensive baseline security review for a small or mid-size software company, using the baseline-check tool in this repo for what can be checked automatically (committed secrets, GitHub org and repo settings, CI workflows, Dockerfiles, Terraform) and an interview for the rest (identity, laptops, vendors, logging, incident path). Use when the user asks for a security checklist, a first-pass review of their own systems, hardening, secrets handling, or "are we doing the obvious things". Only for systems the user owns or is authorized to review. No exploit instructions, attack playbooks, or help getting into anything.
---

# Cybersecurity baseline review

Help the team find the missing basics and fix them. This is not a penetration test and not a certification. Do not describe a pass as being SOC 2, ISO 27001 or PCI ready, and do not invent a grade.

## Ground rules

- Only systems the user owns or is authorized to review. If that is unclear, ask.
- If asked for exploits, payloads or how an attacker would get in, decline that part and stay on hardening.
- Never ask for secrets in the chat. If one appears, tell them to rotate it now and treat it as exposed.
- Status words are in place, partial, missing, not applicable. Ask for evidence (a setting, a screenshot of a policy page, a log destination), and accept "we don't have that yet" without judgement.

## Step 1: scope

Cloud accounts, source control, production apps, laptops, email and identity provider, vendors with customer data. Ask whether they handle payments, health data or children's data; those raise the bar and usually bring a regulator or a partner's requirements, which take precedence.

## Step 2: run the tool where it applies

From a checkout of their repo:

```sh
pip install baseline-check   # or pip install -e . from this repo
baseline-check scan . --format md -o baseline.md
```

If they want the GitHub settings checked, have them create a read-only fine-grained token themselves (docs/github-token.md), export it in their own shell, and run with `--github-org` and `--github-repo`. Suggest `--dry-run` first so they can see every endpoint called. You never handle the token.

Read the report with them. For every `fail`, confirm it is real before calling it a gap; for every `warn`, find out by hand. Note the tool's blind spots: secrets in git history (run gitleaks), rulesets-only branch protection, computed Terraform values.

## Step 3: interview for what the tool cannot see

Identity and access
- SSO or a password manager, unique accounts, no shared admin logins
- MFA on email, source control, cloud consoles, production admin tools; phishing-resistant (passkeys or hardware keys) for admins
- Offboarding the same day, with a named owner
- No long-lived admin cloud keys on laptops
- Access review for production and customer-data tools, quarterly is fine to start

Secrets and production
- Secrets manager or platform-managed env vars in production, no `.env` on servers
- Anything ever committed has been rotated, not just deleted
- Production and development separated; production data not copied to laptops without a written rule
- Backups encrypted and restored at least once

Logging and incidents
- Auth events, admin actions, payment and account changes logged and kept for a stated period
- Someone looks, or an alert exists for mass login failures, new admins, bulk exports
- One-page incident plan: who gets called, who can take a system down, how users are told
- SPF, DKIM, DMARC on the domain; registrar lock

Vendors and people
- Vendor list with what data each one sees and a DPA where personal data is involved
- Laptops encrypted with auto-lock, a lost-device rule
- Finance and support trained for payment-change and password-reset social engineering

## Step 4: prioritise

Rank gaps by: can lead to account or data takeover; cheap to fix this week; can wait. Expect the top of the list to be some of: 2FA not enforced, secrets in repos, write-default CI tokens or `pull_request_target` mistakes, shared admin accounts, no offboarding.

## Output format

1. Scope, and what was out of scope
2. Tool results: score, failing controls, and which were confirmed by hand
3. Interview checklist with status and evidence notes
4. Top five gaps in order, each with a fix that can start this week and an owner
5. 30-day plan
6. What this review did not cover: red team, physical security, formal compliance, anything the user did not give access to

See `examples/sample-review.md` for the shape.
