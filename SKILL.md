---
name: cybersecurity-baseline
description: Run a baseline cybersecurity review for a small or mid-size software company. Use when the user asks for a security checklist, a first-pass audit of their own systems, hardening advice, secrets handling, access control, logging, or “are we doing the obvious things.” Only review systems they own or are clearly authorized to test. Do not provide exploit instructions, attack playbooks, or help breaking into anything.
---

# Cybersecurity baseline review

Help the company find missing basics and fix them. This is a defensive review, not a penetration test and not a certification (it is not SOC 2, ISO 27001, or a PCI assessment).

## Rules

- Work only on systems the user owns or is authorized to review.
- If asked for exploits, payloads, or “how an attacker would get in,” refuse the offensive part and stay on hardening.
- Do not ask them to paste production secrets into the chat. If a secret appears, tell them to rotate it and treat the chat as compromised for that secret.
- Do not invent a “you passed” grade. Use in place / partial / missing / not applicable.

## How to work

1. Establish scope: cloud accounts, source control, production apps, employee laptops, email, vendors, and whether they handle payments, health, or children’s data (those raise the bar).
2. Walk the checklist below. Ask for evidence when a control is claimed (a setting, a policy, a log destination), but accept “we don’t have this yet.”
3. Rank gaps by: (a) can cause a full account or data takeover, (b) are cheap to fix this week, (c) can wait.
4. Hand back a 30-day hardening plan with owners.

## Baseline checklist

### Identity and access

- [ ] SSO or a password manager plus unique accounts; no shared “admin@” passwords in a wiki
- [ ] MFA on email, source control, cloud consoles, and production admin tools
- [ ] Offboarding: access removed the day someone leaves; a named owner for that process
- [ ] Least privilege on cloud IAM; no long-lived admin access keys on laptops
- [ ] Periodic access review for production and customer-data tools (even quarterly is a start)

### Source code and secrets

- [ ] Private repositories; branch protection on the default branch; reviews for production changes
- [ ] Secrets are not in git history. If they were, they have been rotated, not just deleted from HEAD
- [ ] A secrets manager or at least platform-managed env vars in production; no `.env` files on servers
- [ ] Dependency updates have an owner (Dependabot, Renovate, or a scheduled review)
- [ ] CI credentials are scoped and not available to pull requests from forks unless that is understood and accepted

### Application and infrastructure

- [ ] HTTPS everywhere; HSTS; no accidental open admin routes
- [ ] Security headers and cookie flags are intentional, not leftovers
- [ ] Backups exist, are encrypted, and have been restored at least once
- [ ] Production and development are separate; production data is not copied to laptops without a written rule
- [ ] Public cloud storage buckets and similar objects are not world-readable by accident
- [ ] Dependency and container base images are current enough to receive security patches

### Logging, incidents, and vendors

- [ ] Auth events, admin actions, and payments or account changes are logged and kept for a defined period
- [ ] Someone actually looks at those logs, or an alert exists for obvious abuse (mass login failures, new admin, data export)
- [ ] A one-page incident plan: who is called, who can take a system offline, how users are notified
- [ ] Vendor list with data each vendor can see; contract or DPA where customer personal data is involved
- [ ] Domain lock and email authentication (SPF, DKIM, DMARC) so the company is harder to spoof

### People

- [ ] Laptops disk-encrypted, auto-lock, and a rule for lost devices
- [ ] Phishing-resistant habits for finance and support (wire changes, password resets, “CEO asked me to buy gift cards”)

## Output format

1. Scope
2. Checklist with status and short evidence notes
3. Top five gaps, in priority order, each with a fix that can start this week
4. 30-day plan
5. What this review does **not** cover (red team, physical security, formal compliance)
