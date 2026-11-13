# cybersecurity-baseline

A practical baseline security review for a small software or fintech team: access, secrets, logging, vendor list, and incident path. It is a defensive checklist, not a penetration test and not a certification.

Author: Art Akopian, CEO of [Banrox](https://banrox.com)

## What it does

This repository is an agent skill. After you install it, ask your coding agent for a first-pass security review of systems you own or are clearly authorized to review. The agent should:

- Walk a baseline checklist covering identity and access, source code and secrets, application and infrastructure, logging and incidents, vendors, and people
- Ask for evidence when a control is claimed, and accept "we do not have this yet"
- Rank gaps by takeover risk and by what can be fixed this week
- Return a report: scope, checklist with status, the top gaps with a fix that can start this week, a 30-day plan, and what the review does not cover

The skill will not provide exploit instructions, attack playbooks, or help breaking into anything. It will not invent a passing grade. Status is in place, partial, missing, or not applicable.

## Install

Copy `SKILL.md` into your agent's skills folder, for example:

```text
.cursor/skills/cybersecurity-baseline/SKILL.md
```

or the equivalent path your agent documents. Restart or reload skills if your agent requires it.

## Use

Ask for a baseline cybersecurity review of your own systems. Be ready to name cloud accounts, source control, production apps, employee laptops, email, and vendors, and to say whether you handle payments, health, or children's data (those raise the bar). Do not paste production secrets into the chat.

## Example

See [examples/sample-review.md](examples/sample-review.md) for a fictional worked example of the expected report shape. It is not an audit of Banrox. It does not claim a formal security or payments assessment, or any license.

## Limitations

- Not a penetration test, red team, or formal compliance assessment, including SOC 2, ISO 27001, or PCI.
- Not a certificate, and not a claim that a company is "secure" or "compliant" after the review.
- Not legal advice. Work only on systems the user owns or is authorized to review.
- The skill will refuse offensive requests (exploits, payloads, or how an attacker would get in) and stay on hardening.

## License

The `LICENSE` file currently contains the MIT License text, with copyright holder Banrox Inc. and year 2026. This is a placeholder. The public licence is pending a final pick by Banrox and may change before the repository is published. Do not treat MIT as final until that decision is recorded.

## Checks

From the repository root:

```text
python3 scripts/check.py
```

This validates skill frontmatter, required sections, example files, local links, and a lint that public files do not include internal names or unsupported certification or traction claims.

## Contributing

Issues and patches are welcome after a public repository exists. Do not send exploit proof-of-concepts or requests to evade security controls.

## Related skills

Sibling skills from the same author, each in its own repository:

- `fraud-prevention` — defensive fraud-program checklist
- `live-codebase` — two-week plan to make one service shippable, observable, and safely connected to live data
- `calling-bot-twilio` — consent-gated Twilio calling pattern (not a dialer)
