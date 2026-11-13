# Example output (fictional company)

This sample shows the skill's report shape. It is not an audit of Banrox. It does not claim a formal security or payments assessment (including SOC 2, ISO 27001, or PCI), or any license.

## 1. Scope

A five-person product company with a production web app, one cloud account, and a customer-support inbox. No card issued in this example.

## 2. Highest-priority gaps

1. Shared admin cloud login without hardware MFA
2. Secrets in a chat transcript
3. No written "who do we call if production auth breaks" page

## 3. Checklist excerpt

- Unique identities, no shared root: missing
- MFA on email, source control, and cloud: partial
- Offboarding checklist: missing
- Vendor list with data each vendor sees: missing

## 4. 30-day plan

Week 1: hardware MFA on email, source control, and cloud. Rotate any secret that ever sat in chat.
Week 2: inventory vendors and who has admin.
Week 3: write a one-page incident path (who locks access, who talks to users).
Week 4: backup restore test of the customer database, once.

Do not claim the company is "secure" or "compliant" after this. Say what was checked.
