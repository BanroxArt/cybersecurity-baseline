# Security policy

## Reporting a problem

Please report security problems in `baseline-check` privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue for anything that could leak a token or a scanned secret.

Useful reports include the command line, the relevant environment variables (names only, never values), and a minimal fixture that reproduces the problem. Please do not send real tokens, real secrets or reports from real organisations.

You should get an acknowledgement within five working days. Fixes land on `main` with a regression test and a CHANGELOG entry that credits you unless you ask not to be named.

## Supported versions

This is a 0.x project. Only the latest commit on `main` gets fixes.

## In scope

- The GitHub token being sent anywhere other than the configured API origin, or appearing in output, logs, exceptions or `repr()`.
- Secret values, or anything that lets a reader recover them, appearing in a report.
- The tool writing to GitHub or to the scanned checkout.
- Parsing of scanned files (YAML, HCL, Dockerfiles) leading to code execution or reads outside the checkout.

## Out of scope

- A control that misses a misconfiguration (a false negative). Those are bugs and welcome as normal issues, with a fixture.
- Findings about a system you do not own or are not authorised to test.

This tool is a self-check. It is not a penetration test, an audit opinion or a certification, and a clean report does not mean a system is secure.
