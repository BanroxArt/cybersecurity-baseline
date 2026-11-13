# Contributing

Bug reports and patches are welcome. For a new control or a change to how one is scored, open an issue first so we can agree on the wording and severity before you write code.

## Setup

```sh
python -m venv .venv && . .venv/bin/activate
python -m pip install -e '.[dev]'
make check
```

`make check` runs ruff (lint and format), the content lint in `scripts/check.py`, mypy in strict mode over `src/`, and pytest. The Terraform tests run twice, once with `python-hcl2` and once with the built-in reader, so both paths stay honest. CI runs the same steps on Python 3.11 to 3.13.

## What a good patch looks like

- One change per pull request, with a test that fails before it and passes after.
- GitHub API behaviour is tested with recorded responses in `tests/fixtures/github`, one JSON file per request path (`{"status": ..., "body": ...}`). Add a file rather than mocking.
- A new check reports `warn`, not `pass`, when it cannot see enough to decide.
- Test secrets are assembled at runtime from pieces (see `tests/conftest.py`) so no scanner sees a credential-shaped literal in this repo.
- Update `docs/controls.md` if a control's behaviour changes, and `CHANGELOG.md` under "Unreleased".

## Things we will not merge

- Anything that writes to GitHub or needs a token with write scopes.
- Checks against systems the user does not own, exploit code or attack tooling.
- Claims of conformance to a framework or certification. `refs` in `controls.py` point at public guidance for context only.

## Commit messages

Short imperative subject in lower case (`github: read rulesets for GH-10..13`), a blank line, then why.
