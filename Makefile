PY ?= python3

.PHONY: install lint test check demo

install:
	$(PY) -m pip install -e '.[dev]'

lint:
	ruff check .
	ruff format --check .
	$(PY) scripts/check.py

test:
	$(PY) -m pytest -q

check: lint test

# Offline run against the recorded GitHub responses in tests/fixtures.
demo:
	$(PY) -m baseline_audit scan tests/fixtures/sample-repo \
		--github-org example-org --github-repo example-org/api \
		--fixtures tests/fixtures/github --format md
