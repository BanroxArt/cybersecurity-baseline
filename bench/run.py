"""Micro-benchmarks. Run: PYTHONPATH=src python bench/run.py

Standard library timeit, best of five repeats. Numbers are per operation on
one CPU core; compare runs on the same machine, not across machines.
"""

from __future__ import annotations

import platform
import sys
import tempfile
import timeit
from collections.abc import Callable
from pathlib import Path

from baseline_check.checks.dockerfile import scan_dockerfiles
from baseline_check.checks.secrets import entropy, scan_secrets, scan_text
from baseline_check.checks.workflows import scan_workflows


def bench(name: str, fn: Callable[[], object], number: int, repeat: int = 5) -> None:
    best = min(timeit.repeat(fn, number=number, repeat=repeat)) / number
    print(f"| {name} | {best * 1e6:,.2f} | {1 / best:,.0f} |")


def header() -> None:
    print(f"Python {platform.python_version()} on {platform.machine()} ({sys.platform})\n")
    print("| case | µs/op | ops/s |")
    print("|---|---:|---:|")


SRC = Path(__file__).resolve().parents[1] / "src"
WORKFLOW = """name: ci
on: [push, pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: make check
"""
DOCKERFILE = """FROM python:3.12-slim
RUN useradd -m app
USER app
COPY . /app
CMD ["python", "-m", "app"]
"""


def main() -> None:
    header()
    code = "\n".join(p.read_text("utf-8") for p in sorted(SRC.rglob("*.py")))
    lines = code.count("\n")
    bench(f"scan_text over own source ({lines:,} lines)", lambda: list(scan_text(code)), 20)
    bench(
        "entropy, 40-char token", lambda: entropy("q8ZvN3tXr2LmPa9WcKe5YbHu7JdFs4Gi6Ro1TnEy"), 50000
    )
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for i in range(200):
            d = root / f"svc{i:03d}"
            d.mkdir()
            (d / "Dockerfile").write_text(DOCKERFILE)
            (d / "main.py").write_text(code[:4000])
        wf = root / ".github" / "workflows"
        wf.mkdir(parents=True)
        for i in range(200):
            (wf / f"ci{i:03d}.yml").write_text(WORKFLOW)
        bench("scan_secrets, tree of 600 files", lambda: scan_secrets(root), 3)
        bench("scan_workflows, 200 workflow files", lambda: scan_workflows(root), 3)
        bench("scan_dockerfiles, 200 Dockerfiles", lambda: scan_dockerfiles(root), 3)


if __name__ == "__main__":
    main()
