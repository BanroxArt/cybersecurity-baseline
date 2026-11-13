"""baseline-check command line."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from baseline_check.checks.dockerfile import scan_dockerfiles
from baseline_check.checks.github import (
    DryRunTransport,
    FixtureTransport,
    GitHubError,
    check_org,
    check_repo,
    transport_from_env,
)
from baseline_check.checks.secrets import scan_env_files, scan_secrets
from baseline_check.checks.terraform import scan_terraform
from baseline_check.checks.workflows import scan_workflows
from baseline_check.controls import CONTROLS, Severity
from baseline_check.findings import Finding
from baseline_check.report import roll_up, to_json, to_markdown, worst_failure


def run_local(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    findings += scan_secrets(root)
    findings += scan_env_files(root)
    findings += scan_workflows(root)
    findings += scan_dockerfiles(root)
    findings += scan_terraform(root)
    return findings


def run_github(args: argparse.Namespace) -> tuple[list[Finding], list[str]]:
    if not (args.github_org or args.github_repo):
        return [], []
    if args.dry_run:
        transport = DryRunTransport()
    elif args.fixtures:
        transport = FixtureTransport(args.fixtures)
    else:
        transport = transport_from_env()
    findings: list[Finding] = []
    if args.github_org:
        findings += check_org(transport, args.github_org)
    for repo in args.github_repo or []:
        findings += check_repo(transport, repo)
    return findings, getattr(transport, "requests", [])


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"not a directory: {args.path}", file=sys.stderr)
        return 2
    try:
        gh_findings, requests = run_github(args)
    except GitHubError as exc:
        print(f"github: {exc}", file=sys.stderr)
        return 2
    if args.dry_run:
        print("would request:")
        for r in requests:
            print(f"  GET {r}")
        return 0
    results = roll_up(run_local(root) + gh_findings)
    target = args.name or root.name
    text = to_json(results, target) if args.format == "json" else to_markdown(results, target)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    worst = worst_failure(results)
    if worst is not None and worst >= Severity.parse(args.fail_on):
        return 1
    return 0


def cmd_controls(_: argparse.Namespace) -> int:
    for c in CONTROLS.values():
        print(f"{c.id:<7} {c.severity.name.lower():<8} {c.area:<9} {c.title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="baseline-check", description="Defensive baseline self-check.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a checkout and optionally GitHub settings")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--github-org")
    s.add_argument("--github-repo", action="append", metavar="OWNER/NAME")
    s.add_argument("--fixtures", help="serve GitHub API responses from this directory (offline)")
    s.add_argument("--dry-run", action="store_true", help="print the GitHub requests and exit")
    s.add_argument("--format", choices=["md", "json"], default="md")
    s.add_argument("--name", help="target name shown in the report")
    s.add_argument("-o", "--output")
    s.add_argument(
        "--fail-on",
        default="high",
        choices=[x.name.lower() for x in Severity],
        help="exit 1 if any failing control is at least this severe (default high)",
    )
    s.set_defaults(func=cmd_scan)
    c = sub.add_parser("controls", help="list the baseline controls")
    c.set_defaults(func=cmd_controls)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
