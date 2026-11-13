"""Terraform checks for the three misconfigurations that leak data most often.

This does not parse HCL properly. It finds top-level ``resource`` blocks by
brace matching and reads ``key = value`` pairs inside them, which covers
literal values. Anything computed (variables, locals, modules) is skipped,
so a clean result here is weaker evidence than a tfsec or checkov run.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from baseline_audit.checks.secrets import SKIP_DIRS
from baseline_audit.findings import Finding, Status

RESOURCE = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.M)
ADMIN_PORTS = {
    22: "ssh",
    3389: "rdp",
    3306: "mysql",
    5432: "postgres",
    6379: "redis",
    27017: "mongodb",
}
OPEN_CIDRS = ('"0.0.0.0/0"', '"::/0"')


def blocks(text: str) -> Iterator[tuple[str, str, int, str]]:
    """Yield ``(type, name, line, body)`` for each resource block."""
    for m in RESOURCE.finditer(text):
        depth, i = 1, m.end()
        in_str = False
        while i < len(text) and depth:
            ch = text[i]
            if ch == '"' and text[i - 1] != "\\":
                in_str = not in_str
            elif not in_str:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
            i += 1
        yield m.group(1), m.group(2), text.count("\n", 0, m.start()) + 1, text[m.end() : i - 1]


def _attr(body: str, key: str) -> str | None:
    m = re.search(rf"^\s*{key}\s*=\s*(.+?)\s*$", body, re.M)
    return m.group(1) if m else None


def _ports(body: str) -> set[int]:
    if (_attr(body, "protocol") or "").strip('"') in ("-1", "all"):
        return set(ADMIN_PORTS)
    lo, hi = _attr(body, "from_port"), _attr(body, "to_port")
    try:
        a, b = int(lo or ""), int(hi or lo or "")
    except ValueError:
        return set()
    return {p for p in ADMIN_PORTS if a <= p <= b} if b - a < 65535 else set(ADMIN_PORTS)


def check_tf(text: str, rel: str) -> list[Finding]:
    out: list[Finding] = []
    for rtype, name, line, body in blocks(text):
        loc = f"{rel}:{line} {rtype}.{name}"
        if rtype in ("aws_s3_bucket", "aws_s3_bucket_acl"):
            acl = _attr(body, "acl")
            if acl and acl.strip('"') in ("public-read", "public-read-write"):
                out.append(Finding("IAC-01", Status.FAIL, f"bucket ACL {acl}", loc))
        if rtype == "aws_s3_bucket_public_access_block":
            for key in ("block_public_acls", "block_public_policy", "restrict_public_buckets"):
                if (_attr(body, key) or "").strip() == "false":
                    out.append(Finding("IAC-01", Status.FAIL, f"{key} = false", loc))
        if rtype == "google_storage_bucket_iam_member" and '"allUsers"' in body:
            out.append(Finding("IAC-01", Status.FAIL, "bucket granted to allUsers", loc))
        if rtype in (
            "aws_security_group",
            "aws_security_group_rule",
            "aws_vpc_security_group_ingress_rule",
        ):
            chunks = (
                re.findall(r"ingress\s*\{(.*?)\}", body, re.S)
                if rtype == "aws_security_group"
                else [body]
            )
            for chunk in chunks:
                if rtype == "aws_security_group_rule" and '"ingress"' not in (
                    _attr(chunk, "type") or ""
                ):
                    continue
                if any(c in chunk for c in OPEN_CIDRS):
                    for port in sorted(_ports(chunk)):
                        out.append(
                            Finding(
                                "IAC-02",
                                Status.FAIL,
                                f"{ADMIN_PORTS[port]} ({port}) open to the internet",
                                loc,
                            )
                        )
        encrypted = (_attr(body, "storage_encrypted") or "false").strip() == "true"
        if rtype in ("aws_db_instance", "aws_rds_cluster") and not encrypted:
            out.append(Finding("IAC-03", Status.FAIL, "storage_encrypted is not true", loc))
        if rtype == "aws_ebs_volume" and (_attr(body, "encrypted") or "false").strip() != "true":
            out.append(Finding("IAC-03", Status.FAIL, "EBS volume not encrypted", loc))
    return out


def scan_terraform(root: Path) -> list[Finding]:
    files = [
        p
        for p in sorted(root.rglob("*.tf"))
        if not any(part in SKIP_DIRS for part in p.relative_to(root).parts)
    ]
    if not files:
        return [
            Finding(c, Status.SKIP, "no Terraform files") for c in ("IAC-01", "IAC-02", "IAC-03")
        ]
    out: list[Finding] = []
    for f in files:
        out += check_tf(
            f.read_text(encoding="utf-8", errors="replace"), f.relative_to(root).as_posix()
        )
    for cid in ("IAC-01", "IAC-02", "IAC-03"):
        if not any(x.control == cid for x in out):
            out.append(Finding(cid, Status.PASS, "no literal misconfiguration found"))
    return out
