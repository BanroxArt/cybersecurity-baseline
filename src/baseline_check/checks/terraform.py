"""Terraform checks for the misconfigurations that leak data most often.

Parsing: when ``python-hcl2`` is installed (``pip install 'baseline-check[hcl]'``)
files are parsed with it. Otherwise a small built-in reader is used. The
built-in reader strips ``#``, ``//`` and ``/* */`` comments and skips
heredocs and quoted strings when matching braces, so comments and strings
cannot throw off block boundaries, but it is not a full HCL implementation:
it does not evaluate expressions, ``for`` constructs or functions.

Either way, values are only judged when they are literals. Anything computed
(variables, locals, module outputs, function calls) is reported as WARN on
the controls where it matters, never as PASS or FAIL. A clean result here is
weaker evidence than a tfsec, trivy or checkov run against a plan.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from baseline_check.checks.secrets import SKIP_DIRS
from baseline_check.findings import Finding, Status

_hcl2: Any
try:  # optional dependency
    import hcl2 as _hcl2
except ImportError:  # pragma: no cover - exercised when the extra is absent
    _hcl2 = None

RESOURCE = re.compile(r'^[ \t]*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.M)
ADMIN_PORTS = {
    22: "ssh",
    3389: "rdp",
    3306: "mysql",
    5432: "postgres",
    6379: "redis",
    27017: "mongodb",
}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
PUBLIC_ACCESS_KEYS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)
PUBLIC_PRINCIPAL = re.compile(r'"(?:Principal|AWS)"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])')


@dataclass(frozen=True, slots=True)
class Computed:
    """A value the reader could not resolve to a literal."""

    expr: str


@dataclass(slots=True)
class Resource:
    type: str
    name: str
    line: int
    attrs: dict[str, Any]


def hcl_backend() -> str:
    return "python-hcl2" if _hcl2 is not None else "built-in"


# ---------------------------------------------------------------- built-in reader


def strip_comments(text: str) -> str:
    """Blank out comments, keeping strings, heredocs and line numbers intact."""
    out: list[str] = []
    i, n = 0, len(text)
    heredoc: str | None = None
    while i < n:
        if heredoc is not None:
            end = text.find("\n", i)
            line = text[i : n if end == -1 else end + 1]
            out.append(line)
            if line.strip() == heredoc:
                heredoc = None
            i += len(line)
            continue
        ch = text[i]
        if ch == '"':
            j = i + 1
            while j < n and text[j] != '"' and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            out.append(text[i : j + 1])
            i = j + 1
            continue
        m = re.match(r"<<-?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\n", text[i:])
        if m:
            heredoc = m.group(1)
            out.append(m.group(0))
            i += m.end()
            continue
        if ch == "#" or text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            chunk = text[i : n if end == -1 else end + 2]
            out.append("\n" * chunk.count("\n"))
            i += len(chunk)
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _depth_change(line: str) -> int:
    depth, in_str, i = 0, False, 0
    while i < len(line):
        ch = line[i]
        if in_str:
            if ch == "\\":
                i += 1
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "{[(":
            depth += 1
        elif ch in "}])":
            depth -= 1
        i += 1
    return depth


def _literal(raw: str) -> Any:
    v = raw.strip().rstrip(",")
    if v in ("true", "false"):
        return v == "true"
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    if re.fullmatch(r'"(?:[^"\\$]|\\.|\$(?!\{))*"', v):
        return v[1:-1]
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        if not inner:
            return []
        items = [x.strip() for x in re.split(r",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", inner)]
        return [_literal(x) for x in items if x]
    if v.startswith("<<"):
        lines = v.split("\n")
        return "\n".join(lines[1:-1])
    return Computed(v)


def _parse_body(lines: list[str]) -> dict[str, Any]:
    attrs: dict[str, Any] = {}
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line:
            continue
        block = re.match(r'^([A-Za-z_][\w-]*)((?:\s+"[^"]*")*)\s*\{(.*)$', line)
        if block and "=" not in line.split("{", 1)[0]:
            depth = _depth_change(line)
            inner: list[str] = [block.group(3)] if block.group(3).strip() else []
            while depth > 0 and i < len(lines):
                depth += _depth_change(lines[i])
                inner.append(lines[i])
                i += 1
            if inner and inner[-1].rstrip().endswith("}"):
                inner[-1] = inner[-1].rstrip()[:-1]
            labels = re.findall(r'"([^"]*)"', block.group(2))
            body = _parse_body(inner)
            name = block.group(1)
            if labels and name == "dynamic":
                body = {**body, "__label__": labels[0]}
            attrs.setdefault(name, []).append(body)
            continue
        kv = re.match(r"^([A-Za-z_][\w-]*)\s*=\s*(.*)$", line)
        if not kv:
            continue
        value = kv.group(2)
        heredoc = re.match(r"<<-?\s*([A-Za-z_]\w*)\s*$", value)
        if heredoc:
            collected = [value]
            while i < len(lines):
                collected.append(lines[i])
                i += 1
                if lines[i - 1].strip() == heredoc.group(1):
                    break
            attrs[kv.group(1)] = _literal("\n".join(collected))
            continue
        depth = _depth_change(value)
        while depth > 0 and i < len(lines):
            depth += _depth_change(lines[i])
            value += " " + lines[i].strip()
            i += 1
        attrs[kv.group(1)] = _literal(value)
    return attrs


def blocks(text: str) -> Iterator[tuple[str, str, int, str]]:
    """Yield ``(type, name, line, body)`` for each resource block (built-in reader)."""
    clean = strip_comments(text)
    for m in RESOURCE.finditer(clean):
        depth, i = 1, m.end()
        in_str = False
        while i < len(clean) and depth:
            ch = clean[i]
            if in_str:
                if ch == "\\":
                    i += 1
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        line = clean.count("\n", 0, m.start()) + 1
        yield m.group(1), m.group(2), line, clean[m.end() : i - 1]


def _builtin_resources(text: str) -> list[Resource]:
    return [
        Resource(t, n, line, _parse_body(body.splitlines())) for t, n, line, body in blocks(text)
    ]


# ---------------------------------------------------------------- python-hcl2


def _unquote(v: Any) -> Any:
    if isinstance(v, str):
        if v.startswith('"') and v.endswith('"') and len(v) >= 2:
            v = v[1:-1]
        if "${" in v:
            return Computed(v)
        return v
    if isinstance(v, list):
        return [_unquote(x) for x in v]
    if isinstance(v, dict):
        return {
            _unquote(k) if isinstance(k, str) else k: _unquote(x)
            for k, x in v.items()
            if not str(k).startswith("__")
        }
    return v


def _hcl2_resources(text: str) -> list[Resource]:
    assert _hcl2 is not None
    data = _hcl2.loads(text)
    clean = strip_comments(text)  # same line breaks as text, comments blanked
    lines = {
        (m.group(1), m.group(2)): clean.count("\n", 0, m.start()) + 1
        for m in RESOURCE.finditer(clean)
    }
    out: list[Resource] = []
    for entry in data.get("resource", []):
        for rtype, named in entry.items():
            rtype = str(_unquote(rtype))
            for name, body in named.items():
                name = str(_unquote(name))
                attrs = _unquote(body) if isinstance(body, dict) else {}
                for dyn in attrs.get("dynamic", []) or []:
                    if isinstance(dyn, dict) and len(dyn) == 1:
                        label, inner = next(iter(dyn.items()))
                        dyn.clear()
                        dyn.update(inner if isinstance(inner, dict) else {})
                        dyn["__label__"] = label
                out.append(Resource(rtype, name, lines.get((rtype, name), 0), attrs))
    return out


def parse_resources(text: str) -> tuple[list[Resource], str | None]:
    """Resources in ``text`` and, if the real parser failed, why."""
    if _hcl2 is not None:
        try:
            return _hcl2_resources(text), None
        except Exception as exc:  # lark raises a family of its own errors
            return _builtin_resources(text), f"python-hcl2 could not parse: {type(exc).__name__}"
    return _builtin_resources(text), None


# ---------------------------------------------------------------- checks


def _as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _ports(rule: dict[str, Any], proto_key: str) -> set[int] | None:
    """Admin ports a rule opens, or None if the range is computed."""
    proto = rule.get(proto_key)
    if isinstance(proto, Computed):
        return None
    if str(proto) in ("-1", "all"):
        return set(ADMIN_PORTS)
    lo, hi = rule.get("from_port"), rule.get("to_port", rule.get("from_port"))
    if isinstance(lo, Computed) or isinstance(hi, Computed):
        return None
    try:
        a, b = int(str(lo)), int(str(hi))
    except (TypeError, ValueError):
        return set()
    if (a, b) == (0, 0) or b - a >= 65535:
        return set(ADMIN_PORTS)
    return {p for p in ADMIN_PORTS if a <= p <= b}


def _open_cidrs(rule: dict[str, Any], keys: tuple[str, ...]) -> bool | None:
    computed = False
    for key in keys:
        for v in _as_list(rule.get(key)):
            if isinstance(v, Computed):
                computed = True
            elif str(v) in OPEN_CIDRS:
                return True
    return None if computed else False


def _check_ingress(
    rule: dict[str, Any], loc: str, proto_key: str, cidr_keys: tuple[str, ...]
) -> list[Finding]:
    open_ = _open_cidrs(rule, cidr_keys)
    if open_ is False:
        return []
    ports = _ports(rule, proto_key)
    if open_ is None or ports is None:
        return [Finding("IAC-02", Status.WARN, "ingress source or ports are computed", loc)]
    return [
        Finding("IAC-02", Status.FAIL, f"{ADMIN_PORTS[p]} ({p}) open to the internet", loc)
        for p in sorted(ports)
    ]


def _encryption(attrs: dict[str, Any], key: str, what: str, loc: str) -> list[Finding]:
    v = attrs.get(key)
    if isinstance(v, Computed):
        return [Finding("IAC-03", Status.WARN, f"{key} is computed ({v.expr}), not checked", loc)]
    if v is True or str(v).lower() == "true":
        return []
    return [Finding("IAC-03", Status.FAIL, f"{what}: {key} is not true", loc)]


def check_resource(res: Resource, rel: str) -> list[Finding]:
    loc = f"{rel}:{res.line} {res.type}.{res.name}"
    a = res.attrs
    out: list[Finding] = []
    if res.type in ("aws_s3_bucket", "aws_s3_bucket_acl"):
        acl = a.get("acl")
        if isinstance(acl, str) and acl in ("public-read", "public-read-write"):
            out.append(Finding("IAC-01", Status.FAIL, f"bucket ACL {acl}", loc))
    if res.type == "aws_s3_bucket_public_access_block":
        for key in PUBLIC_ACCESS_KEYS:
            v = a.get(key)
            if isinstance(v, Computed):
                out.append(Finding("IAC-01", Status.WARN, f"{key} is computed", loc))
            elif v is None:
                out.append(
                    Finding("IAC-01", Status.FAIL, f"{key} not set (defaults to false)", loc)
                )
            elif not (v is True or str(v).lower() == "true"):
                out.append(Finding("IAC-01", Status.FAIL, f"{key} = false", loc))
    if res.type == "aws_s3_bucket_policy":
        policy = a.get("policy")
        if isinstance(policy, str) and PUBLIC_PRINCIPAL.search(policy) and '"Allow"' in policy:
            status = Status.WARN if '"Condition"' in policy else Status.FAIL
            msg = "policy allows Principal *" + (
                " with a condition" if status is Status.WARN else ""
            )
            out.append(Finding("IAC-01", status, msg, loc))
    if res.type.startswith("google_storage_bucket_iam"):
        members = _as_list(a.get("member")) + _as_list(a.get("members"))
        if any(str(m) in ("allUsers", "allAuthenticatedUsers") for m in members):
            out.append(Finding("IAC-01", Status.FAIL, "bucket granted to allUsers", loc))

    if res.type == "aws_security_group":
        for rule in _as_list(a.get("ingress")):
            if isinstance(rule, dict):
                out += _check_ingress(rule, loc, "protocol", ("cidr_blocks", "ipv6_cidr_blocks"))
        for dyn in _as_list(a.get("dynamic")):
            if isinstance(dyn, dict) and dyn.get("__label__") == "ingress":
                out.append(Finding("IAC-02", Status.WARN, "dynamic ingress not evaluated", loc))
    if res.type == "aws_security_group_rule" and a.get("type") == "ingress":
        out += _check_ingress(a, loc, "protocol", ("cidr_blocks", "ipv6_cidr_blocks"))
    if res.type == "aws_vpc_security_group_ingress_rule":
        out += _check_ingress(a, loc, "ip_protocol", ("cidr_ipv4", "cidr_ipv6"))

    if res.type in ("aws_db_instance", "aws_rds_cluster"):
        out += _encryption(a, "storage_encrypted", "database storage", loc)
    if res.type == "aws_ebs_volume":
        out += _encryption(a, "encrypted", "EBS volume", loc)
    return out


def check_tf(text: str, rel: str) -> list[Finding]:
    resources, parse_error = parse_resources(text)
    out: list[Finding] = []
    if parse_error:
        out.append(Finding("IAC-01", Status.WARN, f"{parse_error}; used the built-in reader", rel))
    for res in resources:
        out += check_resource(res, rel)
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
            out.append(
                Finding(cid, Status.PASS, f"no literal misconfiguration found ({hcl_backend()})")
            )
    return out
