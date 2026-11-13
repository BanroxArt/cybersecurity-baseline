import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from baseline_check.checks import terraform
from baseline_check.checks.terraform import blocks, check_tf, scan_terraform
from baseline_check.findings import Status


@pytest.fixture(params=["python-hcl2", "built-in"], autouse=True)
def backend(request, monkeypatch):
    """Run every test against both readers."""
    if request.param == "built-in":
        monkeypatch.setattr(terraform, "_hcl2", None)
    elif terraform._hcl2 is None:
        pytest.skip("python-hcl2 not installed")
    return request.param


def controls(text):
    return sorted(f.control for f in check_tf(text, "main.tf"))


def statuses(text, control):
    return [f.status for f in check_tf(text, "main.tf") if f.control == control]


def test_blocks_handle_nesting_and_braces_in_strings():
    text = 'resource "a" "b" {\n  x = "{"\n  inner {\n    y = 1\n  }\n}\nresource "c" "d" {}\n'
    got = [(t, n, line) for t, n, line, _ in blocks(text)]
    assert got == [("a", "b", 1), ("c", "d", 7)]


def test_public_bucket_and_access_block():
    text = """
resource "aws_s3_bucket_acl" "x" {
  acl = "public-read"
}
resource "aws_s3_bucket_public_access_block" "x" {
  block_public_acls   = false
  block_public_policy = true
}
resource "google_storage_bucket_iam_member" "x" {
  member = "allUsers"
}
"""
    # acl, block_public_acls = false, two keys left unset (default false), allUsers
    msgs = sorted(f.message for f in check_tf(text, "main.tf"))
    assert controls(text) == ["IAC-01"] * 5
    assert "ignore_public_acls not set (defaults to false)" in msgs


def test_open_admin_ports():
    text = """
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 3389
    to_port     = 3389
    cidr_blocks = ["198.51.100.0/24"]
  }
}
resource "aws_security_group_rule" "all" {
  type        = "ingress"
  protocol    = "-1"
  from_port   = 0
  to_port     = 0
  cidr_blocks = ["0.0.0.0/0"]
}
resource "aws_security_group_rule" "egress" {
  type        = "egress"
  from_port   = 0
  to_port     = 65535
  cidr_blocks = ["0.0.0.0/0"]
}
"""
    findings = check_tf(text, "main.tf")
    assert {f.control for f in findings} == {"IAC-02"}
    assert all("aws_security_group_rule.all" in f.location for f in findings)
    assert len(findings) == 6


def test_encryption():
    text = """
resource "aws_db_instance" "a" {
  engine = "postgres"
}
resource "aws_rds_cluster" "b" {
  storage_encrypted = true
}
resource "aws_ebs_volume" "c" {
  encrypted = false
}
"""
    assert controls(text) == ["IAC-03", "IAC-03"]


def test_scan_reports_pass_or_skip(tmp_path):
    assert {f.status for f in scan_terraform(tmp_path)} == {Status.SKIP}
    (tmp_path / "ok.tf").write_text('resource "aws_ebs_volume" "v" {\n  encrypted = true\n}\n')
    assert {f.status for f in scan_terraform(tmp_path)} == {Status.PASS}


def test_comments_with_quotes_and_braces_do_not_break_blocks():
    # Regression: a stray quote or brace in a comment flipped the string state
    # of the old brace matcher and swallowed later resources.
    text = """
# don't "quote me { here
resource "aws_ebs_volume" "a" {
  encrypted = true // trailing "quote
}
/* commented out {
resource "aws_ebs_volume" "ghost" { encrypted = false }
*/
resource "aws_ebs_volume" "b" {
  encrypted = false
}
"""
    findings = check_tf(text, "main.tf")
    assert [f.location for f in findings] == ["main.tf:9 aws_ebs_volume.b"]


def test_heredoc_policy_with_public_principal():
    text = """
resource "aws_s3_bucket_policy" "p" {
  bucket = "b"
  policy = <<EOT
{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}
EOT
}
resource "aws_s3_bucket_policy" "scoped" {
  bucket = "b"
  policy = <<EOT
{"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"},
  "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}}}]}
EOT
}
"""
    assert statuses(text, "IAC-01") == [Status.FAIL, Status.WARN]


def test_computed_encryption_is_warn_not_fail():
    # Regression: storage_encrypted = var.enc was reported as FAIL.
    text = 'resource "aws_db_instance" "a" {\n  storage_encrypted = var.enc\n}\n'
    assert statuses(text, "IAC-03") == [Status.WARN]


def test_nested_and_dynamic_ingress():
    text = """
resource "aws_security_group" "sg" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "ops {legacy}"
  }
  dynamic "ingress" {
    for_each = var.rules
    content {
      from_port = ingress.value
    }
  }
  tags = { Name = "x" }
}
"""
    findings = check_tf(text, "main.tf")
    assert [(f.status, f.message) for f in findings] == [
        (Status.FAIL, "ssh (22) open to the internet"),
        (Status.WARN, "dynamic ingress not evaluated"),
    ]


def test_vpc_ingress_rule_all_protocols():
    # Regression: ip_protocol = "-1" was missed because only `protocol` was read.
    text = """
resource "aws_vpc_security_group_ingress_rule" "all" {
  security_group_id = aws_security_group.x.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}
resource "aws_vpc_security_group_ingress_rule" "computed" {
  cidr_ipv4   = var.cidr
  ip_protocol = "tcp"
  from_port   = 22
  to_port     = 22
}
"""
    got = statuses(text, "IAC-02")
    assert got.count(Status.FAIL) == 6
    assert got.count(Status.WARN) == 1


def test_access_block_fully_set_passes():
    text = """
resource "aws_s3_bucket_public_access_block" "ok" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""
    assert check_tf(text, "main.tf") == []


hcl_noise = st.text(alphabet='abc {}"#/*\n=<>EOT', max_size=200)


@settings(max_examples=150, deadline=None)
@given(hcl_noise)
def test_reader_never_raises_on_garbage(noise):
    resource = 'resource "aws_ebs_volume" "v" {\n  encrypted = false\n}\n'
    check_tf(noise, "x.tf")
    # A well-formed resource after arbitrary garbage on its own lines is not
    # lost by the built-in reader unless the garbage opens an unterminated block.
    check_tf(noise + "\n" + resource, "x.tf")
