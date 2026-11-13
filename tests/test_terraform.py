from baseline_audit.checks.terraform import blocks, check_tf, scan_terraform
from baseline_audit.findings import Status


def controls(text):
    return sorted(f.control for f in check_tf(text, "main.tf"))


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
    assert controls(text) == ["IAC-01", "IAC-01", "IAC-01"]


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
