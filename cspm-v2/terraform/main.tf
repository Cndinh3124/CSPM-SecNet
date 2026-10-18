# Minimal SecNet-CSPM demo infrastructure.
# Only creates a Security Group in the account's existing default VPC.
# No EC2, public IPv4, NAT Gateway, ALB, RDS, EKS, or S3 resources are created.
#
# The public SSH rule is intentionally enabled by default to produce a real
# Prowler finding. No compute resource is attached to this Security Group.
# Set enable_public_ssh_test = false to disable the intentional finding.

data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "demo" {
  name        = "${var.project_name}-Demo-SG"
  description = "Security group used for controlled SecNet-CSPM Prowler demonstrations."
  vpc_id      = data.aws_vpc.default.id

  tags = {
    Name       = "${var.project_name}-Demo-SG"
    CSPMScope  = "demo"
    CSPMTarget = "true"
    Environment = "demo"
  }
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = aws_security_group.demo.id
  description       = "Intentional CSPM finding: public SSH for Prowler detection."
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  cidr_ipv4         = var.enable_public_ssh_test ? "0.0.0.0/0" : var.allowed_ssh_cidr

  tags = {
    CSPMScenario = "public-ssh"
  }
}

output "vpc_id" {
  description = "Existing default VPC used for the demo."
  value       = data.aws_vpc.default.id
}

output "security_group_id" {
  description = "Security Group scanned by Prowler."
  value       = aws_security_group.demo.id
}
