resource "aws_security_group" "cspm_test_ssh" {
  name        = "CSPM-Test-SSH-Public"
  description = "Intentional insecure Security Group for CSPM remediation testing"
  vpc_id      = aws_vpc.cspm.id

  egress {
    description = "Allow outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "CSPM-Test-SSH-Public"
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
    Purpose     = "CSPM remediation demonstration"
    CSPMTest    = "true"
  }
}