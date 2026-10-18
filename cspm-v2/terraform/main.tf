resource "aws_vpc" "cspm_demo" {
  cidr_block           = "10.60.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name      = "${var.project_name}-Demo-VPC"
    CSPMScope = "demo"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.cspm_demo.id
  cidr_block              = "10.60.1.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name      = "${var.project_name}-Public-Subnet"
    CSPMScope = "demo"
  }
}

resource "aws_internet_gateway" "demo" {
  vpc_id = aws_vpc.cspm_demo.id

  tags = {
    Name = "${var.project_name}-IGW"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.cspm_demo.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.demo.id
  }

  tags = {
    Name = "${var.project_name}-Public-RT"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "demo" {
  name        = "${var.project_name}-Demo-SG"
  description = "Security Group for the CSPM EC2 demonstration."
  vpc_id      = aws_vpc.cspm_demo.id

  # Default egress permits outbound traffic for SSM connectivity.
  # No inbound rules unless an explicit test rule is enabled.

  tags = {
    Name       = "${var.project_name}-Demo-SG"
    CSPMScope  = "demo"
    CSPMTarget = "true"
  }
}

# Deliberately create a public SSH finding only when explicitly enabled.
resource "aws_vpc_security_group_ingress_rule" "ssh_test" {
  count = var.enable_public_ssh_test ? 1 : 0

  security_group_id = aws_security_group.demo.id
  description       = "INTENTIONAL TEST: public SSH finding for Prowler."
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    CSPMScenario = "public-ssh"
    CSPMScope    = "demo"
  }
}

resource "aws_iam_role" "ec2_ssm" {
  name = "${var.project_name}-EC2-SSM-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Project = var.project_name
  }
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ec2_ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_ssm" {
  name = "${var.project_name}-EC2-SSM-Profile"
  role = aws_iam_role.ec2_ssm.name
}

resource "aws_instance" "demo" {
  ami                         = "ami-09fad7bb72d4e6685"
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.demo.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_ssm.name
  associate_public_ip_address = true

  root_block_device {
    encrypted             = true
    volume_size           = 8
    volume_type           = "gp3"
    delete_on_termination = true
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  depends_on = [
    aws_route_table_association.public,
    aws_iam_role_policy_attachment.ssm_core
  ]

  tags = {
    Name       = "${var.project_name}-Ubuntu-Demo"
    Project    = var.project_name
    CSPMScope  = "demo"
    CSPMTarget = "true"
  }
}
resource "aws_vpc_security_group_egress_rule" "https_outbound" {
  security_group_id = aws_security_group.demo.id

  description = "Allow outbound HTTPS for AWS Systems Manager and updates"
  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "tcp"
  from_port   = 443
  to_port     = 443

  tags = {
    CSPMScope = "demo"
  }
}


output "vpc_id" {
  value = aws_vpc.cspm_demo.id
}

output "subnet_id" {
  value = aws_subnet.public.id
}

output "security_group_id" {
  value = aws_security_group.demo.id
}

output "instance_id" {
  value = aws_instance.demo.id
}

output "instance_public_ip" {
  value = aws_instance.demo.public_ip
}
