# ============================================================
# SecNet CSPM - Main Infrastructure
# ============================================================

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "ubuntu" {
  most_recent = true

  owners = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ============================================================
# VPC
# ============================================================

resource "aws_vpc" "cspm" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-VPC"
  }
}

# ============================================================
# Internet Gateway
# ============================================================

resource "aws_internet_gateway" "cspm" {
  vpc_id = aws_vpc.cspm.id

  tags = {
    Name = "${var.project_name}-IGW"
  }
}

# ============================================================
# PUBLIC SUBNET
# Existing CSPM EC2 remains here
#
# Existing:
# 10.0.1.0/24
# AZ-a
# ============================================================

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.cspm.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-Public-Subnet"
    Tier = "Public"
  }
}

# ============================================================
# PUBLIC ROUTE TABLE
# ============================================================

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.cspm.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.cspm.id
  }

  tags = {
    Name = "${var.project_name}-Public-RT"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ============================================================
# PRIVATE SUBNET - AZ A
#
# Intended for:
# - RDS
# - ECS
#
# CIDR:
# 10.0.10.0/24
# ============================================================

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.cspm.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project_name}-Private-Subnet-A"
    Tier = "Private"
    AZ   = "A"
  }
}

# ============================================================
# PRIVATE SUBNET - AZ B
#
# Intended for:
# - RDS
# - ECS
#
# CIDR:
# 10.0.11.0/24
# ============================================================

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.cspm.id
  cidr_block        = "10.0.11.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project_name}-Private-Subnet-B"
    Tier = "Private"
    AZ   = "B"
  }
}

# ============================================================
# PRIVATE ROUTE TABLE
#
# No Internet/NAT route.
#
# This keeps the 3-day lab cheap.
# ============================================================

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.cspm.id

  tags = {
    Name = "${var.project_name}-Private-RT"
  }
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}

# ============================================================
# SECURITY GROUP - CSPM EC2
#
# Existing workload.
# DO NOT REMOVE SSH.
# ============================================================

resource "aws_security_group" "cspm_ec2" {
  name        = "${var.project_name}-EC2-SG"
  description = "Security group for CSPM lab EC2"
  vpc_id      = aws_vpc.cspm.id

  ingress {
    description = "SSH for CSPM lab"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  ingress {
    description = "HTTP for CSPM lab"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-EC2-SG"
  }
}

# ============================================================
# CSPM LAB EC2
#
# Existing workload.
# ============================================================

resource "aws_instance" "cspm_lab" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.cspm_ec2.id]
  associate_public_ip_address = true

  root_block_device {
    encrypted = true
  }

  tags = {
    Name = "${var.project_name}-Lab-EC2"
  }
}

# ============================================================
# S3 - CSPM LAB
# ============================================================

resource "aws_s3_bucket" "cspm_lab" {
  bucket_prefix = "cspm-lab-"

  tags = {
    Name = "${var.project_name}-S3"
  }
}

# ============================================================
# S3 - CSPM TEST
# ============================================================

resource "aws_s3_bucket" "cspm_test" {
  bucket_prefix = "cspm-test-"

  tags = {
    Name = "${var.project_name}-Test-S3"
  }
}