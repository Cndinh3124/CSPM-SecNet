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

resource "aws_vpc" "cspm" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-VPC"
  }
}

resource "aws_internet_gateway" "cspm" {
  vpc_id = aws_vpc.cspm.id

  tags = {
    Name = "${var.project_name}-IGW"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.cspm.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-Public-Subnet"
  }
}

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

resource "aws_s3_bucket" "cspm_lab" {
  bucket_prefix = "cspm-lab-"

  tags = {
    Name = "${var.project_name}-S3"
  }
}

resource "aws_s3_bucket" "cspm_test" {
  bucket_prefix = "cspm-test-"

  tags = {
    Name = "${var.project_name}-Test-S3"
  }
}
