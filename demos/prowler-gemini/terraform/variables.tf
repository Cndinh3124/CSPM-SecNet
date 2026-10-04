variable "aws_region" {
  description = "AWS region used for the SecNet CSPM demonstration environment"
  type        = string
  default     = "ap-southeast-1"
}

variable "project_name" {
  description = "Name of the SecNet CSPM demonstration project"
  type        = string
  default     = "secnet-cspm-demo"
}

variable "vpc_cidr" {
  description = "CIDR block of the demonstration VPC"
  type        = string
  default     = "10.10.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block of the public subnet"
  type        = string
  default     = "10.10.1.0/24"
}

variable "private_subnet_1_cidr" {
  description = "CIDR block of the first private subnet"
  type        = string
  default     = "10.10.2.0/24"
}

variable "private_subnet_2_cidr" {
  description = "CIDR block of the second private subnet"
  type        = string
  default     = "10.10.3.0/24"
}

variable "public_availability_zone" {
  description = "Availability Zone for the public subnet"
  type        = string
  default     = "ap-southeast-1a"
}

variable "private_availability_zone_1" {
  description = "Availability Zone for the first private subnet"
  type        = string
  default     = "ap-southeast-1a"
}

variable "private_availability_zone_2" {
  description = "Availability Zone for the second private subnet"
  type        = string
  default     = "ap-southeast-1b"
}

variable "ec2_instance_type" {
  description = "EC2 instance type used for the demonstration"
  type        = string
  default     = "t3.micro"
}

variable "ssh_ingress_cidr" {
  description = "CIDR allowed to access SSH on the EC2 security group"
  type        = string
  default     = "10.10.1.0/24"
}

variable "db_name" {
  description = "Initial database name"
  type        = string
  default     = "secnetdemo"
}

variable "db_username" {
  description = "RDS master username"
  type        = string
  default     = "secnetadmin"
}

variable "db_instance_class" {
  description = "RDS instance class used for the demonstration"
  type        = string
  default     = "db.t3.micro"
}
