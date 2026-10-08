variable "aws_region" { type=string default="ap-southeast-1" }
variable "project_name" { type=string default="SecNet-CSPM" }
variable "environment" { type=string default="lab" }
variable "vpc_cidr" { type=string default="10.50.0.0/16" }
variable "allowed_ssh_cidr" { type=string default="10.50.0.0/16" }
variable "enable_public_ssh_test" { type=bool default=false }
variable "enable_public_s3_test" { type=bool default=false }
