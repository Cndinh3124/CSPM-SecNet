variable "aws_region" {
  type        = string
  description = "AWS region for the CSPM demonstration."
  default     = "ap-southeast-1"
}

variable "project_name" {
  type        = string
  description = "Project identifier."
  default     = "SecNet-CSPM"
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type for the demo."
  default     = "t3.micro"
}

variable "enable_public_ssh_test" {
  type        = bool
  description = "Enable intentionally insecure public SSH ingress for Prowler testing."
  default     = false
}
