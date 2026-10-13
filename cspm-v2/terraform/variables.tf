variable "aws_region" {
  type        = string
  description = "AWS region for the CSPM demonstration."
  default     = "ap-southeast-1"
}

variable "project_name" {
  type        = string
  description = "Project identifier used in the Security Group name and tags."
  default     = "SecNet-CSPM"
}

variable "allowed_ssh_cidr" {
  type        = string
  description = "Trusted IPv4 CIDR used when the intentional public SSH finding is disabled."
  type        = string
  default     = "10.50.0.0/16"
}

variable "enable_public_ssh_test" {
  type        = bool
  description = "Intentionally allow SSH from the Internet to create a real Prowler finding. No EC2 is attached."
  default     = true
}
