output "vpc_id" {
  description = "CSPM VPC ID"
  value       = aws_vpc.cspm.id
}

output "public_subnet_id" {
  description = "Public subnet ID"
  value       = aws_subnet.public.id
}

output "security_group_id" {
  description = "EC2 security group ID"
  value       = aws_security_group.cspm_ec2.id
}

output "ec2_id" {
  description = "CSPM lab EC2 instance ID"
  value       = aws_instance.cspm_lab.id
}

output "ec2_public_ip" {
  description = "Public IP of CSPM lab EC2"
  value       = aws_instance.cspm_lab.public_ip
}

output "s3_bucket_name" {
  description = "CSPM lab S3 bucket"
  value       = aws_s3_bucket.cspm_lab.id
}