output "vpc_id" {
  description = "ID of the demonstration VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_id" {
  description = "ID of the public subnet"
  value       = aws_subnet.public.id
}

output "private_subnet_1_id" {
  description = "ID of the first private subnet"
  value       = aws_subnet.private_1.id
}

output "private_subnet_2_id" {
  description = "ID of the second private subnet"
  value       = aws_subnet.private_2.id
}

output "ec2_instance_id" {
  description = "ID of the demonstration EC2 instance"
  value       = aws_instance.web.id
}

output "ec2_public_ip" {
  description = "Public IP of the demonstration EC2 instance"
  value       = aws_instance.web.public_ip
}

output "ec2_public_dns" {
  description = "Public DNS of the demonstration EC2 instance"
  value       = aws_instance.web.public_dns
}

output "s3_bucket_name" {
  description = "Name of the CSPM demonstration S3 bucket"
  value       = aws_s3_bucket.cspm_demo.id
}

output "cloudtrail_bucket_name" {
  description = "Name of the CloudTrail S3 bucket"
  value       = aws_s3_bucket.cloudtrail.id
}

output "rds_endpoint" {
  description = "RDS endpoint"
  value       = aws_db_instance.mysql.address
}

output "rds_identifier" {
  description = "RDS instance identifier"
  value       = aws_db_instance.mysql.identifier
}
