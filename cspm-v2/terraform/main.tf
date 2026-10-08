data "aws_availability_zones" "available" { state="available" }
data "aws_ami" "ubuntu" {
 most_recent=true
 owners=["099720109477"]
 filter { name="name" values=["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"] }
 filter { name="architecture" values=["x86_64"] }
 filter { name="virtualization-type" values=["hvm"] }
}
resource "aws_vpc" "lab" { cidr_block=var.vpc_cidr enable_dns_support=true enable_dns_hostnames=true tags={Name=var.project_name} }
resource "aws_internet_gateway" "lab" { vpc_id=aws_vpc.lab.id tags={Name=var.project_name} }
resource "aws_subnet" "public_a" { vpc_id=aws_vpc.lab.id cidr_block="10.50.1.0/24" availability_zone=data.aws_availability_zones.available.names[0] map_public_ip_on_launch=true tags={Name="CSPM-Public-A" Tier="public"} }
resource "aws_subnet" "public_b" { vpc_id=aws_vpc.lab.id cidr_block="10.50.2.0/24" availability_zone=data.aws_availability_zones.available.names[1] map_public_ip_on_launch=true tags={Name="CSPM-Public-B" Tier="public"} }
resource "aws_route_table" "public" { vpc_id=aws_vpc.lab.id route { cidr_block="0.0.0.0/0" gateway_id=aws_internet_gateway.lab.id } tags={Name="CSPM-Public-RT"} }
resource "aws_route_table_association" "a" { subnet_id=aws_subnet.public_a.id route_table_id=aws_route_table.public.id }
resource "aws_route_table_association" "b" { subnet_id=aws_subnet.public_b.id route_table_id=aws_route_table.public.id }
resource "aws_security_group" "lab" {
 name="CSPM-Lab-SG" description="Controlled CSPM lab security group" vpc_id=aws_vpc.lab.id
 ingress { description="SSH CSPM test" protocol="tcp" from_port=22 to_port=22 cidr_blocks=var.enable_public_ssh_test ? ["0.0.0.0/0"] : [var.allowed_ssh_cidr] }
 ingress { description="HTTP lab" protocol="tcp" from_port=80 to_port=80 cidr_blocks=["0.0.0.0/0"] }
 egress { protocol="-1" from_port=0 to_port=0 cidr_blocks=["0.0.0.0/0"] }
 tags={Name="CSPM-Lab-SG" CSPMScope="lab"}
}
resource "aws_instance" "lab" {
 ami=data.aws_ami.ubuntu.id instance_type="t3.micro" subnet_id=aws_subnet.public_a.id vpc_security_group_ids=[aws_security_group.lab.id] associate_public_ip_address=true
 root_block_device { encrypted=true }
 tags={Name="CSPM-Lab-EC2" CSPMScope="lab"}
}
resource "aws_s3_bucket" "lab" { bucket_prefix="secnet-cspm-lab-" tags={Name="CSPM-Lab-S3" CSPMScope="lab"} }
resource "aws_s3_bucket_public_access_block" "lab" {
 bucket=aws_s3_bucket.lab.id
 block_public_acls=!var.enable_public_s3_test block_public_policy=!var.enable_public_s3_test ignore_public_acls=!var.enable_public_s3_test restrict_public_buckets=!var.enable_public_s3_test
}
output "vpc_id" { value=aws_vpc.lab.id }
output "ec2_instance_id" { value=aws_instance.lab.id }
output "security_group_id" { value=aws_security_group.lab.id }
output "s3_bucket_name" { value=aws_s3_bucket.lab.bucket }
