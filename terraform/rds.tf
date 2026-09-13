# ============================================================
# SecNet CSPM - RDS PostgreSQL
# ============================================================

# ============================================================
# RDS DB Subnet Group
# ============================================================

resource "aws_db_subnet_group" "secnet" {
  name        = "secnet-cspm-db-subnet-group"
  description = "Private subnet group for SecNet CSPM PostgreSQL"

  subnet_ids = [
    aws_subnet.private_a.id,
    aws_subnet.private_b.id
  ]

  tags = {
    Name        = "${var.project_name}-RDS-Subnet-Group"
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
    Purpose     = "SecNet PostgreSQL"
  }
}

# ============================================================
# RDS PostgreSQL
#
# Lab configuration:
# - Single AZ
# - Private
# - No public access
# - 20 GB storage
# ============================================================

resource "aws_db_instance" "secnet" {
  identifier = "secnet-cspm-postgres"

  engine         = "postgres"
  engine_version = "17"

  instance_class = "db.t4g.micro"

  allocated_storage     = 20
  max_allocated_storage = 20
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = "secnet_cspm"
  username = "secnet"

  manage_master_user_password = true

  db_subnet_group_name = aws_db_subnet_group.secnet.name

  vpc_security_group_ids = [
    aws_security_group.secnet_rds.id
  ]

  publicly_accessible = false

  multi_az = false

  backup_retention_period = 0

  deletion_protection = false

  skip_final_snapshot = true

  apply_immediately = true

  auto_minor_version_upgrade = true

  copy_tags_to_snapshot = true

  tags = {
    Name        = "${var.project_name}-RDS-PostgreSQL"
    Project     = "CSPM"
    Environment = "Lab"
    ManagedBy   = "Terraform"
    Purpose     = "SecNet CSPM Database"
  }
}