resource "aws_s3_bucket" "cspm_demo" {
  bucket_prefix = "${var.project_name}-"

  tags = {
    Name    = "${var.project_name}-bucket"
    Project = var.project_name
  }
}

resource "aws_s3_bucket_public_access_block" "cspm_demo" {
  bucket = aws_s3_bucket.cspm_demo.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cspm_demo" {
  bucket = aws_s3_bucket.cspm_demo.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
