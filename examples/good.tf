# examples/good.tf — properly configured Terraform that passes all packs.
# Run: raksha scan examples/good.tf --rules generic,dpdpa,rbi

# ---------------------------------------------------------------------------
# Bucket for personal data — DPDPA-compliant
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "user_data" {
  bucket = "infraverse-user-personal-data"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.data_key.arn
      }
    }
  }

  lifecycle_rule {
    id      = "expire-after-retention-period"
    enabled = true
    expiration {
      days = 730  # aligned with documented retention period
    }
  }

  tags = {
    Project              = "InfraVerse"
    Env                  = "production"
    data_classification  = "personal"
    consent_basis        = "explicit"
    audit_logging        = "enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "user_data" {
  bucket                  = aws_s3_bucket.user_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# RDS for sensitive personal data — Indian region, encrypted, DPIA done
# ---------------------------------------------------------------------------
resource "aws_db_instance" "customer_pii" {
  identifier        = "customer-pii"
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  allocated_storage = 100
  region            = "ap-south-1"     # Mumbai

  storage_encrypted = true
  kms_key_id        = aws_kms_key.data_key.arn

  tags = {
    data_classification              = "sensitive_personal"
    consent_basis                    = "legitimate_use"
    audit_logging                    = "enabled"
    dpia_completed                   = "2026-04-15"
    cross_border_transfer_approved   = "false"
  }
}

# ---------------------------------------------------------------------------
# Restricted security group
# ---------------------------------------------------------------------------
resource "aws_security_group" "internal" {
  name = "internal-ssh"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

# ---------------------------------------------------------------------------
# CloudWatch log group with 7-year retention
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "app_logs" {
  name              = "/infraverse/app"
  retention_in_days = 2555   # 7 years for RBI-regulated workloads

  tags = {
    regulated_entity = "rbi"
  }
}

# ---------------------------------------------------------------------------
# KMS with rotation
# ---------------------------------------------------------------------------
resource "aws_kms_key" "data_key" {
  description             = "Data encryption key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

# ---------------------------------------------------------------------------
# Multi-region CloudTrail
# ---------------------------------------------------------------------------
resource "aws_cloudtrail" "audit" {
  name                          = "audit-trail"
  s3_bucket_name                = "audit-bucket"
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}
