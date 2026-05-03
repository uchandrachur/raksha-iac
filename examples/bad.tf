# examples/bad.tf — intentionally insecure Terraform for demo purposes.
# Run: raksha scan examples/bad.tf --rules generic,dpdpa,rbi

# ---------------------------------------------------------------------------
# Bucket holding personal data — multiple DPDPA + generic violations
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "user_data" {
  bucket = "infraverse-user-personal-data"
  acl    = "public-read"

  # Missing: server_side_encryption_configuration  → GEN-003, DPDPA-002
  # Missing: lifecycle_rule                         → DPDPA-004
  # Missing: data_classification tag                → DPDPA-005
  # Missing: consent_basis tag                      → DPDPA-001
  # Missing: audit_logging tag                      → DPDPA-006

  tags = {
    Project = "InfraVerse"
    Env     = "production"
    # Note: NO data_classification tag — fires DPDPA-005
  }
}

# Public access block intentionally weakened
resource "aws_s3_bucket_public_access_block" "user_data" {
  bucket                  = aws_s3_bucket.user_data.id
  block_public_acls       = false   # GEN-001
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# ---------------------------------------------------------------------------
# RDS for sensitive personal data, deployed in us-east-1 (cross-border issue)
# ---------------------------------------------------------------------------
resource "aws_db_instance" "customer_pii" {
  identifier        = "customer-pii"
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  allocated_storage = 100
  region            = "us-east-1"

  # Missing: storage_encrypted = true               → GEN-006, DPDPA-002
  # Wrong region for personal data without approval → DPDPA-003

  tags = {
    data_classification = "sensitive_personal"
    # Missing: dpia_completed                       → DPDPA-007
    # Missing: cross_border_transfer_approved       → DPDPA-003
    # Missing: regulated_entity (would fire RBI rules if present)
  }
}

# ---------------------------------------------------------------------------
# Open security group on SSH — generic rule
# ---------------------------------------------------------------------------
resource "aws_security_group" "public" {
  name = "public-ssh"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # GEN-005
  }
}

# ---------------------------------------------------------------------------
# CloudWatch log group with too-short retention — CERT-In violation
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "app_logs" {
  name              = "/infraverse/app"
  retention_in_days = 30   # CERTIN-001 (need >= 180)

  tags = {
    regulated_entity = "rbi"   # → also fires RBI-003 (need 2555 days)
  }
}

# ---------------------------------------------------------------------------
# KMS key without rotation
# ---------------------------------------------------------------------------
resource "aws_kms_key" "data_key" {
  description = "Data encryption key"
  # Missing: enable_key_rotation = true  → GEN-008
}

# ---------------------------------------------------------------------------
# CloudTrail not multi-region
# ---------------------------------------------------------------------------
resource "aws_cloudtrail" "audit" {
  name           = "audit-trail"
  s3_bucket_name = "audit-bucket"
  # Missing: is_multi_region_trail = true  → GEN-007
}
