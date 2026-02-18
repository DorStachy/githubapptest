# ─────────────────────────────────────────────────────────────────
# Terraform AWS infra — INTENTIONALLY VULNERABLE for CodeFence testing.
#
# Covers: public S3, open security groups, no encryption at rest,
#         overly permissive IAM, missing VPC flow logs, hardcoded creds,
#         unencrypted RDS, public EC2, no access logging, and SAFE counterparts.
# ─────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"          # CRITICAL: hardcoded credentials
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # CRITICAL
}

# ══════════════════════ S3 ═══════════════════════════════════════

# ─── PUBLIC BUCKET — NO ENCRYPTION (CRITICAL) ──────────────────
resource "aws_s3_bucket" "public_data" {
  bucket = "company-public-data-2026"
  acl    = "public-read"

  tags = { Environment = "production" }
}

# ─── BUCKET WITHOUT VERSIONING (MEDIUM) ────────────────────────
resource "aws_s3_bucket" "logs" {
  bucket = "company-internal-logs"
  # Missing: versioning, lifecycle, encryption
}

# ─── SAFE BUCKET (no vuln) ─────────────────────────────────────
resource "aws_s3_bucket" "private_safe" {
  bucket = "company-private-safe"
}

resource "aws_s3_bucket_versioning" "private_safe" {
  bucket = aws_s3_bucket.private_safe.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "private_safe" {
  bucket = aws_s3_bucket.private_safe.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "private_safe" {
  bucket                  = aws_s3_bucket.private_safe.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ══════════════════════ EC2 / NETWORKING ═════════════════════════

# ─── OPEN SECURITY GROUP (CRITICAL) ───────────────────────────
resource "aws_security_group" "allow_all" {
  name        = "allow-everything"
  description = "DO NOT USE IN PRODUCTION"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]    # Open to the entire internet
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ─── SSH-ONLY SG (MEDIUM — port 22 exposed) ───────────────────
resource "aws_security_group" "ssh_only" {
  name = "ssh-access"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]    # SSH from everywhere
  }
}

# ─── SAFE SECURITY GROUP (no vuln) ────────────────────────────
resource "aws_security_group" "restricted" {
  name = "restricted-access"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Private network only
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ─── EC2 WITHOUT IMDSV2 (HIGH) ───────────────────────────────
resource "aws_instance" "web" {
  ami                    = "ami-0abcdef1234567890"
  instance_type          = "t3.medium"
  vpc_security_group_ids = [aws_security_group.allow_all.id]
  associate_public_ip_address = true

  # Missing: metadata_options to enforce IMDSv2
  # Missing: ebs encryption

  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="production-db-password-plain"
    echo "Starting app..."
  EOF
}

# ─── SAFE EC2 (no vuln) ──────────────────────────────────────
resource "aws_instance" "web_safe" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.medium"
  vpc_security_group_ids = [aws_security_group.restricted.id]

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"      # IMDSv2 enforced
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted = true
  }
}

# ══════════════════════ RDS ══════════════════════════════════════

# ─── PUBLIC RDS, NO ENCRYPTION (CRITICAL) ─────────────────────
resource "aws_db_instance" "main" {
  identifier        = "prod-database"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.medium"
  allocated_storage = 100
  username          = "admin"
  password          = "SuperSecret123!"           # CRITICAL: hardcoded
  publicly_accessible = true                       # CRITICAL: internet-facing
  storage_encrypted   = false                      # HIGH: no encryption at rest
  skip_final_snapshot = true
  multi_az            = false                      # LOW: no HA

  # Missing: backup_retention_period, deletion_protection
}

# ─── SAFE RDS (no vuln) ──────────────────────────────────────
resource "aws_db_instance" "safe" {
  identifier          = "prod-database-safe"
  engine              = "mysql"
  engine_version      = "8.0"
  instance_class      = "db.t3.medium"
  allocated_storage   = 100
  username            = "admin"
  password            = var.db_password
  publicly_accessible = false
  storage_encrypted   = true
  multi_az            = true
  backup_retention_period = 7
  deletion_protection     = true
  skip_final_snapshot     = false
}

variable "db_password" {
  type      = string
  sensitive = true
}

# ══════════════════════ IAM ══════════════════════════════════════

# ─── OVERLY PERMISSIVE IAM POLICY (CRITICAL) ─────────────────
resource "aws_iam_policy" "admin_like" {
  name   = "too-permissive"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# ─── IAM WITH WILDCARD RESOURCE (HIGH) ───────────────────────
resource "aws_iam_policy" "s3_wildcard" {
  name   = "s3-too-broad"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
      Resource = "*"
    }]
  })
}

# ─── SAFE IAM POLICY (no vuln) ───────────────────────────────
resource "aws_iam_policy" "s3_scoped" {
  name   = "s3-scoped"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::company-private-safe/*"
    }]
  })
}

# ══════════════════════ CLOUDWATCH / LOGGING ═══════════════════

# ─── MISSING VPC FLOW LOGS (MEDIUM) ──────────────────────────
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  # Missing: aws_flow_log resource
}

# ─── ELB WITHOUT ACCESS LOGS (LOW) ──────────────────────────
resource "aws_lb" "app" {
  name               = "app-lb"
  internal           = false
  load_balancer_type = "application"
  # Missing: access_logs block
}
