# Checkov targets — Terraform IaC misconfigurations
# WARNING: Intentionally insecure infrastructure for scanner testing

provider "aws" {
  region = "us-east-1"
}

# CKV_AWS_18: S3 bucket without access logging
# CKV_AWS_19: S3 bucket without encryption
# CKV_AWS_21: S3 bucket without versioning
resource "aws_s3_bucket" "data" {
  bucket = "my-vulnerable-bucket"
  acl    = "public-read"

  tags = {
    Environment = "test"
  }
}

# CKV_AWS_24: Security group with unrestricted ingress
resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# CKV_AWS_79: EC2 instance without metadata service v2
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  tags = {
    Name = "vulnerable-instance"
  }
}

# CKV_AWS_145: RDS without encryption
resource "aws_db_instance" "database" {
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  username             = "admin"
  password             = "plaintext-password-123"
  publicly_accessible  = true
  skip_final_snapshot  = true
  storage_encrypted    = false
}
