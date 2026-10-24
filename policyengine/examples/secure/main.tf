terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

locals {
  common_tags = {
    Environment = "production"
    Owner       = "platform-team"
    Project     = "myapp"
    CostCenter  = "engineering"
  }
}

# SECURE: S3 bucket with encryption and versioning
resource "aws_s3_bucket" "data" {
  bucket = "my-secure-bucket-unique-name"
  tags   = local.common_tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SECURE: Security group with restricted access
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Web server security group — HTTP/HTTPS only from internet"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # HTTP from internet is acceptable for web servers
    description = "HTTP from internet"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # HTTPS from internet
    description = "HTTPS from internet"
  }

  # SSH restricted to office/VPN IP only (not 0.0.0.0/0)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"] # Internal VPN range only
    description = "SSH from VPN only"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = local.common_tags
}

# SECURE: IAM policy with minimal required permissions
resource "aws_iam_policy" "app_policy" {
  name        = "app-minimal-policy"
  description = "Minimal policy for application — least privilege"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::my-secure-bucket-unique-name",
          "arn:aws:s3:::my-secure-bucket-unique-name/*"
        ]
      }
    ]
  })

  tags = local.common_tags
}

# SECURE: RDS with encryption, no public access, deletion protection
resource "aws_db_instance" "database" {
  identifier          = "my-secure-database"
  engine              = "postgres"
  engine_version      = "14"
  instance_class      = "db.t3.micro"
  username            = "dbadmin"
  password            = var.db_password # from variable — not hardcoded
  storage_encrypted   = true            # SECURE: encryption enabled
  publicly_accessible = false           # SECURE: no public access
  deletion_protection = true            # SECURE: prevent accidental deletion
  skip_final_snapshot = false
  allocated_storage   = 20
  multi_az            = true            # SECURE: high availability

  backup_retention_period = 7
  backup_window           = "03:00-04:00"

  tags = local.common_tags
}

variable "db_password" {
  description = "Database master password"
  type        = string
  sensitive   = true
}

# SECURE: EBS volume with encryption
resource "aws_ebs_volume" "data_volume" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true   # SECURE: encryption enabled
  kms_key_id        = aws_kms_key.ebs.arn
  tags              = local.common_tags
}

resource "aws_kms_key" "ebs" {
  description             = "KMS key for EBS encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = local.common_tags
}

# SECURE: EC2 instance with proper tags and IMDSv2
resource "aws_instance" "web_server" {
  ami             = "ami-0c55b159cbfafe1f0"
  instance_type   = "t3.micro"
  security_groups = [aws_security_group.web.name]

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 required
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted = true
  }

  tags = local.common_tags
}
