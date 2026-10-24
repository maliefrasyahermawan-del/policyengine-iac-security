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

# VULN: S3 bucket without encryption, versioning, or public access block
resource "aws_s3_bucket" "data" {
  bucket = "my-insecure-bucket"
  # MISSING: server_side_encryption_configuration
  # MISSING: versioning
  # No tags — violates tagging policy
}

# VULN: Security group with SSH and RDP open to the world
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Web server security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # VULN: SSH open to internet
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # VULN: RDP open to internet
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # No tags — violates tagging policy
}

# VULN: IAM policy with wildcard action and resource
resource "aws_iam_policy" "overprivileged" {
  name        = "admin-like-policy"
  description = "Overly permissive policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"    # VULN: wildcard action
        Resource = "*"    # VULN: wildcard resource
      }
    ]
  })
  # No tags
}

# VULN: RDS with encryption disabled and publicly accessible
resource "aws_db_instance" "database" {
  identifier          = "my-database"
  engine              = "postgres"
  engine_version      = "14"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = "hardcoded_password_123!" # VULN: hardcoded password
  storage_encrypted   = false                      # VULN: encryption disabled
  publicly_accessible = true                       # VULN: database publicly accessible
  skip_final_snapshot = true
  allocated_storage   = 20
  # No tags
  # No deletion_protection
}

# VULN: EBS volume without encryption
resource "aws_ebs_volume" "data_volume" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false # VULN: unencrypted EBS
  # No tags
}

# VULN: EC2 instance without proper tags and using insecure security group
resource "aws_instance" "web_server" {
  ami             = "ami-0c55b159cbfafe1f0"
  instance_type   = "t3.micro"
  security_groups = [aws_security_group.web.name]

  # No tags — violates tagging policy
  # No IMDSv2 configuration (metadata service without token)
}
