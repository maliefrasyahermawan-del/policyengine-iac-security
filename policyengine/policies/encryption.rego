package terraform.encryption

import future.keywords.in

# Deny S3 buckets without server-side encryption
deny[msg] {
	resource := input.resource.aws_s3_bucket[name]
	not resource.server_side_encryption_configuration
	msg := sprintf("S3 bucket '%v' does not have server-side encryption configured. Add server_side_encryption_configuration block.", [name])
}

# Deny RDS instances with storage_encrypted = false
deny[msg] {
	resource := input.resource.aws_db_instance[name]
	resource.storage_encrypted == false
	msg := sprintf("RDS instance '%v' has encryption disabled (storage_encrypted = false). Set storage_encrypted = true.", [name])
}

# Deny EBS volumes without encryption
deny[msg] {
	resource := input.resource.aws_ebs_volume[name]
	not resource.encrypted
	msg := sprintf("EBS volume '%v' is not encrypted. Set encrypted = true.", [name])
}

# Deny EBS volumes with explicit encrypted = false
deny[msg] {
	resource := input.resource.aws_ebs_volume[name]
	resource.encrypted == false
	msg := sprintf("EBS volume '%v' has encryption explicitly disabled. Set encrypted = true.", [name])
}

# Deny RDS without deletion protection (protects against accidental data loss)
deny[msg] {
	resource := input.resource.aws_db_instance[name]
	not resource.deletion_protection
	msg := sprintf("RDS instance '%v' does not have deletion protection enabled. Set deletion_protection = true.", [name])
}

# Deny SNS topics without encryption
deny[msg] {
	resource := input.resource.aws_sns_topic[name]
	not resource.kms_master_key_id
	msg := sprintf("SNS topic '%v' is not encrypted with KMS. Set kms_master_key_id to a valid KMS key ARN.", [name])
}
