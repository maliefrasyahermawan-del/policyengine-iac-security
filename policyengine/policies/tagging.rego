package terraform.tagging

import future.keywords.in

required_tags := {"Environment", "Owner", "Project"}

# Deny AWS resources without required tags
deny[msg] {
	resource := input.resource.aws_instance[name]
	missing := required_tags - {tag | resource.tags[tag]}
	count(missing) > 0
	msg := sprintf("EC2 instance '%v' is missing required tags: %v", [name, missing])
}

deny[msg] {
	resource := input.resource.aws_s3_bucket[name]
	not resource.tags
	msg := sprintf("S3 bucket '%v' has no tags. Required tags: %v", [name, required_tags])
}

deny[msg] {
	resource := input.resource.aws_s3_bucket[name]
	resource.tags
	missing := required_tags - {tag | resource.tags[tag]}
	count(missing) > 0
	msg := sprintf("S3 bucket '%v' is missing required tags: %v", [name, missing])
}

deny[msg] {
	resource := input.resource.aws_db_instance[name]
	not resource.tags
	msg := sprintf("RDS instance '%v' has no tags. Required tags: %v", [name, required_tags])
}

deny[msg] {
	resource := input.resource.aws_security_group[name]
	not resource.tags
	msg := sprintf("Security group '%v' has no tags. At minimum add an Owner tag for accountability.", [name])
}

deny[msg] {
	resource := input.resource.aws_iam_policy[name]
	not resource.tags
	msg := sprintf("IAM policy '%v' has no tags. Add tags for cost tracking and ownership.", [name])
}
