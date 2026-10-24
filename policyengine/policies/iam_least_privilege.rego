package terraform.iam_least_privilege

import future.keywords.in

# Deny IAM policies with wildcard actions
deny[msg] {
	resource := input.resource.aws_iam_policy[name]
	policy_doc := json.unmarshal(resource.policy)
	statement := policy_doc.Statement[_]
	statement.Effect == "Allow"
	statement.Action == "*"
	msg := sprintf("IAM policy '%v' uses wildcard Action ('*'). Specify explicit actions following least-privilege principle.", [name])
}

# Deny IAM policies with array containing wildcard
deny[msg] {
	resource := input.resource.aws_iam_policy[name]
	policy_doc := json.unmarshal(resource.policy)
	statement := policy_doc.Statement[_]
	statement.Effect == "Allow"
	statement.Action[_] == "*"
	msg := sprintf("IAM policy '%v' includes wildcard action ('*') in Action array. Remove '*' and use specific actions.", [name])
}

# Deny IAM policies with wildcard resources
deny[msg] {
	resource := input.resource.aws_iam_policy[name]
	policy_doc := json.unmarshal(resource.policy)
	statement := policy_doc.Statement[_]
	statement.Effect == "Allow"
	statement.Resource == "*"
	statement.Action != "sts:AssumeRole"
	msg := sprintf("IAM policy '%v' uses wildcard Resource ('*'). Specify exact resource ARNs.", [name])
}

# Deny IAM roles with overly permissive trust policy (anyone can assume)
deny[msg] {
	resource := input.resource.aws_iam_role[name]
	policy := json.unmarshal(resource.assume_role_policy)
	statement := policy.Statement[_]
	statement.Effect == "Allow"
	statement.Principal == "*"
	msg := sprintf("IAM role '%v' allows any principal to assume it (Principal: '*'). Restrict to specific trusted accounts/services.", [name])
}

# Deny inline IAM policies on users (prefer managed policies)
deny[msg] {
	resource := input.resource.aws_iam_user_policy[name]
	msg := sprintf("Inline IAM policy '%v' found on user. Use managed policies attached via aws_iam_user_policy_attachment instead.", [name])
}
