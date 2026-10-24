package terraform.network_security

import future.keywords.in

# Deny SSH (port 22) open to the entire internet
deny[msg] {
	resource := input.resource.aws_security_group[name]
	rule := resource.ingress[_]
	rule.cidr_blocks[_] == "0.0.0.0/0"
	rule.from_port <= 22
	rule.to_port >= 22
	msg := sprintf("Security group '%v' allows SSH (port 22) from anywhere (0.0.0.0/0). Restrict to specific IP ranges.", [name])
}

# Deny RDP (port 3389) open to the entire internet
deny[msg] {
	resource := input.resource.aws_security_group[name]
	rule := resource.ingress[_]
	rule.cidr_blocks[_] == "0.0.0.0/0"
	rule.from_port <= 3389
	rule.to_port >= 3389
	msg := sprintf("Security group '%v' allows RDP (port 3389) from anywhere (0.0.0.0/0). Restrict to specific IP ranges.", [name])
}

# Deny any port open to IPv6 internet
deny[msg] {
	resource := input.resource.aws_security_group[name]
	rule := resource.ingress[_]
	rule.ipv6_cidr_blocks[_] == "::/0"
	msg := sprintf("Security group '%v' has ingress rule open to all IPv6 addresses (::/0).", [name])
}

# Deny database port 3306 (MySQL) open to the internet
deny[msg] {
	resource := input.resource.aws_security_group[name]
	rule := resource.ingress[_]
	rule.cidr_blocks[_] == "0.0.0.0/0"
	rule.from_port <= 3306
	rule.to_port >= 3306
	msg := sprintf("Security group '%v' allows MySQL port (3306) from anywhere. Databases must not be publicly accessible.", [name])
}

# Deny database port 5432 (PostgreSQL) open to the internet
deny[msg] {
	resource := input.resource.aws_security_group[name]
	rule := resource.ingress[_]
	rule.cidr_blocks[_] == "0.0.0.0/0"
	rule.from_port <= 5432
	rule.to_port >= 5432
	msg := sprintf("Security group '%v' allows PostgreSQL port (5432) from anywhere. Databases must not be publicly accessible.", [name])
}

# Deny wide port ranges open to the internet (e.g., 0-65535)
deny[msg] {
	resource := input.resource.aws_security_group[name]
	rule := resource.ingress[_]
	rule.cidr_blocks[_] == "0.0.0.0/0"
	rule.from_port == 0
	rule.to_port == 65535
	msg := sprintf("Security group '%v' allows ALL ports from anywhere (0.0.0.0/0). This is a critical misconfiguration.", [name])
}
