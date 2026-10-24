package docker.container_security

import future.keywords.in

# Deny containers running in privileged mode
deny[msg] {
	service := input.services[name]
	service.privileged == true
	msg := sprintf("Service '%v' runs in privileged mode. Remove 'privileged: true' and use cap_add for specific capabilities instead.", [name])
}

# Deny containers explicitly running as root
deny[msg] {
	service := input.services[name]
	service.user == "root"
	msg := sprintf("Service '%v' explicitly runs as root user. Use a non-root user (e.g., user: '1000:1000').", [name])
}

# Deny containers with hardcoded passwords in environment variables
deny[msg] {
	service := input.services[name]
	env := service.environment[_]
	contains(lower(env), "password=")
	not startswith(env, "PASSWORD=${")
	not startswith(env, "DB_PASSWORD=${")
	msg := sprintf("Service '%v' appears to have a hardcoded password in environment variables. Use Docker secrets or environment variable substitution from .env file.", [name])
}

# Deny containers with hardcoded secrets/keys in environment variables
deny[msg] {
	service := input.services[name]
	env := service.environment[_]
	contains(lower(env), "secret=")
	not contains(env, "${")
	msg := sprintf("Service '%v' appears to have a hardcoded secret in environment variables. Use Docker secrets or vault integration.", [name])
}

# Warn containers without resource limits (memory/cpu)
deny[msg] {
	service := input.services[name]
	not service.deploy.resources.limits
	msg := sprintf("Service '%v' has no resource limits defined. Add deploy.resources.limits to prevent resource exhaustion.", [name])
}

# Deny containers with network_mode host (bypasses network isolation)
deny[msg] {
	service := input.services[name]
	service.network_mode == "host"
	msg := sprintf("Service '%v' uses host network mode, bypassing Docker network isolation. Use bridge networking instead.", [name])
}
