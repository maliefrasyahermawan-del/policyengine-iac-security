from typing import Any

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def merge_results(checkov_result: dict, opa_result: dict) -> dict:
    all_findings = []

    checkov_findings = checkov_result.get("findings", [])
    opa_findings = opa_result.get("findings", [])

    all_findings.extend(checkov_findings)
    all_findings.extend(opa_findings)

    all_findings = _deduplicate(all_findings)
    all_findings = _enrich_severity(all_findings)
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 4))

    severity_counts = _count_by_severity(all_findings)
    scanner_counts = _count_by_scanner(all_findings)

    has_critical = severity_counts.get("CRITICAL", 0) > 0
    has_high = severity_counts.get("HIGH", 0) > 0
    allow_deploy = not (has_critical or has_high)

    checkov_summary = checkov_result.get("summary", {})
    opa_summary = opa_result.get("summary", {})

    return {
        "allow_deploy": allow_deploy,
        "total_violations": len(all_findings),
        "severity_counts": severity_counts,
        "scanner_counts": scanner_counts,
        "findings": all_findings,
        "checkov_summary": checkov_summary,
        "opa_summary": opa_summary,
        "errors": _collect_errors(checkov_result, opa_result),
    }


def _deduplicate(findings: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for f in findings:
        key = (
            f.get("check_id", ""),
            f.get("resource", ""),
            f.get("message", "")[:80],
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


CHECKOV_SEVERITY_OVERRIDES = {
    "CKV_AWS_18": "MEDIUM",
    "CKV_AWS_19": "HIGH",
    "CKV_AWS_21": "MEDIUM",
    "CKV_AWS_52": "HIGH",
    "CKV_AWS_53": "MEDIUM",
    "CKV_AWS_54": "MEDIUM",
    "CKV_AWS_55": "HIGH",
    "CKV_AWS_56": "HIGH",
    "CKV_AWS_57": "HIGH",
    "CKV_AWS_66": "HIGH",
    "CKV_AWS_67": "HIGH",
    "CKV_AWS_91": "MEDIUM",
    "CKV_AWS_145": "HIGH",
    "CKV2_AWS_6": "HIGH",
    "CKV_DOCKER_1": "CRITICAL",
    "CKV_DOCKER_2": "HIGH",
    "CKV_DOCKER_3": "HIGH",
    "CKV_DOCKER_4": "MEDIUM",
    "CKV_DOCKER_7": "HIGH",
    "CKV_DOCKER_8": "MEDIUM",
}

KEYWORD_SEVERITY = {
    "CRITICAL": ["wildcard", "0.0.0.0/0", "ssh from anywhere", "rdp from anywhere", "privileged mode", "publicly accessible"],
    "HIGH": ["encrypt", "no encryption", "root user", "admin", "password", "secret", "storage_encrypted"],
    "MEDIUM": ["tag", "version", "logging", "backup", "retention", "limit", "mfa"],
    "LOW": ["description", "comment", "naming"],
}


def _enrich_severity(findings: list[dict]) -> list[dict]:
    for f in findings:
        if f.get("severity") not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            check_id = f.get("check_id", "")
            if check_id in CHECKOV_SEVERITY_OVERRIDES:
                f["severity"] = CHECKOV_SEVERITY_OVERRIDES[check_id]
                continue

            msg = (f.get("message", "") + " " + f.get("description", "")).lower()
            assigned = False
            for sev, keywords in KEYWORD_SEVERITY.items():
                if any(k in msg for k in keywords):
                    f["severity"] = sev
                    assigned = True
                    break
            if not assigned:
                f["severity"] = "MEDIUM"
        else:
            check_id = f.get("check_id", "")
            if check_id in CHECKOV_SEVERITY_OVERRIDES:
                f["severity"] = CHECKOV_SEVERITY_OVERRIDES[check_id]
    return findings


def _count_by_severity(findings: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _count_by_scanner(findings: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        scanner = f.get("scanner", "unknown")
        counts[scanner] = counts.get(scanner, 0) + 1
    return counts


def _collect_errors(checkov_result: dict, opa_result: dict) -> list[dict]:
    errors = []
    if checkov_result.get("error"):
        errors.append({"scanner": "checkov", "error": checkov_result["error"], "message": checkov_result.get("message", "")})
    if opa_result.get("error"):
        errors.append({"scanner": "opa", "error": opa_result["error"], "message": opa_result.get("message", "")})
    return errors
