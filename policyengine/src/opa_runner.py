import subprocess
import json
import shutil
from pathlib import Path


def is_conftest_available() -> bool:
    return shutil.which("conftest") is not None


def is_opa_available() -> bool:
    return shutil.which("opa") is not None


INSTALL_INSTRUCTIONS = (
    "conftest is not installed or not in PATH.\n"
    "Download from: https://github.com/open-policy-agent/conftest/releases\n"
    "Windows: download conftest_Windows_x86_64.zip, extract conftest.exe, place in PATH.\n"
    "Alternatively: place conftest.exe in the same folder as cli.py and add to PATH.\n\n"
    "OPA binary (optional, used by conftest internally):\n"
    "Download: https://github.com/open-policy-agent/opa/releases/latest/download/opa_windows_amd64.exe\n"
    "Rename to opa.exe and place in PATH."
)


def parse_conftest_output(data: list) -> dict:
    findings = []
    summary = {"total_passed": 0, "total_failed": 0, "total_warnings": 0}

    for result in data:
        if not isinstance(result, dict):
            continue

        filename = result.get("filename", "")

        for failure in result.get("failures", []):
            msg = failure.get("msg", "Policy violation")
            policy = failure.get("metadata", {}).get("policy", "")
            findings.append(
                {
                    "scanner": "opa",
                    "policy": policy,
                    "file": filename,
                    "message": msg,
                    "severity": _infer_severity(msg),
                    "status": "FAILED",
                    "check_id": _extract_check_id(msg),
                    "resource": _extract_resource(msg),
                    "guideline": "See policies/ directory for policy definition.",
                }
            )
            summary["total_failed"] += 1

        for warning in result.get("warnings", []):
            msg = warning.get("msg", "Policy warning")
            findings.append(
                {
                    "scanner": "opa",
                    "policy": warning.get("metadata", {}).get("policy", ""),
                    "file": filename,
                    "message": msg,
                    "severity": "LOW",
                    "status": "WARNING",
                    "check_id": _extract_check_id(msg),
                    "resource": _extract_resource(msg),
                    "guideline": "See policies/ directory for policy definition.",
                }
            )
            summary["total_warnings"] += 1

        for success in result.get("successes", []):
            summary["total_passed"] += 1

    return {"findings": findings, "summary": summary}


def _infer_severity(message: str) -> str:
    msg_lower = message.lower()
    if any(k in msg_lower for k in ["wildcard", "0.0.0.0/0", "ssh", "rdp", "publicly accessible", "privileged"]):
        return "CRITICAL"
    if any(k in msg_lower for k in ["encrypt", "password", "secret", "root user", "admin"]):
        return "HIGH"
    if any(k in msg_lower for k in ["tag", "version", "limit", "readonly"]):
        return "MEDIUM"
    return "LOW"


def _extract_check_id(message: str) -> str:
    keywords = {
        "ssh": "OPA-NET-001",
        "rdp": "OPA-NET-002",
        "0.0.0.0/0": "OPA-NET-003",
        "encrypt": "OPA-ENC-001",
        "wildcard": "OPA-IAM-001",
        "privileged": "OPA-CONT-001",
        "root": "OPA-CONT-002",
        "password": "OPA-CONT-003",
        "tag": "OPA-TAG-001",
        "publicly accessible": "OPA-NET-004",
    }
    msg_lower = message.lower()
    for keyword, check_id in keywords.items():
        if keyword in msg_lower:
            return check_id
    return "OPA-CUSTOM"


def _extract_resource(message: str) -> str:
    import re
    match = re.search(r"'([^']+)'", message)
    if match:
        return match.group(1)
    return "unknown"


def run_conftest(file_path: str, policy_dir: str = "policies/") -> dict:
    if not is_conftest_available():
        return {
            "error": "conftest_not_found",
            "message": INSTALL_INSTRUCTIONS,
            "findings": [],
            "summary": {"total_passed": 0, "total_failed": 0, "total_warnings": 0},
        }

    if not Path(file_path).exists():
        return {
            "error": "file_not_found",
            "message": f"File not found: {file_path}",
            "findings": [],
            "summary": {"total_passed": 0, "total_failed": 0, "total_warnings": 0},
        }

    policy_path = Path(policy_dir)
    if not policy_path.exists():
        return {
            "error": "policy_dir_not_found",
            "message": f"Policy directory not found: {policy_dir}",
            "findings": [],
            "summary": {"total_passed": 0, "total_failed": 0, "total_warnings": 0},
        }

    file_ext = Path(file_path).suffix.lower()
    parser_flag = []
    if file_ext in [".tf", ".hcl"]:
        parser_flag = ["--parser", "hcl2"]
    elif file_ext in [".yml", ".yaml"]:
        parser_flag = ["--parser", "yaml"]

    cmd = (
        ["conftest", "test", file_path, "--policy", str(policy_path), "--output", "json"]
        + parser_flag
    )

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return {
            "error": "timeout",
            "message": "conftest timed out after 60 seconds.",
            "findings": [],
            "summary": {"total_passed": 0, "total_failed": 0, "total_warnings": 0},
        }
    except FileNotFoundError:
        return {
            "error": "conftest_not_found",
            "message": INSTALL_INSTRUCTIONS,
            "findings": [],
            "summary": {"total_passed": 0, "total_failed": 0, "total_warnings": 0},
        }

    stdout = result.stdout.strip()
    if not stdout:
        return {
            "error": "empty_output",
            "message": "conftest produced no output. Ensure policies are valid Rego.",
            "findings": [],
            "summary": {"total_passed": 0, "total_failed": 0, "total_warnings": 0},
        }

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return {
            "error": "invalid_json",
            "message": "conftest returned non-JSON output.",
            "raw": stdout[:500],
            "findings": [],
            "summary": {"total_passed": 0, "total_failed": 0, "total_warnings": 0},
        }

    parsed = parse_conftest_output(data)
    parsed["file"] = file_path
    return parsed
