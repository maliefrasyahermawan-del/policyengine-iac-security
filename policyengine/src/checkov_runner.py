import subprocess
import json
import shutil
from pathlib import Path


SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    "UNKNOWN": "MEDIUM",
}


def is_checkov_available() -> bool:
    return shutil.which("checkov") is not None


def parse_checkov_output(data: dict | list) -> dict:
    findings = []

    results_list = data if isinstance(data, list) else [data]

    for result_block in results_list:
        if not isinstance(result_block, dict):
            continue

        check_results = result_block.get("results", {})
        failed = check_results.get("failed_checks", [])
        passed = check_results.get("passed_checks", [])

        for check in failed:
            severity = SEVERITY_MAP.get(
                check.get("check_result", {}).get("severity", "UNKNOWN"), "MEDIUM"
            )
            findings.append(
                {
                    "scanner": "checkov",
                    "check_id": check.get("check_id", "UNKNOWN"),
                    "check_type": check.get("check_type", ""),
                    "resource": check.get("resource", ""),
                    "file": check.get("file_path", ""),
                    "line_range": check.get("file_line_range", []),
                    "severity": severity,
                    "message": check.get("check_result", {}).get(
                        "result", "FAILED"
                    ),
                    "description": check.get("short_description", ""),
                    "guideline": check.get("guideline", ""),
                    "status": "FAILED",
                }
            )

        summary = {
            "total_passed": len(passed),
            "total_failed": len(failed),
        }

    return {"findings": findings, "summary": summary if results_list else {}}


def run_checkov(file_path: str) -> dict:
    if not is_checkov_available():
        return {
            "error": "checkov_not_found",
            "message": (
                "Checkov is not installed or not in PATH.\n"
                "Install with: pip install checkov\n"
                "Then verify: checkov --version"
            ),
            "findings": [],
            "summary": {"total_passed": 0, "total_failed": 0},
        }

    if not Path(file_path).exists():
        return {
            "error": "file_not_found",
            "message": f"File not found: {file_path}",
            "findings": [],
            "summary": {"total_passed": 0, "total_failed": 0},
        }

    cmd = [
        "checkov",
        "-f",
        file_path,
        "--output",
        "json",
        "--compact",
        "--quiet",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return {
            "error": "timeout",
            "message": "Checkov timed out after 120 seconds.",
            "findings": [],
            "summary": {"total_passed": 0, "total_failed": 0},
        }
    except FileNotFoundError:
        return {
            "error": "checkov_not_found",
            "message": (
                "Checkov binary not found.\n"
                "Install with: pip install checkov"
            ),
            "findings": [],
            "summary": {"total_passed": 0, "total_failed": 0},
        }

    stdout = result.stdout.strip()
    if not stdout:
        return {
            "error": "empty_output",
            "message": "Checkov produced no output.",
            "findings": [],
            "summary": {"total_passed": 0, "total_failed": 0},
        }

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        lines = stdout.splitlines()
        for i, line in enumerate(lines):
            if line.strip().startswith("{") or line.strip().startswith("["):
                try:
                    data = json.loads("\n".join(lines[i:]))
                    break
                except json.JSONDecodeError:
                    continue
        else:
            return {
                "error": "invalid_json",
                "message": "Checkov returned non-JSON output.",
                "raw": stdout[:500],
                "findings": [],
                "summary": {"total_passed": 0, "total_failed": 0},
            }

    parsed = parse_checkov_output(data)
    parsed["file"] = file_path
    return parsed
