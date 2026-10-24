#!/usr/bin/env python3
"""PolicyEngine CLI — validate IaC files for security misconfigurations."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.checkov_runner import run_checkov, is_checkov_available
from src.opa_runner import run_conftest, is_conftest_available
from src.aggregator import merge_results
from src.remediation import enrich_findings_with_remediation
from src.report_generator import generate_reports

SEVERITY_ICONS = {
    "CRITICAL": "✗",
    "HIGH": "✗",
    "MEDIUM": "!",
    "LOW": "·",
    "INFO": "·",
}

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",   # bright red
    "HIGH": "\033[33m",       # yellow
    "MEDIUM": "\033[93m",     # bright yellow
    "LOW": "\033[32m",        # green
    "INFO": "\033[36m",       # cyan
}
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"


def color(text: str, code: str) -> str:
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass
    return f"{code}{text}{RESET}"


def print_separator(char="=", width=64):
    print(char * width)


def print_header(file_path: str):
    print_separator()
    print(color(f"  PolicyEngine Validation Report", BOLD))
    print_separator()
    print(f"  File: {file_path}")
    print()


def print_scanner_summary(checkov_result: dict, opa_result: dict):
    checkov_summary = checkov_result.get("summary", {})
    opa_summary = opa_result.get("summary", {})

    if checkov_result.get("error"):
        err_msg = checkov_result.get("message", "Checkov not available")
        first_line = err_msg.splitlines()[0]
        print(color(f"  [CHECKOV]  ⚠ Not available — {first_line}", "\033[33m"))
    else:
        failed = checkov_summary.get("total_failed", 0)
        passed = checkov_summary.get("total_passed", 0)
        status = color(f"{failed} failed", RED) if failed else color("0 failed", GREEN)
        print(f"  [CHECKOV]  {status}, {color(str(passed) + ' passed', GREEN)}")

    if opa_result.get("error"):
        err_msg = opa_result.get("message", "conftest not available")
        first_line = err_msg.splitlines()[0]
        print(color(f"  [OPA]      ⚠ Not available — {first_line}", "\033[33m"))
    else:
        violations = opa_summary.get("total_failed", 0)
        passed = opa_summary.get("total_passed", 0)
        status = color(f"{violations} violations", RED) if violations else color("0 violations", GREEN)
        print(f"  [OPA]      {status}, {color(str(passed) + ' passed', GREEN)}")

    print()


def print_findings_by_severity(findings: list[dict]):
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    grouped: dict[str, list] = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        grouped.setdefault(sev, []).append(f)

    for sev in severity_order:
        items = grouped.get(sev, [])
        if not items:
            continue

        sev_color = SEVERITY_COLORS.get(sev, "")
        print(color(f"  {sev} ({len(items)}):", sev_color + BOLD))

        for f in items:
            icon = SEVERITY_ICONS.get(sev, "!")
            scanner = f.get("scanner", "?").upper()
            resource = f.get("resource", "")
            message = f.get("message", "")
            check_id = f.get("check_id", "")

            resource_str = f" [{resource}]" if resource else ""
            check_str = f" ({check_id})" if check_id else ""
            print(color(f"    {icon} {message}{resource_str}{check_str}", sev_color))

            remediation = f.get("remediation", {})
            if remediation:
                fix = remediation.get("fix", "")
                if fix:
                    first_sentence = fix.split(".")[0] + "."
                    print(f"      → {first_sentence}")
                snippet = remediation.get("terraform_snippet", "")
                if snippet and len(snippet) < 120:
                    print(f"      \033[90m{snippet.splitlines()[0]}\033[0m")

        print()


def print_result_banner(allow_deploy: bool, merged: dict):
    print_separator()
    total = merged.get("total_violations", 0)
    critical = merged.get("severity_counts", {}).get("CRITICAL", 0)
    high = merged.get("severity_counts", {}).get("HIGH", 0)

    if allow_deploy:
        print(color(f"  RESULT: ✅ PASSED — {total} total violation(s), none blocking", GREEN + BOLD))
        print(color("  Deployment ALLOWED.", GREEN))
    else:
        print(color(f"  RESULT: ⛔ FAILED — {critical} critical, {high} high violation(s) found", RED + BOLD))
        print(color("  Deployment BLOCKED. Fix violations above before deploying.", RED))

    print_separator()


def validate(args):
    file_path = args.file
    policy_dir = args.policy_dir
    output_dir = args.output_dir
    use_ai = args.ai
    quiet = args.quiet

    if not Path(file_path).exists():
        print(color(f"Error: file not found: {file_path}", RED))
        sys.exit(2)

    if not quiet:
        print_header(file_path)

        if not is_checkov_available():
            print(color("  ⚠ Checkov not found. Install: pip install checkov", "\033[33m"))
        if not is_conftest_available():
            print(color("  ⚠ conftest not found. See README for install instructions.", "\033[33m"))
        print()

    checkov_result = run_checkov(file_path)
    opa_result = run_conftest(file_path, policy_dir=policy_dir)

    merged = merge_results(checkov_result, opa_result)
    merged["findings"] = enrich_findings_with_remediation(merged["findings"], use_ai=use_ai)

    if not quiet:
        print_scanner_summary(checkov_result, opa_result)
        print_findings_by_severity(merged["findings"])

    report_paths = generate_reports(merged, base_path=output_dir, file_path=file_path)
    merged["report_paths"] = report_paths

    if not quiet:
        print_result_banner(merged.get("allow_deploy", False), merged)
        print(f"\n  Reports saved:")
        print(f"    JSON: {report_paths['json']}")
        print(f"    HTML: {report_paths['html']}")
        print()

    exit_code = 0 if merged.get("allow_deploy", False) else 1
    sys.exit(exit_code)


def main():
    parser = argparse.ArgumentParser(
        prog="policyengine",
        description="PolicyEngine — IaC Security Validation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py validate examples/insecure/main.tf
  python cli.py validate examples/insecure/docker-compose.yml
  python cli.py validate main.tf --policy-dir custom_policies/
  python cli.py validate main.tf --output-dir /tmp/reports/ --quiet
        """,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    val_parser = subparsers.add_parser("validate", help="Validate an IaC file")
    val_parser.add_argument("file", help="Path to Terraform (.tf) or Docker Compose (.yml) file")
    val_parser.add_argument(
        "--policy-dir", default="policies/",
        help="Directory containing custom OPA/Rego policies (default: policies/)"
    )
    val_parser.add_argument(
        "--output-dir", default="reports/",
        help="Directory to save reports (default: reports/)"
    )
    val_parser.add_argument(
        "--ai", action="store_true", default=False,
        help="Use Ollama AI for enhanced remediation suggestions (requires Ollama running)"
    )
    val_parser.add_argument(
        "--quiet", "-q", action="store_true", default=False,
        help="Suppress output; use exit code only (0=pass, 1=fail)"
    )
    val_parser.set_defaults(func=validate)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
