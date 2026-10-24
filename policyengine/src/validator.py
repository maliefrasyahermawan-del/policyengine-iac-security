from pathlib import Path

from .checkov_runner import run_checkov
from .opa_runner import run_conftest
from .aggregator import merge_results
from .remediation import enrich_findings_with_remediation
from .report_generator import generate_reports


def validate_file(
    file_path: str,
    policy_dir: str = "policies/",
    output_dir: str = "reports/",
    use_ai_remediation: bool = False,
) -> dict:
    file_path = str(Path(file_path).resolve())

    checkov_result = run_checkov(file_path)
    opa_result = run_conftest(file_path, policy_dir=policy_dir)

    merged = merge_results(checkov_result, opa_result)

    merged["findings"] = enrich_findings_with_remediation(
        merged["findings"], use_ai=use_ai_remediation
    )

    report_paths = generate_reports(merged, base_path=output_dir, file_path=file_path)
    merged["report_paths"] = report_paths

    return merged
