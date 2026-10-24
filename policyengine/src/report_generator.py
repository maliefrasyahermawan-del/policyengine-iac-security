import json
from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape


SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#65a30d",
    "INFO": "#2563eb",
}

SEVERITY_BADGE = {
    "CRITICAL": "bg-red-100 text-red-800",
    "HIGH": "bg-orange-100 text-orange-800",
    "MEDIUM": "bg-yellow-100 text-yellow-800",
    "LOW": "bg-green-100 text-green-800",
    "INFO": "bg-blue-100 text-blue-800",
}


def generate_json_report(merged_result: dict, output_path: str) -> str:
    report = {
        "generated_at": datetime.now().isoformat(),
        "allow_deploy": merged_result.get("allow_deploy", False),
        "total_violations": merged_result.get("total_violations", 0),
        "severity_counts": merged_result.get("severity_counts", {}),
        "scanner_counts": merged_result.get("scanner_counts", {}),
        "checkov_summary": merged_result.get("checkov_summary", {}),
        "opa_summary": merged_result.get("opa_summary", {}),
        "errors": merged_result.get("errors", []),
        "findings": merged_result.get("findings", []),
    }

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return str(out)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>PolicyEngine Report</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .finding-detail { display: none; }
    .finding-detail.open { display: table-row; }
    .toggle-btn { cursor: pointer; user-select: none; }
  </style>
</head>
<body class="bg-gray-50 min-h-screen font-sans">
  <div class="max-w-7xl mx-auto px-4 py-8">

    <!-- Header -->
    <div class="mb-8">
      <h1 class="text-3xl font-bold text-gray-900 mb-1">PolicyEngine Validation Report</h1>
      <p class="text-sm text-gray-500">Generated: {{ generated_at }} &nbsp;|&nbsp; File: {{ file_path }}</p>
    </div>

    <!-- Result Banner -->
    {% if allow_deploy %}
    <div class="rounded-xl p-6 mb-8 bg-green-50 border-2 border-green-400 flex items-center gap-4">
      <div class="text-5xl">✅</div>
      <div>
        <div class="text-2xl font-bold text-green-700">PASSED — Deployment Allowed</div>
        <div class="text-green-600 mt-1">No CRITICAL or HIGH violations found. Safe to deploy.</div>
      </div>
    </div>
    {% else %}
    <div class="rounded-xl p-6 mb-8 bg-red-50 border-2 border-red-400 flex items-center gap-4">
      <div class="text-5xl">🚫</div>
      <div>
        <div class="text-2xl font-bold text-red-700">FAILED — Deployment Blocked</div>
        <div class="text-red-600 mt-1">{{ critical_count }} CRITICAL and {{ high_count }} HIGH violations found. Fix before deploying.</div>
      </div>
    </div>
    {% endif %}

    <!-- Summary Cards -->
    <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
      <div class="bg-white rounded-lg p-4 border shadow-sm text-center">
        <div class="text-3xl font-bold text-gray-800">{{ total_violations }}</div>
        <div class="text-sm text-gray-500 mt-1">Total Violations</div>
      </div>
      <div class="bg-red-50 rounded-lg p-4 border border-red-200 text-center">
        <div class="text-3xl font-bold text-red-600">{{ severity_counts.get('CRITICAL', 0) }}</div>
        <div class="text-sm text-red-500 mt-1">Critical</div>
      </div>
      <div class="bg-orange-50 rounded-lg p-4 border border-orange-200 text-center">
        <div class="text-3xl font-bold text-orange-600">{{ severity_counts.get('HIGH', 0) }}</div>
        <div class="text-sm text-orange-500 mt-1">High</div>
      </div>
      <div class="bg-yellow-50 rounded-lg p-4 border border-yellow-200 text-center">
        <div class="text-3xl font-bold text-yellow-600">{{ severity_counts.get('MEDIUM', 0) }}</div>
        <div class="text-sm text-yellow-500 mt-1">Medium</div>
      </div>
      <div class="bg-green-50 rounded-lg p-4 border border-green-200 text-center">
        <div class="text-3xl font-bold text-green-600">{{ severity_counts.get('LOW', 0) }}</div>
        <div class="text-sm text-green-500 mt-1">Low</div>
      </div>
    </div>

    <!-- Scanner Summary -->
    <div class="grid grid-cols-2 gap-4 mb-8">
      <div class="bg-white rounded-lg p-4 border shadow-sm">
        <h3 class="font-semibold text-gray-700 mb-2">Checkov Scanner</h3>
        <div class="text-sm text-gray-600">
          Failed checks: <span class="font-bold text-red-600">{{ checkov_summary.get('total_failed', 0) }}</span> &nbsp;
          Passed: <span class="font-bold text-green-600">{{ checkov_summary.get('total_passed', 0) }}</span>
        </div>
      </div>
      <div class="bg-white rounded-lg p-4 border shadow-sm">
        <h3 class="font-semibold text-gray-700 mb-2">OPA/Conftest Scanner</h3>
        <div class="text-sm text-gray-600">
          Violations: <span class="font-bold text-red-600">{{ opa_summary.get('total_failed', 0) }}</span> &nbsp;
          Passed: <span class="font-bold text-green-600">{{ opa_summary.get('total_passed', 0) }}</span>
        </div>
      </div>
    </div>

    <!-- Errors -->
    {% if errors %}
    <div class="bg-yellow-50 border border-yellow-300 rounded-lg p-4 mb-8">
      <h3 class="font-semibold text-yellow-800 mb-2">⚠ Scanner Warnings</h3>
      {% for err in errors %}
      <div class="text-sm text-yellow-700 mb-1">
        <strong>{{ err.scanner }}:</strong> {{ err.message }}
      </div>
      {% endfor %}
    </div>
    {% endif %}

    <!-- Findings Table -->
    {% if findings %}
    <div class="bg-white rounded-xl border shadow-sm overflow-hidden mb-8">
      <div class="px-6 py-4 border-b bg-gray-50">
        <h2 class="text-lg font-semibold text-gray-800">Violations ({{ findings | length }})</h2>
      </div>
      <table class="w-full text-sm">
        <thead>
          <tr class="bg-gray-100 text-gray-600 text-left">
            <th class="px-4 py-3 w-24">Severity</th>
            <th class="px-4 py-3 w-32">Scanner</th>
            <th class="px-4 py-3 w-32">Check ID</th>
            <th class="px-4 py-3">Resource</th>
            <th class="px-4 py-3">Message</th>
            <th class="px-4 py-3 w-20">Detail</th>
          </tr>
        </thead>
        <tbody>
          {% for f in findings %}
          {% set idx = loop.index %}
          <tr class="border-t hover:bg-gray-50">
            <td class="px-4 py-3">
              <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium
                {% if f.severity == 'CRITICAL' %}bg-red-100 text-red-800
                {% elif f.severity == 'HIGH' %}bg-orange-100 text-orange-800
                {% elif f.severity == 'MEDIUM' %}bg-yellow-100 text-yellow-800
                {% else %}bg-green-100 text-green-800{% endif %}">
                {{ f.severity }}
              </span>
            </td>
            <td class="px-4 py-3 text-gray-600">{{ f.scanner | upper }}</td>
            <td class="px-4 py-3 font-mono text-xs text-gray-500">{{ f.check_id or 'N/A' }}</td>
            <td class="px-4 py-3 text-gray-700 font-medium">{{ f.resource or '-' }}</td>
            <td class="px-4 py-3 text-gray-600">{{ f.message }}</td>
            <td class="px-4 py-3">
              <button class="toggle-btn text-blue-600 hover:text-blue-800 text-xs underline"
                      onclick="toggleDetail({{ idx }})">
                View fix
              </button>
            </td>
          </tr>
          <tr id="detail-{{ idx }}" class="finding-detail bg-blue-50 border-t border-blue-100">
            <td colspan="6" class="px-6 py-4">
              {% if f.remediation %}
              <div class="mb-2">
                <span class="font-semibold text-gray-800">{{ f.remediation.title }}</span>
              </div>
              <p class="text-gray-700 text-sm mb-3">{{ f.remediation.fix }}</p>
              {% if f.remediation.terraform_snippet %}
              <div class="bg-gray-800 text-green-300 rounded p-3 text-xs font-mono whitespace-pre overflow-x-auto mb-3">{{ f.remediation.terraform_snippet }}</div>
              {% endif %}
              {% if f.remediation.get('ai_fix') %}
              <div class="bg-purple-50 border border-purple-200 rounded p-3 text-sm text-gray-700 mb-2">
                <strong class="text-purple-700">AI Suggestion:</strong> {{ f.remediation.ai_fix }}
              </div>
              {% endif %}
              {% if f.remediation.references %}
              <div class="text-xs text-gray-500">
                References:
                {% for ref in f.remediation.references %}
                <a href="{{ ref }}" class="text-blue-500 hover:underline ml-1">{{ ref }}</a>
                {% endfor %}
              </div>
              {% endif %}
              {% else %}
              <p class="text-gray-500 text-sm">No remediation available. Review the resource documentation.</p>
              {% endif %}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% else %}
    <div class="text-center text-gray-500 py-12">No violations found.</div>
    {% endif %}

    <!-- Download -->
    <div class="flex justify-end">
      <a href="/download-report" class="bg-gray-800 text-white px-4 py-2 rounded hover:bg-gray-700 text-sm">
        Download JSON Report
      </a>
    </div>

  </div>

  <script>
    function toggleDetail(idx) {
      const row = document.getElementById('detail-' + idx);
      row.classList.toggle('open');
    }
  </script>
</body>
</html>"""


def generate_html_report(merged_result: dict, output_path: str, file_path: str = "") -> str:
    from jinja2 import Environment, BaseLoader

    env = Environment(loader=BaseLoader())
    env.globals["zip"] = zip

    template = env.from_string(HTML_TEMPLATE)

    severity_counts = merged_result.get("severity_counts", {})
    rendered = template.render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        file_path=file_path or "N/A",
        allow_deploy=merged_result.get("allow_deploy", False),
        total_violations=merged_result.get("total_violations", 0),
        severity_counts=severity_counts,
        critical_count=severity_counts.get("CRITICAL", 0),
        high_count=severity_counts.get("HIGH", 0),
        findings=merged_result.get("findings", []),
        checkov_summary=merged_result.get("checkov_summary", {}),
        opa_summary=merged_result.get("opa_summary", {}),
        errors=merged_result.get("errors", []),
        scanner_counts=merged_result.get("scanner_counts", {}),
    )

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(rendered, encoding="utf-8")
    return str(out)


def generate_reports(merged_result: dict, base_path: str = "reports/", file_path: str = "") -> dict:
    base = Path(base_path)
    json_path = generate_json_report(merged_result, str(base / "validation_report.json"))
    html_path = generate_html_report(merged_result, str(base / "validation_report.html"), file_path=file_path)
    return {"json": json_path, "html": html_path}
