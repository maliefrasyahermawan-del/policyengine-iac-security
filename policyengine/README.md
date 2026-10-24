# PolicyEngine

**Infrastructure as Code (IaC) Security Validation — Shift-Left Security**

PolicyEngine scans Terraform and Docker Compose files for security misconfigurations *before* they reach production. It combines two scanners:

- **Checkov** — 1000+ built-in checks (encryption, public access, IAM, etc.)
- **OPA/Conftest** — custom Rego policies you write and control

---

## Quick Start

### 1. Install Python dependencies

```bash
cd policyengine
pip install -r requirements.txt
```

### 2. Install OPA binary tools

**conftest** (wraps OPA for config file testing):
- Download from: https://github.com/open-policy-agent/conftest/releases
- Windows: `conftest_Windows_x86_64.zip` → extract `conftest.exe` → place in PATH
- Verify: `conftest --version`

**OPA** (optional, used by conftest internally):
- Download: https://github.com/open-policy-agent/opa/releases/latest/download/opa_windows_amd64.exe
- Rename to `opa.exe` → place in PATH
- Verify: `opa version`

> **Note:** PolicyEngine works without conftest/OPA — Checkov will still run. You'll see a warning about missing custom policies.

---

## Usage

### CLI

```bash
# Validate insecure Terraform config (demo — will FAIL)
python cli.py validate examples/insecure/main.tf

# Validate secure Terraform config (should PASS)
python cli.py validate examples/secure/main.tf

# Validate Docker Compose
python cli.py validate examples/insecure/docker-compose.yml

# Use custom policy directory
python cli.py validate main.tf --policy-dir my_policies/

# Save reports to specific directory
python cli.py validate main.tf --output-dir /tmp/reports/

# Enable AI remediation (requires Ollama running: ollama run llama3.2:3b)
python cli.py validate main.tf --ai

# Quiet mode — exit code only (for CI/CD)
python cli.py validate main.tf --quiet
echo $?  # 0 = pass, 1 = fail
```

### Web UI

```bash
python run.py
# Open http://localhost:8000
# Upload any .tf or .yml file via drag-and-drop
```

---

## Expected Demo Output

```
================================================================
  PolicyEngine Validation Report
================================================================
  File: examples/insecure/main.tf

  [CHECKOV]  12 failed, 8 passed
  [OPA]       5 violations, 0 passed

  CRITICAL (3):
    ✗ Security group 'web' allows SSH (port 22) from anywhere [aws_security_group.web]
      → Ganti cidr_blocks dari ["0.0.0.0/0"] menjadi IP range spesifik.
    ✗ RDS instance 'database' has publicly accessible enabled
      → Set publicly_accessible = false.
    ✗ IAM policy 'overprivileged' uses wildcard Action ('*')
      → Specify explicit actions following least-privilege principle.

  HIGH (4):
    ...

================================================================
  RESULT: ⛔ FAILED — 3 critical, 4 high violation(s) found
  Deployment BLOCKED. Fix violations above before deploying.
================================================================
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: IaC Security Validation
on: [push, pull_request]

jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install PolicyEngine
        run: pip install checkov

      - name: Install conftest
        run: |
          wget https://github.com/open-policy-agent/conftest/releases/download/v0.46.0/conftest_0.46.0_Linux_x86_64.tar.gz
          tar xzf conftest_0.46.0_Linux_x86_64.tar.gz
          sudo mv conftest /usr/local/bin/

      - name: Validate IaC
        run: python cli.py validate infra/main.tf --quiet
        # Exit code 1 automatically fails the job
```

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/sh
python /path/to/policyengine/cli.py validate infra/main.tf --quiet
if [ $? -ne 0 ]; then
  echo "PolicyEngine: Security violations found. Commit blocked."
  exit 1
fi
```

---

## Project Structure

```
policyengine/
├── src/
│   ├── validator.py          # Orchestrator
│   ├── checkov_runner.py     # Checkov wrapper
│   ├── opa_runner.py         # conftest/OPA wrapper
│   ├── aggregator.py         # Merge & deduplicate results
│   ├── remediation.py        # Fix suggestions (static + AI)
│   └── report_generator.py   # HTML + JSON reports
├── policies/
│   ├── network_security.rego
│   ├── encryption.rego
│   ├── container_security.rego
│   ├── tagging.rego
│   └── iam_least_privilege.rego
├── examples/
│   ├── insecure/             # Demo files with intentional vulns
│   └── secure/               # Fixed versions for comparison
├── web/
│   ├── main.py               # FastAPI app
│   └── templates/
│       ├── index.html        # Upload form
│       └── report.html       # Results page
├── cli.py                    # CLI entrypoint
├── run.py                    # Web server entrypoint
└── requirements.txt
```

---

## Writing Custom Policies

Add `.rego` files to `policies/`. Example — deny resources without a `CostCenter` tag:

```rego
package terraform.custom

deny[msg] {
    resource := input.resource.aws_instance[name]
    not resource.tags.CostCenter
    msg := sprintf("EC2 instance '%v' missing required CostCenter tag", [name])
}
```

Then run:
```bash
python cli.py validate main.tf --policy-dir policies/
```

---

## Reports

After each validation, two reports are saved to `reports/`:
- `validation_report.json` — machine-readable, suitable for SIEM/ticketing integration
- `validation_report.html` — human-readable with expandable remediation details

---

## AI Remediation (Optional)

Install and run Ollama:
```bash
# Install Ollama from https://ollama.com
ollama pull llama3.2:3b
ollama serve  # starts on http://localhost:11434
```

Then validate with `--ai`:
```bash
python cli.py validate main.tf --ai
```

If Ollama is not running, PolicyEngine falls back to static remediation templates automatically.
