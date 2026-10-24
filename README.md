# PolicyEngine — IaC Security Validation

> A shift-left security tool that checks Terraform and Docker Compose configurations before they reach production.

## What this project does

PolicyEngine combines Checkov's infrastructure-as-code checks with custom Open Policy Agent (OPA/Rego) rules. It analyzes configuration, consolidates findings, proposes remediation, and produces reports for local review or CI/CD gates.

## Core functions

- Scan Terraform and Docker Compose files with Checkov.
- Enforce organization-specific policies through OPA/Conftest and Rego.
- Merge and deduplicate findings into severity-based reports.
- Generate JSON/HTML output with remediation guidance.
- Offer CLI validation, a local upload interface, GitHub Actions, and pre-commit integration.
- Optionally request remediation suggestions from a local Ollama model.

## Architecture

```text
Terraform / Compose config → Checkov + OPA/Conftest → finding aggregator → remediation engine
                                                                          │
                                                                          ▼
                                                             CLI | HTML | JSON | CI gate
```

## Technology and local run

Python, FastAPI, Jinja2, Checkov, python-hcl2, OPA/Conftest, Rego, and optional Ollama.

```bash
cd policyengine
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python cli.py validate examples/insecure/main.tf
python run.py
```

## Safety note

The insecure example files are intentionally vulnerable so the scanner can demonstrate findings. They are learning artifacts only and must never be used as deployable infrastructure.
