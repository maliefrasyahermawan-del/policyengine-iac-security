import shutil
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, UploadFile, Form, Request
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.validator import validate_file

app = FastAPI(title="PolicyEngine", description="IaC Security Validation")

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

POLICIES_DIR = Path("policies")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/validate", response_class=HTMLResponse)
async def validate(
    request: Request,
    file: UploadFile = File(...),
    use_ai: bool = Form(default=False),
):
    suffix = Path(file.filename).suffix or ".tf"
    with tempfile.NamedTemporaryFile(
        delete=False, suffix=suffix, dir=UPLOAD_DIR, prefix="upload_"
    ) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        result = validate_file(
            tmp_path,
            policy_dir=str(POLICIES_DIR),
            output_dir=str(REPORTS_DIR),
            use_ai_remediation=use_ai,
        )
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    severity_counts = result.get("severity_counts", {})
    findings = result.get("findings", [])

    from datetime import datetime

    return templates.TemplateResponse(
        "report.html",
        {
            "request": request,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "file_path": file.filename,
            "allow_deploy": result.get("allow_deploy", False),
            "total_violations": result.get("total_violations", 0),
            "severity_counts": severity_counts,
            "critical_count": severity_counts.get("CRITICAL", 0),
            "high_count": severity_counts.get("HIGH", 0),
            "findings": findings,
            "checkov_summary": result.get("checkov_summary", {}),
            "opa_summary": result.get("opa_summary", {}),
            "errors": result.get("errors", []),
            "scanner_counts": result.get("scanner_counts", {}),
        },
    )


@app.get("/api/validate")
async def validate_api(file_path: str, policy_dir: str = "policies/", use_ai: bool = False):
    if not Path(file_path).exists():
        return JSONResponse(status_code=404, content={"error": f"File not found: {file_path}"})
    result = validate_file(file_path, policy_dir=policy_dir, use_ai_remediation=use_ai)
    return result


@app.get("/download-report")
async def download_report():
    json_path = REPORTS_DIR / "validation_report.json"
    if not json_path.exists():
        return JSONResponse(status_code=404, content={"error": "No report available yet. Run a validation first."})
    return FileResponse(str(json_path), media_type="application/json", filename="validation_report.json")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "PolicyEngine"}
