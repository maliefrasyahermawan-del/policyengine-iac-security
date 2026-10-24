import httpx


REMEDIATION_TEMPLATES: dict[str, dict] = {
    "no_open_ssh": {
        "title": "Restrict SSH access",
        "severity": "CRITICAL",
        "fix": (
            "Ganti cidr_blocks dari [\"0.0.0.0/0\"] menjadi IP range spesifik, "
            "contoh IP kantor atau VPN: [\"10.0.0.0/8\"] atau [\"YOUR_IP/32\"]. "
            "Jika memerlukan akses dari mana saja, gunakan AWS Systems Manager Session Manager "
            "sebagai pengganti SSH langsung."
        ),
        "terraform_snippet": 'cidr_blocks = ["YOUR_IP/32"]  # Replace with specific IP',
        "references": ["https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"],
    },
    "no_open_rdp": {
        "title": "Restrict RDP access",
        "severity": "CRITICAL",
        "fix": (
            "Ganti cidr_blocks dari [\"0.0.0.0/0\"] menjadi IP range spesifik. "
            "Pertimbangkan penggunaan AWS Systems Manager Fleet Manager "
            "untuk RDP tanpa membuka port 3389 ke internet."
        ),
        "terraform_snippet": 'cidr_blocks = ["YOUR_OFFICE_IP/32"]',
        "references": ["https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/connecting_to_windows_instance.html"],
    },
    "s3_no_encryption": {
        "title": "Enable S3 server-side encryption",
        "severity": "HIGH",
        "fix": (
            "Tambahkan block server_side_encryption_configuration ke resource aws_s3_bucket. "
            "Gunakan SSE-S3 (AES256) untuk enkripsi standar atau SSE-KMS untuk kontrol lebih ketat."
        ),
        "terraform_snippet": """server_side_encryption_configuration {
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}""",
        "references": ["https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration"],
    },
    "rds_no_encryption": {
        "title": "Enable RDS storage encryption",
        "severity": "HIGH",
        "fix": (
            "Set storage_encrypted = true pada resource aws_db_instance. "
            "Perhatikan: enkripsi tidak dapat diaktifkan pada instance yang sudah berjalan. "
            "Buat snapshot, buat instance baru dari snapshot dengan enkripsi, lalu hapus yang lama."
        ),
        "terraform_snippet": 'storage_encrypted = true',
        "references": ["https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#storage_encrypted"],
    },
    "rds_publicly_accessible": {
        "title": "Disable public accessibility for RDS",
        "severity": "CRITICAL",
        "fix": (
            "Set publicly_accessible = false. Database tidak perlu diakses dari internet. "
            "Gunakan VPC private subnet dan pastikan aplikasi diakses melalui VPC yang sama."
        ),
        "terraform_snippet": 'publicly_accessible = false',
        "references": ["https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#publicly_accessible"],
    },
    "iam_wildcard_action": {
        "title": "Remove wildcard IAM actions",
        "severity": "CRITICAL",
        "fix": (
            "Ganti Action = \"*\" dengan daftar action spesifik yang dibutuhkan aplikasi. "
            "Ikuti prinsip least privilege: hanya izinkan action yang benar-benar digunakan. "
            "Gunakan IAM Access Analyzer untuk menentukan action minimal yang diperlukan."
        ),
        "terraform_snippet": """policy = jsonencode({
  Version = "2012-10-17"
  Statement = [{
    Effect   = "Allow"
    Action   = [
      "s3:GetObject",
      "s3:PutObject",
      # tambahkan action spesifik lainnya
    ]
    Resource = "arn:aws:s3:::your-specific-bucket/*"
  }]
})""",
        "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"],
    },
    "iam_wildcard_resource": {
        "title": "Remove wildcard IAM resource",
        "severity": "HIGH",
        "fix": (
            "Ganti Resource = \"*\" dengan ARN resource spesifik. "
            "Contoh: arn:aws:s3:::your-bucket-name/* untuk akses S3 spesifik."
        ),
        "terraform_snippet": 'Resource = "arn:aws:s3:::your-specific-bucket/*"',
        "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html"],
    },
    "docker_privileged": {
        "title": "Remove privileged mode from container",
        "severity": "CRITICAL",
        "fix": (
            "Hapus atau set privileged: false. Container privileged memiliki akses penuh ke host. "
            "Jika container membutuhkan capability tertentu, gunakan cap_add untuk menambahkan "
            "capability spesifik saja, bukan mode privileged."
        ),
        "terraform_snippet": """privileged: false
cap_add:
  - NET_BIND_SERVICE  # tambahkan capability spesifik yang dibutuhkan""",
        "references": ["https://docs.docker.com/compose/compose-file/compose-file-v3/#cap_add-cap_drop"],
    },
    "docker_root_user": {
        "title": "Run container as non-root user",
        "severity": "HIGH",
        "fix": (
            "Ganti user: root dengan non-root user. Buat user di Dockerfile dan gunakan di sini. "
            "Contoh: user: '1000:1000' atau user: appuser."
        ),
        "terraform_snippet": "user: '1000:1000'  # non-root user",
        "references": ["https://docs.docker.com/engine/security/userns-remap/"],
    },
    "docker_hardcoded_secret": {
        "title": "Remove hardcoded secrets from docker-compose",
        "severity": "HIGH",
        "fix": (
            "Jangan hardcode password/secret di docker-compose.yml. Gunakan secrets management: "
            "1) Docker Secrets untuk Swarm mode, "
            "2) Environment variables dari .env file (jangan commit .env ke git), "
            "3) HashiCorp Vault atau AWS Secrets Manager."
        ),
        "terraform_snippet": """environment:
  - DB_PASSWORD=${DB_PASSWORD}  # dari .env file atau environment
# atau gunakan secrets:
secrets:
  db_password:
    external: true""",
        "references": ["https://docs.docker.com/compose/use-secrets/"],
    },
    "docker_no_resource_limits": {
        "title": "Add resource limits to container",
        "severity": "MEDIUM",
        "fix": (
            "Tambahkan deploy.resources.limits untuk mencegah container mengkonsumsi "
            "seluruh resource host. Tentukan memory dan CPU yang sesuai dengan kebutuhan aplikasi."
        ),
        "terraform_snippet": """deploy:
  resources:
    limits:
      cpus: '0.50'
      memory: 512M
    reservations:
      cpus: '0.25'
      memory: 128M""",
        "references": ["https://docs.docker.com/compose/compose-file/compose-file-v3/#resources"],
    },
    "missing_tags": {
        "title": "Add required tags to resource",
        "severity": "MEDIUM",
        "fix": (
            "Tambahkan tags wajib ke resource Terraform: Environment, Owner, Project, CostCenter. "
            "Tags membantu tracking cost, ownership, dan compliance."
        ),
        "terraform_snippet": """tags = {
  Environment = "production"
  Owner       = "team-name"
  Project     = "project-name"
  CostCenter  = "cost-center-id"
}""",
        "references": ["https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html"],
    },
    "s3_public_access": {
        "title": "Enable S3 public access block",
        "severity": "CRITICAL",
        "fix": (
            "Tambahkan resource aws_s3_bucket_public_access_block untuk memblokir semua akses publik. "
            "S3 bucket seharusnya tidak pernah publik kecuali hosting static website."
        ),
        "terraform_snippet": """resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}""",
        "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
    },
}


CHECKOV_ID_TO_TEMPLATE = {
    "CKV_AWS_19": "s3_no_encryption",
    "CKV_AWS_145": "s3_no_encryption",
    "CKV2_AWS_6": "s3_public_access",
    "CKV_AWS_25": "no_open_ssh",
    "CKV_AWS_24": "no_open_rdp",
    "CKV_AWS_52": "rds_no_encryption",
    "CKV_AWS_17": "rds_publicly_accessible",
    "CKV_AWS_1": "iam_wildcard_action",
    "CKV_DOCKER_1": "docker_privileged",
    "CKV_DOCKER_2": "docker_no_resource_limits",
    "CKV_DOCKER_8": "docker_root_user",
}

OPA_MSG_TO_TEMPLATE = {
    "ssh": "no_open_ssh",
    "rdp": "no_open_rdp",
    "s3 bucket": "s3_no_encryption",
    "rds": "rds_no_encryption",
    "publicly accessible": "rds_publicly_accessible",
    "wildcard": "iam_wildcard_action",
    "privileged": "docker_privileged",
    "root user": "docker_root_user",
    "password": "docker_hardcoded_secret",
    "tag": "missing_tags",
    "resource limit": "docker_no_resource_limits",
}


def get_remediation(finding: dict) -> dict:
    check_id = finding.get("check_id", "")
    if check_id in CHECKOV_ID_TO_TEMPLATE:
        return REMEDIATION_TEMPLATES[CHECKOV_ID_TO_TEMPLATE[check_id]]

    message = (finding.get("message", "") + " " + finding.get("description", "")).lower()
    for keyword, template_key in OPA_MSG_TO_TEMPLATE.items():
        if keyword in message:
            return REMEDIATION_TEMPLATES[template_key]

    return {
        "title": "Manual review required",
        "severity": finding.get("severity", "MEDIUM"),
        "fix": (
            "Tinjau dokumentasi resmi resource ini untuk best practice keamanan. "
            f"Check ID: {check_id or 'N/A'}. "
            "Periksa: https://www.checkov.io/5.Policy%20Index/terraform.html"
        ),
        "terraform_snippet": "",
        "references": [],
    }


def get_ai_remediation(violation: dict) -> str | None:
    try:
        prompt = (
            f"Given this Infrastructure as Code security violation: {violation.get('message', '')}\n"
            f"Resource: {violation.get('resource', 'unknown')}\n"
            f"Scanner: {violation.get('scanner', 'unknown')}\n"
            "Suggest a specific one-paragraph fix with the exact Terraform or Docker Compose "
            "configuration change needed. Be concise and actionable."
        )
        response = httpx.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3.2:3b",
                "prompt": prompt,
                "stream": False,
            },
            timeout=10.0,
        )
        if response.status_code == 200:
            return response.json().get("response", "").strip()
    except Exception:
        pass
    return None


def enrich_findings_with_remediation(findings: list[dict], use_ai: bool = False) -> list[dict]:
    enriched = []
    for finding in findings:
        f = dict(finding)
        remediation = get_remediation(f)

        if use_ai:
            ai_fix = get_ai_remediation(f)
            if ai_fix:
                remediation = dict(remediation)
                remediation["ai_fix"] = ai_fix

        f["remediation"] = remediation
        enriched.append(f)
    return enriched
