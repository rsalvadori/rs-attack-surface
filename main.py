from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from urllib.parse import urlparse
from datetime import datetime
import os
import re

from scan.httpx_runner import run_httpx
from scan.tls_analyzer import analyze_tls
from scan.nuclei_analyzer import analyze_nuclei
from scan.lgpd_analyzer import analyze_lgpd
from scan.infra_analyzer import analyze_infrastructure
from scan.finding_enricher import enrich_finding
from scan.report_generator_html import generate_pdf_report

from frontend.html_builder import generate_html_dashboard

app = FastAPI(
    title="RS Attack Surface API",
    version="1.3.2",
    description="Scanner de Attack Surface com análise de segurança, privacidade e infraestrutura."
)

# =========================
# FRONTEND
# =========================
app.mount("/frontend", StaticFiles(directory="frontend"), name="frontend")

# 🔥 NOVO (necessário para abrir HTML gerado)
app.mount("/reports", StaticFiles(directory="reports"), name="reports")


@app.get("/")
def serve_dashboard():
    return FileResponse("frontend/dashboard.html")


# =========================
# MODELOS
# =========================
class ScanRequest(BaseModel):
    domain: str = Field(..., example="example.com")


# =========================
# VALIDAÇÃO
# =========================
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()

    if not domain:
        raise ValueError("Domínio vazio.")

    if not domain.startswith(("http://", "https://")):
        domain = f"https://{domain}"

    parsed = urlparse(domain)
    host = parsed.netloc or parsed.path

    if not host:
        raise ValueError("Não foi possível identificar o domínio.")

    if ":" in host:
        host = host.split(":")[0]

    if host.startswith("www."):
        host = host[4:]

    return host


def validate_domain(domain: str) -> bool:
    return bool(DOMAIN_REGEX.match(domain))


# =========================
# SCORE
# =========================
def calculate_scores(findings: list[dict]) -> tuple[int, str, int, int]:
    security_score = 100
    privacy_score = 100

    for f in findings:
        severity = f.get("severity", "info")
        title = f.get("title", "").lower()

        is_privacy = any(
            k in title for k in [
                "privacidade", "lgpd", "cookies", "encarregado",
                "privacy", "cookie", "consent", "gdpr"
            ]
        )

        if is_privacy:
            if severity == "high":
                privacy_score -= 20
            elif severity == "medium":
                privacy_score -= 10
            elif severity == "low":
                privacy_score -= 5
        else:
            if severity == "critical":
                security_score -= 30
            elif severity == "high":
                security_score -= 25
            elif severity == "medium":
                security_score -= 15
            elif severity == "low":
                security_score -= 5

    security_score = max(security_score, 0)
    privacy_score = max(privacy_score, 0)

    final_score = int((security_score * 0.7) + (privacy_score * 0.3))

    if final_score >= 85:
        risk = "low"
    elif final_score >= 60:
        risk = "medium"
    else:
        risk = "high"

    return final_score, risk, security_score, privacy_score


def get_top_findings(findings: list[dict], limit: int = 3) -> list[dict]:
    severity_order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0
    }

    filtered = [f for f in findings if f.get("severity") != "info"]

    return sorted(
        filtered,
        key=lambda x: severity_order.get(x.get("severity", "info"), 0),
        reverse=True
    )[:limit]


# =========================
# CORE
# =========================
def execute_scan(domain: str) -> dict:
    findings: list[dict] = []

    try:
        httpx_data = run_httpx(domain)
    except Exception:
        httpx_data = {}

    if httpx_data:
        findings.append({
            "title": "HTTPX Scan Executado",
            "severity": "info",
            "impact": f"Status {httpx_data.get('status_code')} em {httpx_data.get('url')}",
            "recommendation": "Prosseguir com análise"
        })

    headers_raw = str(httpx_data).lower()

    if "strict-transport-security" not in headers_raw:
        findings.append({
            "title": "Missing HSTS",
            "severity": "medium",
            "impact": "HTTPS não está sendo forçado.",
            "recommendation": "Configurar HSTS."
        })

    if "content-security-policy" not in headers_raw:
        findings.append({
            "title": "Missing CSP",
            "severity": "medium",
            "impact": "Exposição a XSS.",
            "recommendation": "Implementar CSP."
        })

    if "x-frame-options" not in headers_raw:
        findings.append({
            "title": "Missing X-Frame-Options",
            "severity": "medium",
            "impact": "Possível clickjacking.",
            "recommendation": "Configurar X-Frame-Options."
        })

    if "x-content-type-options" not in headers_raw:
        findings.append({
            "title": "Missing X-Content-Type-Options",
            "severity": "low",
            "impact": "Interpretação incorreta.",
            "recommendation": "Configurar nosniff."
        })

    try:
        findings.extend(analyze_tls(domain) or [])
    except Exception:
        pass

    try:
        findings.extend(analyze_nuclei(domain) or [])
    except Exception:
        pass

    try:
        findings.extend(analyze_lgpd(domain) or [])
    except Exception:
        pass

    try:
        infra_data = analyze_infrastructure(domain)
    except Exception:
        infra_data = {}

    try:
        findings = [enrich_finding(f) for f in findings]
    except Exception:
        pass

    score, risk, security_score, privacy_score = calculate_scores(findings)
    top_findings = get_top_findings(findings)

    return {
        "target": domain,
        "score": score,
        "risk": risk,
        "security_score": security_score,
        "privacy_score": privacy_score,
        "findings": findings,
        "top_findings": top_findings,
        "infra": infra_data,
        "raw_httpx": httpx_data
    }


# =========================
# ENDPOINTS
# =========================
@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan")
def scan(request: ScanRequest):
    domain = normalize_domain(request.domain)

    if not validate_domain(domain):
        raise HTTPException(status_code=400, detail="Domínio inválido.")

    return execute_scan(domain)


# =========================
# ✅ CORRIGIDO
# =========================
@app.post("/scan-report")
def scan_report(request: ScanRequest):
    domain = normalize_domain(request.domain)

    if not validate_domain(domain):
        raise HTTPException(status_code=400, detail="Domínio inválido.")

    result = execute_scan(domain)

    safe_domain = re.sub(r"[^a-zA-Z0-9\-]", "_", domain)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    client_dir = os.path.join("reports", safe_domain)
    os.makedirs(client_dir, exist_ok=True)

    # PDF (mantido)
    pdf_name = f"report_{safe_domain}_{timestamp}.pdf"
    pdf_path = os.path.join(client_dir, pdf_name)
    generate_pdf_report(result, pdf_path)

    # HTML
    html_name = f"report_{safe_domain}_{timestamp}.html"
    html_path = os.path.join(client_dir, html_name)

    html_content = generate_html_dashboard(result)

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    # 🔥 ALTERAÇÃO PRINCIPAL
    return {
        "html_url": f"/reports/{safe_domain}/{html_name}"
    }