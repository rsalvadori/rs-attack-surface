from scan.context_analyzer import generate_executive_summary, generate_conclusion
from fastapi import FastAPI, HTTPException, Request
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
from utils.email_sender import send_email_lead

app = FastAPI(
    title="RS Attack Surface API",
    version="1.3.2",
    description="Scanner de Attack Surface com análise de segurança, privacidade e infraestrutura."
)

app.mount("/frontend", StaticFiles(directory="frontend"), name="frontend")
app.mount("/reports", StaticFiles(directory="reports"), name="reports")

@app.get("/")
def serve_dashboard():
    return FileResponse("frontend/attack-surface.html")


class ScanRequest(BaseModel):
    domain: str = Field(..., example="example.com")


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


def calculate_scores(findings: list[dict]):
    security_score = 100
    privacy_score = 100

    for f in findings:
        severity = f.get("severity", "info")
        title = f.get("title", "").lower()

        is_privacy = any(k in title for k in [
            "privacidade", "lgpd", "cookies", "encarregado",
            "privacy", "cookie", "consent", "gdpr"
        ])

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


def get_top_findings(findings, limit=3):
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    filtered = [f for f in findings if f.get("severity") != "info"]

    return sorted(
        filtered,
        key=lambda x: severity_order.get(x.get("severity", "info"), 0),
        reverse=True
    )[:limit]


def count_severities(findings: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        if sev in counts:
            counts[sev] += 1

    return counts


def is_lgpd_finding(f: dict) -> bool:
    text = " ".join([
        str(f.get("title", "")),
        str(f.get("impact", "")),
        str(f.get("recommendation", ""))
    ]).lower()

    keywords = [
        "lgpd", "privacidade", "privacy", "cookie", "cookies",
        "gdpr", "consent", "encarregado", "dpo", "titular",
        "política de privacidade"
    ]

    return any(k in text for k in keywords)


def count_lgpd_findings(findings: list[dict]) -> int:
    return sum(1 for f in findings if is_lgpd_finding(f))


def evaluate_grade(scan_result: dict) -> str:
    score = int(scan_result.get("score", 0))

    if score >= 85:
        return "A"
    elif score >= 70:
        return "B"
    elif score >= 55:
        return "C"
    elif score >= 40:
        return "D"
    else:
        return "E"


def get_allowed_upgrade_targets(current_grade: str) -> list[str]:
    mapping = {
        "E": ["D", "C", "B", "A"],
        "D": ["C", "B", "A"],
        "C": ["B", "A"],
        "B": ["A"],
        "A": []
    }
    return mapping.get(current_grade, [])


def execute_scan(domain: str):

    findings = []

    try:
        httpx_data = run_httpx(domain)
    except Exception:
        httpx_data = {}

    headers_raw = str(httpx_data).lower()

    if "strict-transport-security" not in headers_raw:
        findings.append({"title": "Missing HSTS", "severity": "medium"})

    if "content-security-policy" not in headers_raw:
        findings.append({"title": "Missing CSP", "severity": "medium"})

    if "x-frame-options" not in headers_raw:
        findings.append({"title": "Missing X-Frame-Options", "severity": "medium"})

    if "x-content-type-options" not in headers_raw:
        findings.append({"title": "Missing X-Content-Type-Options", "severity": "low"})

    # 🔥 ENRIQUECIMENTO HTTPX (dentro do seu fluxo)
    if httpx_data:
        status = httpx_data.get("status_code")
        techs = httpx_data.get("tech", [])
        webserver = httpx_data.get("webserver")

        if status and status >= 400:
            findings.append({
                "title": f"Aplicação retornando status {status}",
                "severity": "medium"
            })

        if techs:
            findings.append({
                "title": f"Tecnologias identificadas: {', '.join(techs[:3])}",
                "severity": "info"
            })

        if webserver:
            findings.append({
                "title": f"Servidor identificado: {webserver}",
                "severity": "info"
            })

    try:
        findings.extend(analyze_tls(domain) or [])
    except Exception as e:
        print("ERRO TLS:", str(e))

    try:
        findings.extend(analyze_lgpd(domain) or [])
    except Exception as e:
        print("ERRO LGPD:", str(e))

    try:
        infra_data = analyze_infrastructure(domain)
    except Exception:
        infra_data = {}

    try:
        findings.extend(analyze_nuclei(domain) or [])
    except Exception as e:
        print("ERRO NUCLEI:", str(e))

    enriched = []
    for f in findings:
        try:
            enriched.append(enrich_finding(f))
        except Exception:
            enriched.append(f)
    findings = enriched

    score, risk, sec, priv = calculate_scores(findings)

    summary = generate_executive_summary({
        "infra": infra_data,
        "findings": findings,
        "score": score
    })

    conclusion = generate_conclusion({
        "infra": infra_data,
        "findings": findings,
        "score": score
    })

    current_grade = evaluate_grade({
        "score": score,
        "findings": findings
    })

    return {
        "target": domain,
        "score": score,
        "risk": risk,
        "security_score": sec,
        "privacy_score": priv,
        "findings": findings,
        "top_findings": get_top_findings(findings),
        "infra": infra_data,
        "raw_httpx": httpx_data,
        "current_grade": current_grade,
        "allowed_upgrade_targets": get_allowed_upgrade_targets(current_grade),
        "severity_counts": count_severities(findings),
        "lgpd_findings_count": count_lgpd_findings(findings),
        "executive_summary": summary,
        "conclusion": conclusion
    }


@app.post("/scan-report")
async def scan_report(request: Request):

    body = await request.json()

    domain = normalize_domain(body.get("domain"))

    if not validate_domain(domain):
        raise HTTPException(status_code=400, detail="Domínio inválido.")

    result = execute_scan(domain)

    safe_domain = re.sub(r"[^a-zA-Z0-9\-]", "_", domain)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    client_dir = os.path.join("reports", safe_domain)
    os.makedirs(client_dir, exist_ok=True)

    pdf_name = f"report_{safe_domain}_{timestamp}.pdf"
    pdf_path = os.path.join(client_dir, pdf_name)
    generate_pdf_report(result, pdf_path)

    html_name = f"report_{safe_domain}_{timestamp}.html"
    html_path = os.path.join(client_dir, html_name)

    with open(html_path, "w", encoding="utf-8") as f:
        result["pdf_url"] = f"/reports/{safe_domain}/{pdf_name}"
        f.write(generate_html_dashboard(result))

    try:
        send_email_lead(
            company=body.get("company", "-"),
            client=body.get("client", "-"),
            email=body.get("email", "-"),
            phone=body.get("phone", "-"),
            domain=domain
        )
    except Exception as e:
        print("EMAIL ERROR:", str(e))

    return {
        "html_url": f"/reports/{safe_domain}/{html_name}",
        "pdf_url": f"/reports/{safe_domain}/{pdf_name}",
        "score": result.get("score"),
        "risk": result.get("risk"),
        "executive_summary": result.get("executive_summary"),
        "conclusion": result.get("conclusion")
    }