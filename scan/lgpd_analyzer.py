import requests
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 5


def fetch(url: str):
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False)
        if r.status_code == 200:
            return r.text.lower()
    except:
        pass
    return ""


def extract_links(html: str):
    return list(set(re.findall(r'href=["\\\'](.*?)["\\\']', html)))


def normalize(domain: str, link: str):
    if link.startswith("http"):
        return link
    if link.startswith("/"):
        return f"https://{domain}{link}"
    return f"https://{domain}/{link}"


def analyze_lgpd(domain: str) -> list[dict]:

    findings = []
    base = f"https://{domain}"

    pages = []

    # =========================
    # 1. HOME
    # =========================
    html = fetch(base)
    if not html:
        return findings

    pages.append(html)

    # =========================
    # 2. LINKS DO SITE
    # =========================
    links = extract_links(html)

    keywords = [
        "privacidade", "privacy", "lgpd", "dados",
        "policy", "cookies", "termos"
    ]

    for l in links:
        if any(k in l.lower() for k in keywords):
            pages.append(fetch(normalize(domain, l)))

    # =========================
    # 3. 🔥 FORÇA CAMINHOS (RESOLVE SEU CASO)
    # =========================
    forced_paths = [
        "/politica-de-privacidade",
        "/politica",
        "/privacy",
        "/privacidade",
        "/lgpd",
        "/termos",
        "/termos-de-uso"
    ]

    for p in forced_paths:
        pages.append(fetch(base + p))

    # =========================
    # 4. TEXTO FINAL
    # =========================
    full = " ".join([p for p in pages if p])

    # =========================
    # 5. DETECÇÃO REAL
    # =========================

    has_policy = any(x in full for x in [
        "política de privacidade",
        "privacy policy",
        "dados pessoais"
    ])

    has_portal = any(x in full for x in [
        "portal do titular",
        "direitos do titular",
        "solicitar dados"
    ])

    has_dpo = any(x in full for x in [
        "encarregado",
        "dpo",
        "privacidade@"
    ])

    has_cookies = "cookie" in full

    # =========================
    # 6. LÓGICA CORRETA
    # =========================

    # 🚨 SÓ ACUSA AUSÊNCIA SE REALMENTE NÃO EXISTIR
    if not has_policy:
        findings.append({
            "title": "Política de privacidade não identificada",
            "severity": "medium",
            "impact": "Não foi possível localizar política de privacidade acessível.",
            "recommendation": "Garantir link visível para política de privacidade."
        })

    if not has_portal:
        findings.append({
            "title": "Canal do titular não identificado",
            "severity": "medium",
            "impact": "Pode dificultar exercício de direitos do titular.",
            "recommendation": "Disponibilizar canal de requisição de dados."
        })

    if not has_dpo:
        findings.append({
            "title": "Contato de privacidade não identificado",
            "severity": "low",
            "impact": "Usuário pode não ter canal direto para LGPD.",
            "recommendation": "Divulgar e-mail ou canal do encarregado."
        })

    if not has_cookies:
        findings.append({
            "title": "Aviso de cookies não identificado",
            "severity": "low",
            "impact": "Pode impactar transparência de coleta.",
            "recommendation": "Implementar banner de cookies."
        })

    return findings