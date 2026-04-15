import requests
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 5
MAX_LINKS = 10


def fetch(url: str):
    try:
        r = requests.get(
            url,
            timeout=TIMEOUT,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        # evita lixo / páginas vazias
        if r.status_code == 200 and len(r.text) > 500:
            return r.text.lower()

    except:
        pass

    return ""


def extract_links(html: str):
    links = re.findall(r'href=["\\\'](.*?)["\\\']', html)

    clean = []
    for l in links:
        if not l:
            continue
        if l.startswith("#"):
            continue
        if "javascript:" in l:
            continue
        if "mailto:" in l:
            continue
        clean.append(l)

    return list(set(clean))


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
    # 2. LINKS DO SITE (CONTROLADO)
    # =========================
    links = extract_links(html)

    keywords = [
        "privacidade", "privacy", "lgpd", "dados",
        "policy", "cookies", "termos"
    ]

    for l in links[:MAX_LINKS]:
        if any(k in l.lower() for k in keywords):
            content = fetch(normalize(domain, l))
            if content:
                pages.append(content)

    # =========================
    # 3. FORÇA CAMINHOS (CRÍTICO)
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
        content = fetch(base + p)
        if content:
            pages.append(content)

    # =========================
    # 4. TEXTO FINAL
    # =========================
    full = " ".join(pages)

    # =========================
    # 5. DETECÇÃO REAL
    # =========================

    # Política REAL (evita falso positivo)
    has_policy = (
        any(x in full for x in [
            "política de privacidade",
            "privacy policy"
        ])
        and "dados pessoais" in full
    )

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

    has_cookies = any(x in full for x in [
        "cookie",
        "cookies",
        "aceitar cookies",
        "consent"
    ])

    # =========================
    # 6. FINDINGS (SEM GAMBIARRA)
    # =========================

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