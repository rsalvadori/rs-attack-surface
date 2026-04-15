import requests
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


TIMEOUT = 5
MAX_LINKS = 10  # controle para não pesar

print(">>> LGPD ANALYZER NOVO EXECUTANDO <<<")

def fetch(url: str):
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False)
        return r.text.lower() if r.status_code == 200 else ""
    except:
        return ""


def extract_links(html: str):
    links = re.findall(r'href=["\\\'](.*?)["\\\']', html)
    clean = []

    for l in links:
        if l.startswith("#") or "javascript:" in l:
            continue
        clean.append(l)

    return list(set(clean))


def normalize_link(domain: str, link: str):
    if link.startswith("http"):
        return link
    if link.startswith("/"):
        return f"https://{domain}{link}"
    return f"https://{domain}/{link}"


def analyze_lgpd(domain: str) -> list[dict]:
    findings = []

    base_url = f"https://{domain}"

    # =========================
    # 🔹 HOME
    # =========================
    html = fetch(base_url)

    if not html:
        return findings

    links = extract_links(html)

    # =========================
    # 🔹 FILTRAR LINKS RELEVANTES
    # =========================
    keywords = [
        "privacidade",
        "privacy",
        "lgpd",
        "dados",
        "cookies",
        "termos",
        "policy"
    ]

    relevant_links = [
        l for l in links if any(k in l.lower() for k in keywords)
    ]

    # limita para não explodir tempo
    relevant_links = relevant_links[:MAX_LINKS]

    pages_content = [html]

    # =========================
    # 🔹 CRAWL LEVE
    # =========================
    for link in relevant_links:
        full_url = normalize_link(domain, link)
        content = fetch(full_url)

        if content:
            pages_content.append(content)

    # junta tudo
    full_text = " ".join(pages_content)

    # =========================
    # 🔹 DETECÇÕES
    # =========================

    # ✔ Política
    has_policy = any(k in full_text for k in [
        "política de privacidade",
        "privacy policy",
        "dados pessoais"
    ])

    # ✔ Portal do titular
    has_portal = any(k in full_text for k in [
        "portal do titular",
        "direitos do titular",
        "acesso aos dados",
        "solicitar dados"
    ])

    # ✔ DPO / contato real
    has_dpo = any(k in full_text for k in [
        "encarregado",
        "dpo",
        "privacidade@",
        "@",
        "contato"
    ])

    # ✔ Cookies
    has_cookies = any(k in full_text for k in [
        "cookies",
        "consent",
        "aceitar cookies",
        "gerenciar cookies"
    ])

    # =========================
    # 🔹 LÓGICA CORRETA
    # =========================

    # 🚨 Só aponta ausência TOTAL se realmente não existir nada
    if not (has_policy or has_portal):
        findings.append({
            "title": "Ausência de mecanismos mínimos de LGPD",
            "severity": "high",
            "impact": "Não foram identificados elementos mínimos de privacidade no site.",
            "recommendation": "Implementar política de privacidade e canal do titular."
        })
        return findings  # aqui pode parar

    # ⚠️ Parcial (caso mais realista)
    if not has_policy:
        findings.append({
            "title": "Política de privacidade não identificada claramente",
            "severity": "medium",
            "impact": "A política pode não estar acessível ou visível ao usuário.",
            "recommendation": "Garantir link claro para política de privacidade."
        })

    if not has_portal:
        findings.append({
            "title": "Portal do titular não identificado",
            "severity": "medium",
            "impact": "Pode dificultar o exercício dos direitos do titular.",
            "recommendation": "Disponibilizar canal estruturado para requisições LGPD."
        })

    if not has_dpo:
        findings.append({
            "title": "Canal de contato de privacidade não identificado",
            "severity": "low",
            "impact": "Usuários podem não ter canal claro para solicitações.",
            "recommendation": "Divulgar e-mail ou canal do encarregado."
        })

    if not has_cookies:
        findings.append({
            "title": "Aviso de cookies não identificado",
            "severity": "low",
            "impact": "Pode impactar transparência no uso de dados.",
            "recommendation": "Implementar banner de cookies."
        })
print("LINKS ENCONTRADOS:", links)
print("LINKS RELEVANTES:", relevant_links)
print("TEXTO FINAL (TRECHO):", full_text[:500])
    return findings