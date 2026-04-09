import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def contains_any(text: str, keywords: list[str]) -> bool:
    return any(k in text for k in keywords)


def analyze_lgpd(domain: str) -> list[dict]:
    findings = []

    try:
        response = requests.get(
            f"https://{domain}",
            timeout=10,
            verify=False
        )
        html = response.text.lower()
    except Exception:
        return findings

    # =========================
    # 🔹 POLÍTICA / LGPD
    # =========================
    policy_keywords = [
        "privacidade",
        "privacy",
        "lgpd",
        "proteção de dados",
        "dados pessoais",
        "política"
    ]

    has_policy = contains_any(html, policy_keywords)

    if not has_policy:
        findings.append({
            "title": "Política de privacidade não identificada",
            "severity": "high",
            "impact": "Ausência de política pode indicar não conformidade com LGPD.",
            "recommendation": "Disponibilizar política de privacidade ou página LGPD."
        })

    # =========================
    # 🔹 COOKIES (MELHORADO)
    # =========================
    cookie_keywords = [
        "cookies",
        "aceitar",
        "rejeitar",
        "consent",
        "minhas opções"
    ]

    cookie_tools = [
        "adopt",
        "cookiebot",
        "onetrust",
        "consentmanager",
        "trustarc"
    ]

    has_cookie_text = contains_any(html, cookie_keywords)
    has_cookie_tool = contains_any(html, cookie_tools)

    if not (has_cookie_text or has_cookie_tool):
        findings.append({
            "title": "Ausência de aviso de cookies",
            "severity": "medium",
            "impact": "Pode indicar não conformidade com requisitos de transparência.",
            "recommendation": "Implementar banner de cookies."
        })

    # =========================
    # 🔹 DPO / ENCARREGADO
    # =========================
    dpo_keywords = [
        "encarregado",
        "dpo",
        "proteção de dados",
        "privacidade@",
        "contato"
    ]

    has_dpo = contains_any(html, dpo_keywords)

    if not has_dpo:
        findings.append({
            "title": "Encarregado (DPO) não identificado",
            "severity": "medium",
            "impact": "Pode indicar ausência de canal formal ao titular.",
            "recommendation": "Informar canal do encarregado (DPO)."
        })

    # =========================
    # 🔹 FORMULÁRIOS
    # =========================
    has_form = "<form" in html

    if has_form and not has_policy:
        findings.append({
            "title": "Formulário sem aviso de privacidade",
            "severity": "medium",
            "impact": "Coleta de dados sem transparência adequada.",
            "recommendation": "Adicionar aviso de privacidade em formulários."
        })

    return findings