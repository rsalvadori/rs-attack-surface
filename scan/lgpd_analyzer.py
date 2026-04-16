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

        if r.status_code == 200:
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
   
    print(">>> EXECUTANDO LGPD ANALYZER:", domain)

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

    for l in links[:MAX_LINKS]:
        if any(k in l.lower() for k in keywords):
            content = fetch(normalize(domain, l))
            if content:
                pages.append(content)

    # =========================
    # 3. FORÇA CAMINHOS
    # =========================
    forced_paths = [
        "/politica-de-privacidade",
        "/politica",
        "/privacy",
        "/privacidade",
        "/lgpd",
        "/termos",
        "/termos-de-uso",
        "/privacy-policy"
    ]

    for p in forced_paths:
        content = fetch(base + p)
        if content:
            pages.append(content)

    # =========================
    # 4. TEXTO FINAL
    # =========================
    full = " ".join(pages)


    print("\n===== DEBUG LGPD =====")
    print("DOMAIN:", domain)
    print("FULL LENGTH:", len(full))
    print("TRECHO REAL DO SITE:")
    print(full[:1000])  # só começo pra não poluir
    print("======================\n")


    # =========================
    # 5. DETECÇÃO CORRETA
    # =========================

    # 🔥 Política (robusta)
    has_policy = bool(re.search(
        r"(pol[ií]tica.*privacidade|privacy.*policy)",
        full
    ))
    # 🔥 Portal titular (robusto)
    has_portal = bool(re.search(
        r"(portal.*titular|direitos.*titular|solicitar.*dados|acesso.*dados|request.*data|dsar)",
        full
    ))

    # 🔥 procura DPO

    has_dpo = bool(re.search(
        r"(encarregado|dpo|data protection officer|privacidade@|lgpd@|contato.*privacidade)",
        full
    ))

    # 🔥 procura Cookies
    has_cookie_banner = bool(re.search(
        r"(cookie|cookies).*(aceitar|rejeitar|gerenciar|consent|prefer)",
        full
    ))

    # =========================
    # 6. FINDINGS (AGORA FUNCIONA)
    # =========================

    if not has_policy:
        findings.append({
            "title": "Política de privacidade ausente ou não identificada",
            "severity": "medium",
            "impact": "Não foi possível identificar uma política de privacidade clara e acessível.",
            "recommendation": "Disponibilizar política de privacidade com link visível."
        })

    if not has_portal:
        findings.append({
            "title": "Canal do titular não identificado",
            "severity": "medium",
            "impact": "Não há evidência de mecanismo estruturado para atendimento ao titular.",
            "recommendation": "Implementar canal para requisições LGPD."
        })

    if not has_dpo:
        findings.append({
            "title": "Contato de privacidade não identificado",
            "severity": "low",
            "impact": "Usuários podem não ter canal direto para solicitações LGPD.",
            "recommendation": "Divulgar e-mail ou canal do encarregado (DPO)."
        })

    if not has_cookie_banner:
        findings.append({
            "title": "Banner de cookies não identificado",
            "severity": "low",
            "impact": "Não foi identificado mecanismo de consentimento de cookies.",
            "recommendation": "Implementar banner de cookies com consentimento."
        })

    # =========================
    # DEBUG
    # =========================
    print("\n===== LGPD ANALYZER RESULT =====")
    print(f"DOMAIN: {domain}")
    print(f"PAGES COLETADAS: {len(pages)}")
    print(f"TAMANHO FULL: {len(full)}")

    print("\nDETECCAO:")
    print(f"HAS POLICY: {has_policy}")
    print(f"HAS PORTAL: {has_portal}")
    print(f"HAS DPO: {has_dpo}")
    print(f"HAS COOKIES: {has_cookie_banner}")

    print("\nFINDINGS:")
    for f in findings:
        print(f"- {f['title']} ({f['severity']})")

    print("================================\n")

    print("\n===== DEBUG LGPD =====")
    print("DOMAIN:", domain)
    print("PAGES:", len(pages))
    print("FULL LENGTH:", len(full))
    
    if len(full) > 0:
        print("\nTRECHO REAL DO SITE:")
        print(full[:1000])
    else:
        print("FULL VAZIO")
    
    print("======================\n")

    return findings