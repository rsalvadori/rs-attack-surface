import re
import requests
import urllib3
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 8
MAX_LINKS = 20
MIN_HTML_LEN = 500

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/123.0.0.0 Safari/537.36"
)


def _clean_text(value: str) -> str:
    if not value:
        return ""
    value = value.lower()
    value = re.sub(r"<script.*?</script>", " ", value, flags=re.DOTALL | re.IGNORECASE)
    value = re.sub(r"<style.*?</style>", " ", value, flags=re.DOTALL | re.IGNORECASE)
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def _fetch(url: str) -> str:
    try:
        r = requests.get(
            url,
            timeout=TIMEOUT,
            verify=False,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
        )
        if r.status_code == 200 and r.text:
            return r.text.lower()
    except Exception:
        pass
    return ""


def _extract_links(html: str, base_url: str) -> list[str]:
    if not html:
        return []

    hrefs = re.findall(r'href=["\'](.*?)["\']', html, flags=re.IGNORECASE)
    results = []

    for href in hrefs:
        href = (href or "").strip()
        if not href:
            continue
        if href.startswith("#"):
            continue
        if href.startswith("javascript:"):
            continue
        if href.startswith("mailto:"):
            continue
        if href.startswith("tel:"):
            continue

        full = urljoin(base_url, href)
        results.append(full)

    seen = set()
    unique = []
    for item in results:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def _maybe_render_with_playwright(url: str) -> str:
    """
    Tenta renderizar o site com Playwright.
    Se Playwright não estiver disponível ou falhar, retorna string vazia.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return ""

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(user_agent=USER_AGENT)
            page.goto(url, wait_until="networkidle", timeout=20000)
            page_text = page.content().lower()
            browser.close()
            return page_text
    except Exception:
        return ""


def _collect_candidate_pages(domain: str) -> list[dict]:
    base_url = f"https://{domain}"
    pages: list[dict] = []

    # 1. Home via requests
    home_html = _fetch(base_url)
    if home_html:
        pages.append({"url": base_url, "html": home_html, "source": "requests-home"})

    # 2. Links relevantes encontrados na home
    relevant_keywords = [
        "privacidade", "privacy", "lgpd", "dados", "policy",
        "cookies", "termos", "contato", "contact", "encarregado",
        "dpo", "titular", "dsar"
    ]

    links = _extract_links(home_html, base_url) if home_html else []
    relevant_links = [
        link for link in links
        if any(k in link.lower() for k in relevant_keywords)
    ][:MAX_LINKS]

    for link in relevant_links:
        html = _fetch(link)
        if html:
            pages.append({"url": link, "html": html, "source": "requests-link"})

    # 3. Paths comuns forçados
    forced_paths = [
        "/politica-de-privacidade",
        "/politica",
        "/privacy",
        "/privacy-policy",
        "/privacidade",
        "/lgpd",
        "/cookies",
        "/cookie-policy",
        "/termos",
        "/termos-de-uso",
        "/contato",
        "/contact",
    ]

    for path in forced_paths:
        url = urljoin(base_url, path)
        html = _fetch(url)
        if html:
            pages.append({"url": url, "html": html, "source": "requests-forced"})

    # 4. Se o HTML veio pobre ou inconclusivo, tenta Playwright na home
    combined_html = " ".join(p["html"] for p in pages if p["html"])
    if len(combined_html) < MIN_HTML_LEN or "wix.com website builder" in combined_html:
        rendered = _maybe_render_with_playwright(base_url)
        if rendered:
            pages.append({"url": base_url, "html": rendered, "source": "playwright-home"})

            rendered_links = _extract_links(rendered, base_url)
            rendered_relevant = [
                link for link in rendered_links
                if any(k in link.lower() for k in relevant_keywords)
            ][:MAX_LINKS]

            for link in rendered_relevant:
                rendered_link_html = _maybe_render_with_playwright(link)
                if rendered_link_html:
                    pages.append({"url": link, "html": rendered_link_html, "source": "playwright-link"})

    # remove duplicados por URL + source
    seen = set()
    unique_pages = []
    for page in pages:
        key = (page["url"], page["source"])
        if key not in seen:
            seen.add(key)
            unique_pages.append(page)

    return unique_pages


def _detect_policy(full_html: str, full_text: str) -> bool:
    patterns = [
        r"pol[ií]tica.{0,40}privacidade",
        r"privacy.{0,20}policy",
        r"aviso.{0,20}privacidade",
    ]
    return any(re.search(p, full_text, flags=re.IGNORECASE) for p in patterns)


def _detect_dpo(full_html: str, full_text: str) -> bool:
    patterns = [
        r"\bencarregado\b",
        r"\bdpo\b",
        r"data protection officer",
        r"lgpd@",
        r"privacidade@",
        r"contato.{0,30}privacidade",
        r"fale.{0,20}encarregado",
    ]
    return any(re.search(p, full_text, flags=re.IGNORECASE) for p in patterns)


def _detect_cookie_banner(full_html: str, full_text: str) -> bool:
    html_patterns = [
        r"onetrust",
        r"cookiebot",
        r"trustarc",
        r"consentmanager",
        r"didomi",
        r"cookie[-_ ]banner",
        r"cookie[-_ ]consent",
    ]

    text_patterns = [
        r"aceitar.{0,20}cookies",
        r"rejeitar.{0,20}cookies",
        r"gerenciar.{0,20}cookies",
        r"prefer[eê]ncias.{0,20}cookies",
        r"utilizamos.{0,20}cookies",
        r"este site.{0,20}cookies",
    ]

    html_hit = any(re.search(p, full_html, flags=re.IGNORECASE) for p in html_patterns)
    text_hit = any(re.search(p, full_text, flags=re.IGNORECASE) for p in text_patterns)
    return html_hit or text_hit


def analyze_lgpd(domain: str) -> list[dict]:
    print(f">>> EXECUTANDO LGPD ANALYZER: {domain}")

    pages = _collect_candidate_pages(domain)

    full_html = " ".join(page["html"] for page in pages if page["html"])
    full_text = _clean_text(full_html)

    print("\n===== LGPD ANALYZER DEBUG =====")
    print("DOMAIN:", domain)
    print("PAGES COLETADAS:", len(pages))
    print("FULL HTML LENGTH:", len(full_html))
    print("FULL TEXT LENGTH:", len(full_text))
    for idx, page in enumerate(pages[:10], start=1):
        print(f"[{idx}] {page['source']} -> {page['url']}")
    print("===============================\n")

    findings = []

    if not full_html.strip():
        findings.append({
            "title": "Site não acessível ou bloqueando análise",
            "severity": "high",
            "impact": "Não foi possível coletar conteúdo suficiente para validação automática de LGPD.",
            "recommendation": "Verificar bloqueios, proteção anti-bot ou adotar crawler com renderização completa."
        })
        return findings

    has_policy = _detect_policy(full_html, full_text)
    has_dpo = _detect_dpo(full_html, full_text)
    has_cookie_banner = _detect_cookie_banner(full_html, full_text)

    print("HAS POLICY:", has_policy)
    print("HAS DPO:", has_dpo)
    print("HAS COOKIES:", has_cookie_banner)

    if not has_policy:
        findings.append({
            "title": "Política de privacidade ausente ou não identificada",
            "severity": "medium",
            "impact": "Não foi possível identificar política de privacidade clara e acessível ao usuário.",
            "recommendation": "Disponibilizar política de privacidade com link visível no site."
        })

    if not has_dpo:
        findings.append({
            "title": "Contato de privacidade não identificado",
            "severity": "low",
            "impact": "Não foi possível identificar canal claro do encarregado/DPO.",
            "recommendation": "Divulgar e-mail ou canal de contato para assuntos de privacidade e LGPD."
        })

    if not has_cookie_banner:
        findings.append({
            "title": "Banner de cookies não identificado",
            "severity": "low",
            "impact": "Não foi identificado mecanismo claro de consentimento/gestão de cookies.",
            "recommendation": "Implementar banner de cookies com aceitação, rejeição ou gestão de preferências."
        })

    print("FINDINGS LGPD:", findings)
    return findings