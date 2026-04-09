def enrich_finding(finding):

    title = finding["title"]

    if "HSTS" in title:
        finding["impact"] = (
            "O site não força HTTPS, permitindo ataques de interceptação de tráfego "
            "em redes inseguras (ex: Wi-Fi público)."
        )
        finding["recommendation"] = (
            "Implementar Strict-Transport-Security (HSTS) para garantir comunicação segura."
        )

    elif "CSP" in title:
        finding["impact"] = (
            "A ausência de CSP permite execução de scripts maliciosos (XSS), "
            "podendo comprometer sessões e dados de usuários."
        )
        finding["recommendation"] = (
            "Implementar Content-Security-Policy restritiva."
        )

    elif "X-Frame-Options" in title:
        finding["impact"] = (
            "A aplicação pode ser carregada em iframes maliciosos, permitindo ataques de clickjacking."
        )
        finding["recommendation"] = (
            "Configurar X-Frame-Options ou frame-ancestors."
        )

    return finding
