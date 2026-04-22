def enrich_finding(finding):

    title = str(finding.get("title", "")).lower()

    # Não sobrescrever se já existe
    if finding.get("impact") and finding.get("recommendation"):
        return finding

    if "hsts" in title:
        finding["impact"] = (
            "O site não força HTTPS, permitindo interceptação de tráfego em redes inseguras."
        )
        finding["recommendation"] = (
            "Implementar Strict-Transport-Security (HSTS)."
        )

    elif "csp" in title:
        finding["impact"] = (
            "Ausência de CSP permite execução de scripts maliciosos (XSS)."
        )
        finding["recommendation"] = (
            "Implementar Content-Security-Policy restritiva."
        )

    elif "x-frame" in title:
        finding["impact"] = (
            "Aplicação pode ser carregada em iframe malicioso (clickjacking)."
        )
        finding["recommendation"] = (
            "Configurar X-Frame-Options ou frame-ancestors."
        )

    elif "tls" in title:
        finding.setdefault("impact", "Uso de protocolos inseguros compromete a criptografia.")
        finding.setdefault("recommendation", "Utilizar TLS 1.2 ou superior.")

    elif "cipher" in title:
        finding.setdefault("impact", "Uso de cifragem fraca reduz segurança da comunicação.")
        finding.setdefault("recommendation", "Remover suites fracas e usar AES-GCM ou ChaCha20.")

    elif "certificate" in title or "ssl" in title:
        finding.setdefault("impact", "Problemas no certificado comprometem a confiança.")
        finding.setdefault("recommendation", "Corrigir certificado SSL.")

    return finding