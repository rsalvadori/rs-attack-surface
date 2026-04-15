from weasyprint import HTML
from html import escape


def sev_class(severity: str) -> str:
    severity = (severity or "").lower()
    if severity == "critical":
        return "sev-critical"
    if severity == "high":
        return "sev-high"
    if severity == "medium":
        return "sev-medium"
    if severity == "low":
        return "sev-low"
    return "sev-info"


def render_findings(findings: list[dict], include_recommendation: bool = True) -> str:
    if not findings:
        return """
        <div class="item">
            <div class="item-title sev-info">[INFO] Nenhum achado relevante</div>
        </div>
        """

    blocks = []
    for f in findings:
        title = escape(str(f.get("title", "Achado")))
        severity_raw = str(f.get("severity", "info"))
        severity = escape(severity_raw.upper())
        impact = escape(str(f.get("impact", "")))
        recommendation = escape(str(f.get("recommendation", "")))

        rec_html = ""
        if include_recommendation and recommendation:
            rec_html = f'<div class="item-rec"><strong>Ação:</strong> {recommendation}</div>'

        blocks.append(f"""
        <div class="item">
            <div class="item-title {sev_class(severity_raw)}">[{severity}] {title}</div>
            <div class="item-impact">{impact}</div>
            {rec_html}
        </div>
        """)

    return "\n".join(blocks)


def generate_pdf_report(scan_result: dict, output_path: str):
    target = escape(str(scan_result.get("target", "-")))
    score = escape(str(scan_result.get("score", "-")))
    risk = escape(str(scan_result.get("risk", "-")).upper())
    security_score = escape(str(scan_result.get("security_score", "-")))
    privacy_score = escape(str(scan_result.get("privacy_score", "-")))

    infra = scan_result.get("infra", {}) or {}
    ips = infra.get("ips", []) or []
    services = infra.get("services", []) or []
    geo_map = infra.get("geo", {}) or {}
    dns = infra.get("dns", {}) or {}

    findings = scan_result.get("findings", []) or []
    top_findings = scan_result.get("top_findings", []) or []

    raw_httpx = scan_result.get("raw_httpx", {}) or {}
    httpx_status = raw_httpx.get("status_code")
    httpx_title = raw_httpx.get("title")
    httpx_webserver = raw_httpx.get("webserver")
    httpx_tech = raw_httpx.get("tech", []) or []

    executive_summary = ""
    dynamic_conclusion = ""

    try:
        from scan.context_analyzer import generate_executive_summary, generate_conclusion
        executive_summary = generate_executive_summary(scan_result) or ""
        dynamic_conclusion = generate_conclusion(scan_result) or ""
    except Exception:
        executive_summary = ""
        dynamic_conclusion = ""

    if not executive_summary:
        executive_summary = (
            "Foram identificados pontos de atenção relacionados à superfície exposta, "
            "configuração de segurança e controles de hardening, exigindo priorização técnica."
        )

    if not dynamic_conclusion:
        dynamic_conclusion = (
            "A exposição identificada indica necessidade de evolução da postura de segurança, "
            "com foco em hardening, revisão técnica e monitoramento contínuo."
        )

    executive_summary = escape(executive_summary)
    dynamic_conclusion = escape(dynamic_conclusion)

    # =========================
    # LGPD / PRIVACIDADE
    # =========================
    lgpd_findings = [
        f for f in findings
        if any(k in str(f.get("title", "")).lower() for k in [
            "privacidade", "lgpd", "cookies", "encarregado",
            "privacy", "cookie", "consent", "gdpr"
        ])
    ]

    if not lgpd_findings:
        missing_lgpd = {
            "title": "Ausência de mecanismos de LGPD",
            "severity": "high",
            "impact": "O site não apresenta política de privacidade, gestão de cookies ou canal do titular.",
            "recommendation": "Implementar política de privacidade, banner de cookies e canal de atendimento LGPD."
        }
        lgpd_findings.append(missing_lgpd)
        findings.append(missing_lgpd)

    lgpd_section = f"""
    <div class="card">
        <div class="section-title">Privacidade e LGPD</div>
        {render_findings(lgpd_findings, include_recommendation=True)}
    </div>
    """

    infra_rows = []
    if ips:
        for ip in ips:
            geo = geo_map.get(ip, {}) or {}
            country = geo.get("country")
            region = geo.get("region")
            city = geo.get("city")
            isp = geo.get("isp") or geo.get("org")

            location = ", ".join([x for x in [country, region, city] if x]) or "Não identificado"
            provider = isp or "Não identificado"

            infra_rows.append(f"""
            <div class="infra-block">
                <div><strong>IP:</strong> {escape(str(ip))}</div>
                <div><strong>Localização:</strong> {escape(location)}</div>
                <div><strong>Provedor:</strong> {escape(provider)}</div>
            </div>
            """)
    else:
        infra_rows.append("""
        <div class="infra-block">
            <div><strong>Infraestrutura:</strong> Não foi possível identificar IP público no escopo analisado.</div>
        </div>
        """)

    services_html = "<br>".join([escape(str(s)) for s in services]) if services else "Não identificado"
    dns_mx = "<br>".join([escape(str(x)) for x in dns.get("MX", [])]) if dns.get("MX") else "N/A"
    dns_ns = "<br>".join([escape(str(x)) for x in dns.get("NS", [])]) if dns.get("NS") else "N/A"

    httpx_extra = ""
    if any([httpx_status, httpx_title, httpx_webserver, httpx_tech]):
        tech_text = "<br>".join([escape(str(x)) for x in httpx_tech]) if httpx_tech else "Não identificado"

        httpx_extra = f"""
        <div class="card">
            <div class="section-title">Contexto da Aplicação</div>
            <table class="kv-table">
                <tr>
                    <td class="kv-cell">
                        <div class="kv-label">Status HTTP</div>
                        <div class="kv-value">{escape(str(httpx_status or "N/A"))}</div>
                    </td>
                    <td class="kv-cell">
                        <div class="kv-label">Servidor</div>
                        <div class="kv-value">{escape(str(httpx_webserver or "N/A"))}</div>
                    </td>
                </tr>
                <tr>
                    <td class="kv-cell" colspan="2">
                        <div class="kv-label">Título</div>
                        <div class="kv-value">{escape(str(httpx_title or "N/A"))}</div>
                    </td>
                </tr>
                <tr>
                    <td class="kv-cell" colspan="2">
                        <div class="kv-label">Tecnologias Identificadas</div>
                        <div class="kv-value">{tech_text}</div>
                    </td>
                </tr>
            </table>
        </div>
        """

    # =========================
    # VULNERABILIDADES
    # =========================
    if not findings:
        vulnerabilities_text = (
            "A análise automatizada não identificou evidências relevantes dentro do escopo analisado. "
            "Ainda assim, recomenda-se monitoramento contínuo e validações periódicas."
        )
    elif any(f.get("severity") in ["critical", "high"] for f in findings):
        vulnerabilities_text = (
            "Foram identificados achados relevantes que podem impactar diretamente a segurança do ambiente, "
            "exigindo priorização imediata na mitigação dos riscos identificados."
        )
    elif any(f.get("severity") in ["medium", "low"] for f in findings):
        vulnerabilities_text = (
            "Foram identificadas fragilidades de configuração e hardening que aumentam a superfície de ataque. "
            "Esses pontos devem ser tratados para elevar o nível de segurança."
        )
    else:
        vulnerabilities_text = (
            "Foram identificadas tecnologias e características do ambiente, incluindo mecanismos de proteção, "
            "sem evidência de falhas críticas dentro do escopo analisado."
        )

    risk_badge_color = "#f59e0b"
    if risk == "LOW":
        risk_badge_color = "#16a34a"
    elif risk == "HIGH":
        risk_badge_color = "#dc2626"
    elif risk == "CRITICAL":
        risk_badge_color = "#991b1b"

    html = f"""
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            @page {{
                size: A4;
                margin: 18mm 14mm 16mm 14mm;
            }}

            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
                color: #17202A;
                font-size: 11px;
                line-height: 1.45;
                background: #ffffff;
            }}

            .hero {{
                background: linear-gradient(135deg, #0f172a, #1e293b);
                color: white;
                border-radius: 14px;
                padding: 22px 24px;
                margin-bottom: 16px;
            }}

            .brand {{
                font-size: 14px;
                letter-spacing: .3px;
                opacity: .92;
                margin-bottom: 6px;
            }}

            .title {{
                font-size: 28px;
                font-weight: 700;
                margin: 0 0 8px 0;
            }}

            .subtitle {{
                font-size: 13px;
                opacity: .88;
                margin-bottom: 16px;
            }}

            .hero-table {{
                width: 100%;
                border-collapse: separate;
                border-spacing: 8px;
            }}

            .hero-table td {{
                background: rgba(255,255,255,0.08);
                border: 1px solid rgba(255,255,255,0.12);
                border-radius: 12px;
                padding: 12px;
                vertical-align: top;
            }}

            .hero-label {{
                font-size: 10px;
                text-transform: uppercase;
                opacity: .8;
                letter-spacing: .5px;
                margin-bottom: 6px;
            }}

            .hero-value {{
                font-size: 18px;
                font-weight: 700;
                word-break: break-word;
            }}

            .risk-badge {{
                display: inline-block;
                padding: 6px 10px;
                border-radius: 999px;
                font-weight: 700;
                font-size: 11px;
                letter-spacing: .3px;
                background: {risk_badge_color};
                color: white;
            }}

            .card {{
                background: #ffffff;
                border: 1px solid #E5E7EB;
                border-radius: 12px;
                padding: 16px 18px;
                margin-bottom: 14px;
            }}

            .section-title {{
                font-size: 15px;
                font-weight: 700;
                margin-bottom: 10px;
                color: #0f172a;
            }}

            .muted {{
                color: #475569;
            }}

            .two-col-table {{
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 14px;
            }}

            .two-col-table td {{
                width: 50%;
                vertical-align: top;
                padding: 0 6px 0 0;
            }}

            .two-col-table td:last-child {{
                padding: 0 0 0 6px;
            }}

            .kv-table {{
                width: 100%;
                border-collapse: separate;
                border-spacing: 8px;
            }}

            .kv-cell {{
                background: #F8FAFC;
                border: 1px solid #E2E8F0;
                border-radius: 10px;
                padding: 10px 12px;
                vertical-align: top;
            }}

            .kv-label {{
                display: block;
                font-size: 10px;
                text-transform: uppercase;
                letter-spacing: .4px;
                color: #64748B;
                margin-bottom: 5px;
            }}

            .kv-value {{
                display: block;
                font-size: 12px;
                font-weight: 600;
                color: #0F172A;
                word-break: break-word;
            }}

            .infra-block {{
                background: #F8FAFC;
                border: 1px solid #E2E8F0;
                border-radius: 10px;
                padding: 10px 12px;
                margin-bottom: 8px;
            }}

            .mini-table {{
                width: 100%;
                border-collapse: separate;
                border-spacing: 8px;
                margin-top: 10px;
            }}

            .mini-cell {{
                background: #F8FAFC;
                border: 1px solid #E2E8F0;
                border-radius: 10px;
                padding: 10px 12px;
                vertical-align: top;
            }}

            .mini-label {{
                font-size: 10px;
                text-transform: uppercase;
                letter-spacing: .4px;
                color: #64748B;
                margin-bottom: 5px;
            }}

            .mini-value {{
                font-size: 12px;
                font-weight: 600;
                color: #0F172A;
                word-break: break-word;
            }}

            .item {{
                border-left: 4px solid #CBD5E1;
                padding: 8px 0 8px 12px;
                margin-bottom: 10px;
            }}

            .item-title {{
                font-weight: 700;
                margin-bottom: 4px;
                font-size: 12px;
            }}

            .item-impact {{
                color: #334155;
                margin-bottom: 4px;
            }}

            .item-rec {{
                color: #0F172A;
            }}

            .sev-critical {{
                color: #991B1B;
            }}

            .sev-high {{
                color: #B91C1C;
            }}

            .sev-medium {{
                color: #B45309;
            }}

            .sev-low {{
                color: #1D4ED8;
            }}

            .sev-info {{
                color: #475569;
            }}

            .small-note {{
                color: #64748B;
                font-size: 10px;
            }}
        </style>
    </head>
    <body>

        <div class="hero">
            <div class="brand">RS Data Security</div>
            <div class="title">Relatório de Exposição Digital</div>
            <div class="subtitle">Avaliação executiva de superfície exposta, hardening, infraestrutura e sinais de risco</div>

            <table class="hero-table">
                <tr>
                    <td style="width:40%">
                        <div class="hero-label">Alvo</div>
                        <div class="hero-value" style="font-size:15px">{target}</div>
                    </td>
                    <td style="width:20%">
                        <div class="hero-label">Score</div>
                        <div class="hero-value">{score}</div>
                    </td>
                    <td style="width:20%">
                        <div class="hero-label">Risco</div>
                        <div class="risk-badge">{risk}</div>
                    </td>
                    <td style="width:20%">
                        <div class="hero-label">Segurança / Privacidade</div>
                        <div class="hero-value" style="font-size:14px">{security_score} / {privacy_score}</div>
                    </td>
                </tr>
            </table>
        </div>

        <div class="card">
            <div class="section-title">Diagnóstico Executivo</div>
            <div class="muted">{executive_summary}</div>
        </div>

        <table class="two-col-table">
            <tr>
                <td>
                    <div class="card">
                        <div class="section-title">Superfície Exposta</div>
                        {''.join(infra_rows)}

                        <table class="mini-table">
                            <tr>
                                <td class="mini-cell">
                                    <div class="mini-label">Serviços Expostos</div>
                                    <div class="mini-value">{services_html}</div>
                                </td>
                                <td class="mini-cell">
                                    <div class="mini-label">Registros MX</div>
                                    <div class="mini-value">{dns_mx}</div>
                                </td>
                            </tr>
                            <tr>
                                <td class="mini-cell" colspan="2">
                                    <div class="mini-label">Servidores DNS</div>
                                    <div class="mini-value">{dns_ns}</div>
                                </td>
                            </tr>
                        </table>
                    </div>
                </td>

                <td>
                    <div class="card">
                        <div class="section-title">Controles Prioritários</div>
                        {render_findings(top_findings, include_recommendation=True)}
                    </div>
                </td>
            </tr>
        </table>

        {httpx_extra}

        {lgpd_section}

        <div class="card">
            <div class="section-title">Análise de Vulnerabilidades</div>
            <div class="muted">{escape(vulnerabilities_text)}</div>
        </div>

        <div class="card">
            <div class="section-title">Detalhamento Técnico</div>
            {render_findings(findings, include_recommendation=False)}
        </div>

        <div class="card">
            <div class="section-title">Conclusão</div>
            <div class="muted">{dynamic_conclusion}</div>
        </div>

        <div class="small-note">
            Este relatório representa uma análise automatizada de superfície exposta e controles observáveis externamente.
            Ausência de achados críticos não elimina a necessidade de avaliação aprofundada.
        </div>

    </body>
    </html>
    """

    HTML(string=html).write_pdf(output_path)