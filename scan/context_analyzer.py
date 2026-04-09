def generate_executive_summary(scan):

    infra = scan.get("infra", {})
    findings = scan.get("findings", [])
    services = infra.get("services", [])
    geo = infra.get("geo", {})

    summary = []

    # -------------------------
    # SERVIÇOS EXPOSTOS
    # -------------------------
    if services:
        summary.append(
            f"Foram identificados serviços expostos publicamente ({', '.join(services)}), ampliando a superfície de ataque."
        )

    # -------------------------
    # INFRA / GEO
    # -------------------------
    if geo:
        for ip, g in geo.items():
            provider = g.get("isp") or "provedor externo"
            summary.append(
                f"A infraestrutura está hospedada em ambiente de terceiros ({provider}), o que exige controles adicionais de segurança e monitoramento."
            )
            break

    # -------------------------
    # CONTROLES FALTANTES
    # -------------------------
    missing_controls = [f for f in findings if f["severity"] == "medium"]

    if missing_controls:
        summary.append(
            "Foram identificadas falhas de hardening, incluindo ausência de headers de segurança essenciais, aumentando o risco de exploração."
        )

    # -------------------------
    # EXPOSIÇÃO REAL
    # -------------------------
    if any("HSTS" in f["title"] for f in findings):
        summary.append(
            "A ausência de HSTS permite ataques de interceptação de tráfego em redes não confiáveis."
        )

    if any("CSP" in f["title"] for f in findings):
        summary.append(
            "A ausência de CSP permite execução de scripts maliciosos, podendo comprometer sessões de usuários."
        )

    return " ".join(summary)


def generate_conclusion(scan):

    score = scan.get("score", 100)
    services = scan.get("infra", {}).get("services", [])
    findings = scan.get("findings", [])

    conclusion = []

    if score < 70:
        conclusion.append(
            "A postura de segurança atual apresenta fragilidades relevantes."
        )

    if services:
        conclusion.append(
            f"A exposição direta de serviços ({', '.join(services)}) aumenta a superfície de ataque."
        )

    if any(f["severity"] in ["medium", "high"] for f in findings):
        conclusion.append(
            "A ausência de controles básicos de segurança indica necessidade imediata de hardening."
        )

    conclusion.append(
        "Recomenda-se a implementação de controles técnicos, revisão de arquitetura e monitoramento contínuo da superfície externa."
    )

    return " ".join(conclusion)
