from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import os

# 🔥 NOVO
from scan.context_analyzer import generate_executive_summary, generate_conclusion


def generate_score_chart(security_score, privacy_score):
    file_path = "temp_chart.png"

    labels = ["Segurança", "Privacidade"]
    values = [security_score, privacy_score]

    plt.figure(figsize=(4, 4))
    plt.bar(labels, values)
    plt.ylim(0, 100)
    plt.title("Score de Segurança")
    plt.savefig(file_path)
    plt.close()

    return file_path


def generate_pdf_report(scan_result, output_path):

    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    # =========================
    # HEADER
    # =========================
    elements.append(Paragraph("<b>RS Data Security</b>", styles["Title"]))
    elements.append(Paragraph("Relatório de Exposição Digital", styles["Heading2"]))
    elements.append(Spacer(1, 12))

    # =========================
    # INFO
    # =========================
    elements.append(Paragraph(f"<b>Alvo:</b> {scan_result['target']}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Score:</b> {scan_result['score']}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Nível de Risco:</b> {scan_result['risk'].upper()}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    # =========================
    # 🔥 DIAGNÓSTICO EXECUTIVO DINÂMICO
    # =========================
    elements.append(Paragraph("<b>Diagnóstico Executivo</b>", styles["Heading3"]))
    elements.append(Paragraph(
        generate_executive_summary(scan_result),
        styles["Normal"]
    ))
    elements.append(Spacer(1, 12))

    # =========================
    # GRÁFICO
    # =========================
    chart_path = generate_score_chart(
        scan_result["security_score"],
        scan_result["privacy_score"]
    )

    elements.append(Image(chart_path, width=3 * inch, height=3 * inch))
    elements.append(Spacer(1, 12))

    # =========================
    # INFRA
    # =========================
    elements.append(Paragraph("<b>Superfície Exposta</b>", styles["Heading3"]))

    infra = scan_result.get("infra", {})
    ips = infra.get("ips", [])

    if ips:
        for ip in ips:
            elements.append(Paragraph(f"• IP: {ip}", styles["Normal"]))

            geo = infra.get("geo", {}).get(ip)

            if geo:
                location = ", ".join(filter(None, [
                    geo.get("country"),
                    geo.get("region"),
                    geo.get("city")
                ]))

                if location:
                    elements.append(Paragraph(
                        f"Localização: {location}",
                        styles["Normal"]
                    ))

                if geo.get("isp"):
                    elements.append(Paragraph(
                        f"Provedor: {geo.get('isp')}",
                        styles["Normal"]
                    ))

            elements.append(Spacer(1, 6))

    services = infra.get("services", [])
    if services:
        elements.append(Paragraph(
            f"<b>Serviços expostos:</b> {', '.join(services)}",
            styles["Normal"]
        ))

    elements.append(Spacer(1, 12))

    # =========================
    # CONTROLES
    # =========================
    elements.append(Paragraph("<b>Controles de Segurança</b>", styles["Heading3"]))

    for f in scan_result["top_findings"]:
        elements.append(Paragraph(
            f"[{f['severity'].upper()}] {f['title']}",
            styles["Normal"]
        ))
        elements.append(Paragraph(f"Impacto: {f['impact']}", styles["Normal"]))
        elements.append(Paragraph(f"Ação: {f['recommendation']}", styles["Normal"]))
        elements.append(Spacer(1, 8))

    # =========================
    # VULNERABILIDADES
    # =========================
    elements.append(Paragraph("<b>Análise de Vulnerabilidades</b>", styles["Heading3"]))

    elements.append(Paragraph(
        "A análise automatizada foi realizada dentro de um escopo controlado e priorizando performance. "
        "A ausência de achados críticos não elimina a possibilidade de exploração, especialmente em ambientes com superfície exposta.",
        styles["Normal"]
    ))

    elements.append(Spacer(1, 12))

    # =========================
    # DETALHAMENTO
    # =========================
    elements.append(Paragraph("<b>Detalhamento Técnico</b>", styles["Heading3"]))

    for f in scan_result["findings"]:
        elements.append(Paragraph(
            f"[{f['severity'].upper()}] {f['title']}",
            styles["Normal"]
        ))
        elements.append(Paragraph(f"{f['impact']}", styles["Normal"]))
        elements.append(Spacer(1, 6))

    # =========================
    # 🔥 CONCLUSÃO DINÂMICA
    # =========================
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>Conclusão</b>", styles["Heading3"]))

    elements.append(Paragraph(
        generate_conclusion(scan_result),
        styles["Normal"]
    ))

    # =========================
    # BUILD
    # =========================
    doc.build(elements)

    if os.path.exists(chart_path):
        os.remove(chart_path)