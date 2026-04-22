from html import escape
import json


def generate_html_dashboard(scan_result: dict) -> str:
    target = escape(str(scan_result.get("target", "-")))
    json_data = json.dumps(scan_result, ensure_ascii=False).replace("</", "<\\/")

    return f"""
<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<title>RS Attack Surface</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>
body {{
    font-family: Arial;
    background: #0b1220;
    color: white;
    margin: 0;
    padding: 30px;
}}

.container {{
    max-width: 1400px;
    margin: auto;
}}

.header {{
    display:flex;
    justify-content:space-between;
    align-items:center;
    margin-bottom:30px;
}}

.title {{
    font-size:22px;
    font-weight:bold;
}}

.card {{
    background: #111827;
    padding: 20px;
    border-radius: 14px;
    margin-bottom: 20px;
}}

.grid {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 20px;
}}

.grid-main {{
    display:grid;
    grid-template-columns: 2fr 1fr;
    gap:20px;
}}

.score-box {{
    display: flex;
    align-items: center;
    gap: 20px;
}}

.score-circle {{
    width: 110px;
    height: 110px;
    border-radius: 50%;
    display:flex;
    flex-direction:column;
    justify-content:center;
    align-items:center;
    font-weight:bold;
    font-size:22px;
}}

.kpis {{
    display:grid;
    grid-template-columns: repeat(4,1fr);
    gap:15px;
}}

.kpi {{
    background:#1f2937;
    padding:15px;
    border-radius:10px;
    text-align:center;
}}

canvas {{
    max-width:220px;
    margin:auto;
}}

.action-block {{
    border-left: 4px solid #dc2626;
    padding: 10px;
    margin-bottom: 10px;
}}

.infra-block {{
    margin-bottom: 12px;
    padding-bottom: 10px;
    border-bottom: 1px solid rgba(255,255,255,0.08);
}}

.muted {{
    opacity: 0.8;
}}

.small {{
    font-size: 12px;
    opacity: 0.85;
}}

ul {{
    margin: 0;
    padding-left: 18px;
}}

li {{
    margin-bottom: 6px;
}}

select {{
    background: #1f2937;
    color: white;
    border: 1px solid #374151;
    border-radius: 8px;
    padding: 8px 10px;
}}
</style>
</head>

<body>
<div class="container">

<div class="header">
    <div class="title">RS Attack Surface</div>
</div>

<div class="card">
    <div class="score-box">
        <div class="score-circle" id="scoreCircle">
            <div id="scoreGrade"></div>
            <div id="scoreValue"></div>
        </div>

        <div>
            <div><strong>Risco:</strong> <span id="riskLevel"></span></div>
            <div><strong>Alvo:</strong> {target}</div>
        </div>
    </div>

    <div style="margin-top:15px;">
        <a id="downloadPdfBtn" href="#" target="_blank" style="
            background:#dc2626;
            color:white;
            padding:10px 16px;
            border-radius:8px;
            text-decoration:none;
            font-weight:bold;
            display:inline-block;
        ">
            ⬇ Baixar relatório em PDF
        </a>
    </div>
</div>

<div class="kpis">
    <div class="kpi">
        <h2 id="kpiVuln"></h2>
        <small>Vulnerabilidades</small>
    </div>

    <div class="kpi">
        <h2 id="kpiLgpd"></h2>
        <small>Risco LGPD</small>
    </div>

    <div class="kpi">
        <h2 id="kpiInfra"></h2>
        <small>IPs Expostos</small>
    </div>

    <div class="kpi">
        <h2 id="kpiScore"></h2>
        <small>Score</small>
    </div>
</div>

<div class="card">
    <h3>Resumo Executivo</h3>
    <div id="executiveSummary"></div>
</div>

<div class="card">
    <h3>Conclusão</h3>
    <div id="conclusion"></div>
</div>

<div class="grid">
    <div class="card">
        <h3>Score</h3>
        <canvas id="scoreChart"></canvas>
    </div>

    <div class="card">
        <h3>Severidade</h3>
        <canvas id="severityChart"></canvas>
    </div>

    <div class="card">
        <h3>Top Riscos</h3>
        <ul id="topFindings"></ul>
    </div>
</div>

<div class="grid-main">
    <div>
        <div class="card">
            <h3>Infraestrutura</h3>
            <div id="infraContainer"></div>
        </div>

        <div class="card">
            <h3>Vulnerabilidades</h3>
            <div id="vulnContainer"></div>
        </div>

        <div class="card">
            <h3>Plano de Ação</h3>
            <div id="actionPlan"></div>
        </div>
    </div>

    <div>
        <div class="card">
            <h3>LGPD / Risco Regulatório</h3>
            <div id="lgpdContainer"></div>
        </div>

        <div class="card">
            <h3>Como melhorar o score</h3>

            <div style="margin-bottom:10px;">
                <strong>Nível atual:</strong> <span id="currentGrade"></span><br>

                <strong>Quero evoluir para:</strong>
                <select id="targetGradeSelect" onchange="recalculatePlan()"></select>
            </div>

            <div id="scoreImprovement"></div>
        </div>
    </div>
</div>

</div>

<script>
const data = {json_data};

window.addEventListener("DOMContentLoaded", function () {{

    if (data.pdf_url) {{
        document.getElementById("downloadPdfBtn").href = data.pdf_url;
    }}

    document.getElementById("executiveSummary").innerText =
        data.executive_summary || "Resumo não disponível.";

    document.getElementById("conclusion").innerText =
        data.conclusion || "Conclusão não disponível.";
}});

const findings = Array.isArray(data.findings) ? data.findings : [];

function normalizeSeverity(s) {{
    return String(s || "").toLowerCase();
}}

function escapeHtml(value) {{
    return String(value || "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}}

function getGrade(score) {{
    if (score >= 90) return "A";
    if (score >= 80) return "B";
    if (score >= 70) return "C";
    if (score >= 60) return "D";
    return "E";
}}

function getColorByGrade(grade) {{
    if (grade === "A") return "#16a34a";
    if (grade === "B") return "#22c55e";
    if (grade === "C") return "#f59e0b";
    if (grade === "D") return "#f97316";
    return "#dc2626";
}}

const score = Number(data.score || 0);
const currentGrade = data.current_grade || getGrade(score);

document.getElementById("scoreValue").innerText = score;
document.getElementById("scoreGrade").innerText = currentGrade;
document.getElementById("currentGrade").innerText = currentGrade;
document.getElementById("riskLevel").innerText = String(data.risk || "").toUpperCase();
document.getElementById("scoreCircle").style.background = getColorByGrade(currentGrade);

// KPIs
document.getElementById("kpiVuln").innerText = findings.length;
document.getElementById("kpiLgpd").innerText = data.lgpd_findings_count || 0;
document.getElementById("kpiInfra").innerText = (data.infra?.ips || []).length;
document.getElementById("kpiScore").innerText = score;

// Chart
new Chart(document.getElementById("scoreChart"), {{
    type: "doughnut",
    data: {{
        labels: ["Segurança", "Privacidade"],
        datasets: [{{
            data: [
                Number(data.security_score || 0),
                Number(data.privacy_score || 0)
            ]
        }}]
    }}
}});
</script>

</body>
</html>
"""