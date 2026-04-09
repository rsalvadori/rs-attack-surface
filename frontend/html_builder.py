from html import escape
import json


def generate_html_dashboard(scan_result: dict) -> str:
    target = escape(str(scan_result.get("target", "-")))
    json_data = json.dumps(scan_result)

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

</style>

</head>

<body>

<div class="container">

<!-- HEADER -->
<div class="header">
    <div class="title">RS Attack Surface</div>

    <button onclick="downloadPDF()" 
        style="
            background: linear-gradient(135deg, #22c55e, #16a34a);
            border: none;
            padding: 10px 18px;
            border-radius: 999px;
            color: white;
            cursor: pointer;
            font-weight: 600;
            font-size: 13px;
        ">
        ⬇ Baixar PDF
    </button>
</div>

<!-- SCORE -->
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
</div>

<!-- KPI CARDS (ADICIONADO) -->
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

<!-- RESUMO (mantido) -->
<div class="card">
    <h3>Resumo Executivo</h3>
    <div id="executiveSummary"></div>
</div>

<!-- TOP GRID -->
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

<!-- MAIN SPLIT -->
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
    <div id="scoreImprovement"></div>
</div>

</div>

</div>

</div>

<script>

const data = {json_data};

// SCORE
function getGrade(score) {{
    if (score >= 90) return "A";
    if (score >= 80) return "B";
    if (score >= 70) return "C";
    if (score >= 60) return "D";
    return "E";
}}

function getColor(score) {{
    if (score >= 80) return "#16a34a";
    if (score >= 60) return "#f59e0b";
    return "#dc2626";
}}

// PDF
function downloadPDF() {{
    const pdfUrl = window.location.href.replace(".html", ".pdf");
    window.open(pdfUrl);
}}

document.getElementById("scoreValue").innerText = data.score;
document.getElementById("scoreGrade").innerText = getGrade(data.score);
document.getElementById("riskLevel").innerText = data.risk.toUpperCase();
document.getElementById("scoreCircle").style.background = getColor(data.score);

// KPIs
document.getElementById("kpiVuln").innerText = data.findings.length;
document.getElementById("kpiLgpd").innerText =
data.findings.filter(f => (f.title || "").toLowerCase().includes("lgpd")).length;

document.getElementById("kpiInfra").innerText = data.infra?.ips?.length || 0;
document.getElementById("kpiScore").innerText = data.score;

// RESUMO (mantido)
let summary = "";

if (data.score < 60)
    summary += "Ambiente com alto risco e exposição relevante. ";
else if (data.score < 80)
    summary += "Ambiente com maturidade intermediária, com gaps de segurança. ";
else
    summary += "Ambiente com boa postura de segurança. ";

if (data.findings.some(f => f.severity === "high"))
    summary += "Existem vulnerabilidades críticas que exigem ação imediata. ";

if (!data.findings.some(f => (f.title || "").toLowerCase().includes("lgpd")))
    summary += "Ausência de controles LGPD pode gerar risco regulatório.";

document.getElementById("executiveSummary").innerText = summary;

// TOP
const topList = document.getElementById("topFindings");
data.top_findings.forEach(f => {{
    topList.innerHTML += `<li>${{f.title}}</li>`;
}});

// INFRA
const infraDiv = document.getElementById("infraContainer");

(data.infra?.ips || []).forEach(ip => {{
    const geo = data.infra.geo[ip] || {{}};

    infraDiv.innerHTML += `
        <div style="margin-bottom:10px;">
            <strong>${{ip}}</strong><br>
            🌎 ${{geo.country || "N/A"}} - ${{geo.city || ""}}<br>
            <small>${{geo.isp || ""}}</small>
        </div>
    `;
}});

// VULNS (mantido)
const vulnDiv = document.getElementById("vulnContainer");

data.findings.forEach(f => {{
    let border = "#334155";
    if (f.severity === "high") border = "#dc2626";
    else if (f.severity === "medium") border = "#f59e0b";

    vulnDiv.innerHTML += `
        <div style="border-left:4px solid ${{border}}; padding:10px; margin-bottom:10px;">
            <strong>${{f.title}}</strong><br>
            Severidade: ${{f.severity}}<br>
            ${{f.impact || ""}}
        </div>
    `;
}});

// LGPD (mantido)
const lgpdDiv = document.getElementById("lgpdContainer");

const lgpd = data.findings.filter(f =>
    ["lgpd","privacidade","cookie","gdpr","consent","encarregado"]
    .some(k => (f.title || "").toLowerCase().includes(k))
);

if (!lgpd.length) {{
    lgpdDiv.innerHTML = `
        <div class="action-block">
            <strong>Ausência de controles LGPD</strong><br>
            Exposição regulatória relevante.
        </div>
    `;
}} else {{
    lgpd.forEach(f => {{
        lgpdDiv.innerHTML += `
            <div class="action-block">
                <strong>${{f.title}}</strong><br>
                ${{f.recommendation}}
            </div>
        `;
    }});
}}

// ACTION (mantido)
const actionDiv = document.getElementById("actionPlan");

data.findings
.filter(f => ["high","medium"].includes(f.severity))
.forEach(f => {{
    actionDiv.innerHTML += `<div class="action-block">${{f.recommendation}}</div>`;
}});

// MELHORIA (mantido)
const improveDiv = document.getElementById("scoreImprovement");

data.findings.forEach(f => {{
    if (["high","medium"].includes(f.severity)) {{
        improveDiv.innerHTML += `<div>${{f.title}} → ${{f.recommendation}}</div>`;
    }}
}});

// CHARTS
new Chart(document.getElementById('scoreChart'), {{
    type: 'doughnut',
    data: {{
        labels: ['Segurança','Privacidade'],
        datasets: [{{
            data: [data.security_score, data.privacy_score]
        }}]
    }}
}});

const counts = {{critical:0, high:0, medium:0, low:0}};

data.findings.forEach(f => {{
    if (counts[f.severity] !== undefined)
        counts[f.severity]++;
}});

new Chart(document.getElementById('severityChart'), {{
    type: 'doughnut',
    data: {{
        labels: ['Critical','High','Medium','Low'],
        datasets: [{{
            data: [
                counts.critical,
                counts.high,
                counts.medium,
                counts.low
            ]
        }}]
    }}
}});

</script>

</body>
</html>
"""