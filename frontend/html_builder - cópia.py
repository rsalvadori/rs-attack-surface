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
    background: #0f172a;
    color: white;
    margin: 0;
    padding: 20px;
}}

.card {{
    background: #1e293b;
    padding: 20px;
    border-radius: 12px;
    margin-bottom: 20px;
}}

.grid {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 20px;
}}

.score-box {{
    display: flex;
    align-items: center;
    gap: 20px;
}}

.score-circle {{
    width: 100px;
    height: 100px;
    border-radius: 50%;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    font-weight: bold;
}}

.action-block {{
    border-left: 4px solid #dc2626;
    padding: 10px;
    margin-bottom: 10px;
}}
</style>

</head>

<body>

<h1>RS Attack Surface - Dashboard</h1>

<div style="display:flex; justify-content:flex-end; margin-bottom:20px;">
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
            box-shadow: 0 4px 14px rgba(0,0,0,0.25);
            transition: all 0.2s ease;
        "
        onmouseover="this.style.transform='scale(1.05)'"
        onmouseout="this.style.transform='scale(1)'"
    >
        ⬇ Baixar Relatório PDF
    </button>
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
</div>

<div class="card">
    <h3>Resumo Executivo</h3>
    <div id="executiveSummary"></div>
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

<div class="card">
    <h3>Infraestrutura</h3>
    <div id="infraContainer"></div>
</div>

<div class="card">
    <h3>Vulnerabilidades</h3>
    <div id="vulnContainer"></div>
</div>

<div class="card">
    <h3>LGPD / Risco Regulatório</h3>
    <div id="lgpdContainer"></div>
</div>

<div class="card">
    <h3>Plano de Ação</h3>
    <div id="actionPlan"></div>
</div>

<div class="card">
    <h3>Como melhorar o score</h3>
    <div id="scoreImprovement"></div>
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

// ===== DOWNLOAD PDF =====
function downloadPDF() {{
    const currentUrl = window.location.href;
    const pdfUrl = currentUrl.replace(".html", ".pdf");
    window.open(pdfUrl, "_blank");
}}

function getColor(score) {{
    if (score >= 80) return "#16a34a";
    if (score >= 60) return "#f59e0b";
    return "#dc2626";
}}

document.getElementById("scoreValue").innerText = data.score;
document.getElementById("scoreGrade").innerText = getGrade(data.score);
document.getElementById("riskLevel").innerText = data.risk.toUpperCase();
document.getElementById("scoreCircle").style.background = getColor(data.score);

// RESUMO
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
    summary += "Ausência de controles LGPD pode gerar risco regulatório, incluindo possíveis sanções da ANPD.";

document.getElementById("executiveSummary").innerText = summary;

// TOP
const topList = document.getElementById("topFindings");
data.top_findings.forEach(f => {{
    topList.innerHTML += `<li>${{f.title}}</li>`;
}});

// INFRA
function flag(c) {{
    return c === "Brazil" ? "🇧🇷" : "🌎";
}}

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

// VULNERABILIDADES
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

// LGPD
const lgpdDiv = document.getElementById("lgpdContainer");

const lgpd = data.findings.filter(f =>
    ["lgpd","privacidade","cookie","gdpr","consent","encarregado"]
    .some(k => (f.title || "").toLowerCase().includes(k))
);

if (!lgpd.length) {{
    lgpdDiv.innerHTML = `
        <div class="action-block">
            <strong>Ausência de controles LGPD</strong><br>
            Exposição regulatória relevante, incluindo risco de sanções administrativas pela ANPD e impacto reputacional.
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

// AÇÃO
const actionDiv = document.getElementById("actionPlan");

data.findings
.filter(f => ["high","medium"].includes(f.severity))
.forEach(f => {{
    actionDiv.innerHTML += `<div class="action-block">${{f.recommendation}}</div>`;
}});

// MELHORIA
const improveDiv = document.getElementById("scoreImprovement");

data.findings.forEach(f => {{
    if (["high","medium"].includes(f.severity)) {{
        improveDiv.innerHTML += `<div>${{f.title}} → ${{f.recommendation}}</div>`;
    }}
}});

// GRÁFICOS
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
            ],
            backgroundColor: [
                "#991b1b",
                "#dc2626",
                "#f59e0b",
                "#3b82f6"
            ]
        }}]
    }}
}});

</script>

</body>
</html>
"""