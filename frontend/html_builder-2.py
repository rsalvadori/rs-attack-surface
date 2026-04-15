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
const findings = data.findings || [];

// =========================
// SCORE
// =========================
function getGrade(score) {{
    if (score >= 85) return "A";
    if (score >= 70) return "B";
    if (score >= 55) return "C";
    if (score >= 40) return "D";
    return "E";
}}

const score = data.score || 0;
const currentGrade = getGrade(score);

document.getElementById("scoreValue").innerText = score;
document.getElementById("scoreGrade").innerText = currentGrade;
document.getElementById("currentGrade").innerText = currentGrade;
document.getElementById("riskLevel").innerText = (data.risk || "").toUpperCase();

// =========================
// KPIs
// =========================
document.getElementById("kpiVuln").innerText = findings.length;
document.getElementById("kpiInfra").innerText = data.infra?.ips?.length || 0;
document.getElementById("kpiScore").innerText = score;

const lgpdCount = findings.filter(f => 
    (f.title || "").toLowerCase().includes("lgpd") ||
    (f.title || "").toLowerCase().includes("privacidade")
).length;

document.getElementById("kpiLgpd").innerText = lgpdCount;

// =========================
// RESUMO
// =========================
document.getElementById("executiveSummary").innerText =
    findings.length === 0
    ? "Nenhuma vulnerabilidade relevante identificada."
    : "Foram identificados pontos de melhoria no ambiente.";

// =========================
// TOP
// =========================
const topList = document.getElementById("topFindings");
(data.top_findings || []).forEach(f => {{
    topList.innerHTML += `<li>${{f.title}}</li>`;
}});

// =========================
// INFRA
// =========================
const infraDiv = document.getElementById("infraContainer");
(data.infra?.ips || []).forEach(ip => {{
    infraDiv.innerHTML += `<div>${{ip}}</div>`;
}});

// =========================
// VULN
// =========================
const vulnDiv = document.getElementById("vulnContainer");
findings.forEach(f => {{
    vulnDiv.innerHTML += `
        <div class="action-block">
            <strong>${{f.title}}</strong><br>
            ${{f.impact || ""}}
        </div>
    `;
}});

// =========================
// ACTION
// =========================
const actionDiv = document.getElementById("actionPlan");
findings.forEach(f => {{
    actionDiv.innerHTML += `
        <div class="action-block">
            ${{f.recommendation || ""}}
        </div>
    `;
}});

// =========================
// LGPD
// =========================
const lgpdDiv = document.getElementById("lgpdContainer");
findings.forEach(f => {{
    if ((f.title || "").toLowerCase().includes("lgpd")) {{
        lgpdDiv.innerHTML += `<div class="action-block">${{f.title}}</div>`;
    }}
}});

// =========================
// SELECT
// =========================
const upgradePaths = {{
    "E": ["D","C","B","A"],
    "D": ["C","B","A"],
    "C": ["B","A"],
    "B": ["A"],
    "A": []
}};

const select = document.getElementById("targetGradeSelect");

(upgradePaths[currentGrade] || []).forEach(g => {{
    const opt = document.createElement("option");
    opt.value = g;
    opt.text = g;
    select.appendChild(opt);
}});

// =========================
// MELHORIA
// =========================
function recalculatePlan() {{
    const target = select.value;
    const div = document.getElementById("scoreImprovement");
    div.innerHTML = `<strong>${{currentGrade}} → ${{target}}</strong>`;
}}

recalculatePlan();
</script>

</body>
</html>
"""