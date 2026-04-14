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

// =========================
// BASE
// =========================
const findings = data.findings || [];

function normalizeSeverity(s) {{
    return (s || "").toLowerCase();
}}

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

function getColor(score) {{
    if (score >= 80) return "#16a34a";
    if (score >= 60) return "#f59e0b";
    return "#dc2626";
}}

const score = data.score || 0;
const currentGrade = getGrade(score);

document.getElementById("scoreValue").innerText = score;
document.getElementById("scoreGrade").innerText = currentGrade;
document.getElementById("currentGrade").innerText = currentGrade;
document.getElementById("riskLevel").innerText = (data.risk || "").toUpperCase();
document.getElementById("scoreCircle").style.background = getColor(score);

// =========================
// SELECT DINÂMICO
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

if (select.options.length > 0) {{
    select.value = select.options[0].value;
}}

// =========================
// REGRAS CORRETAS
// =========================
const rules = {{
    "A": ["critical","high","medium"],
    "B": ["critical","high"],
    "C": ["critical"],
    "D": [],
}};

// =========================
// MELHORIA CORRETA
// =========================
function recalculatePlan() {{
    const target = select.value;
    const div = document.getElementById("scoreImprovement");

    div.innerHTML = "";

    const needed = rules[target] || [];

    const blockers = findings.filter(f =>
        needed.includes(normalizeSeverity(f.severity))
    );

    div.innerHTML += `<strong>${{currentGrade}} → ${{target}}</strong><br><br>`;

    if (blockers.length === 0) {{
        div.innerHTML += `
            <div class="action-block">
                Nenhuma ação necessária para atingir este nível.
            </div>
        `;
        return;
    }}

    blockers.forEach(f => {{
        div.innerHTML += `
            <div class="action-block">
                <strong>${{f.title}}</strong><br>
                ${{f.recommendation || ""}}
            </div>
        `;
    }});
}}

recalculatePlan();
</script>

</body>
</html>
"""