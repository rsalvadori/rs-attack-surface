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

document.getElementById("currentGrade").innerText = data.current_grade;

const select = document.getElementById("targetGradeSelect");

(data.allowed_upgrade_targets || []).forEach(g => {{
    const opt = document.createElement("option");
    opt.value = g;
    opt.text = g;
    select.appendChild(opt);
}});

// 👉 ADICIONA ISSO
if (select.options.length > 0) {{
    select.value = select.options[0].value;
}}

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

function downloadPDF() {{
    const pdfUrl = window.location.href.replace(".html", ".pdf");
    window.open(pdfUrl);
}}

// 🔥 Regra única para identificar LGPD/privacidade
function isLgpdFinding(f) {{
    const text = `${{f.title || ""}} ${{f.impact || ""}} ${{f.recommendation || ""}}`.toLowerCase();

    return [
        "lgpd",
        "privacidade",
        "privacy",
        "cookie",
        "cookies",
        "gdpr",
        "consent",
        "encarregado",
        "dpo",
        "titular",
        "política de privacidade",
        "aviso de cookies"
    ].some(k => text.includes(k));
}}

const lgpdFindings = data.findings.filter(isLgpdFinding);

// SCORE
document.getElementById("scoreValue").innerText = data.score;
document.getElementById("scoreGrade").innerText = getGrade(data.score);
document.getElementById("riskLevel").innerText = (data.risk || "").toUpperCase();
document.getElementById("scoreCircle").style.background = getColor(data.score);

// KPIs
document.getElementById("kpiVuln").innerText = data.findings.length;
document.getElementById("kpiLgpd").innerText = lgpdFindings.length;
document.getElementById("kpiInfra").innerText = data.infra?.ips?.length || 0;
document.getElementById("kpiScore").innerText = data.score;

// RESUMO
let summary = "";

if (data.score < 60)
    summary += "Ambiente com alto risco e exposição relevante. ";
else if (data.score < 80)
    summary += "Ambiente com maturidade intermediária, com gaps de segurança. ";
else
    summary += "Ambiente com boa postura de segurança. ";

if (data.findings.some(f => ["high", "critical"].includes(f.severity)))
    summary += "Existem vulnerabilidades críticas que exigem ação imediata. ";

if (lgpdFindings.length > 0)
    summary += "Existem achados de privacidade/LGPD com potencial risco regulatório. ";

document.getElementById("executiveSummary").innerText = summary.trim();

// TOP
const topList = document.getElementById("topFindings");
(data.top_findings || []).forEach(f => {{
    topList.innerHTML += `<li>${{f.title}}</li>`;
}});

// INFRA
const infraDiv = document.getElementById("infraContainer");
(data.infra?.ips || []).forEach(ip => {{
    const geo = data.infra?.geo?.[ip] || {{}};

    infraDiv.innerHTML += `
        <div style="margin-bottom:10px;">
            <strong>${{ip}}</strong><br>
            🌎 ${{geo.country || "N/A"}} - ${{geo.city || ""}}<br>
            <small>${{geo.isp || ""}}</small>
        </div>
    `;
}});

// VULNS
const vulnDiv = document.getElementById("vulnContainer");
(data.findings || []).forEach(f => {{
    let border = "#334155";
    if (f.severity === "critical" || f.severity === "high") border = "#dc2626";
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

if (!lgpdFindings.length) {{
    lgpdDiv.innerHTML = `
        <div class="action-block">
            <strong>Sem achados específicos de LGPD</strong><br>
            Nenhum indicador regulatório relevante foi identificado neste relatório.
        </div>
    `;
}} else {{
    lgpdFindings.forEach(f => {{
        lgpdDiv.innerHTML += `
            <div class="action-block">
                <strong>${{f.title}}</strong><br>
                ${{f.recommendation || ""}}
            </div>
        `;
    }});
}}

// ACTION
const actionDiv = document.getElementById("actionPlan");

const baseFixes = (data.findings || []).filter(f =>
    ["critical", "high"].includes(f.severity)
);

    baseFixes.forEach(f => {{
        actionDiv.innerHTML += `
            <div class="action-block">
                ${{f.recommendation || ""}}
            </div>
        `;
    }});

// MELHORIA
function recalculatePlan() {{
    const target = document.getElementById("targetGradeSelect").value;
    const div = document.getElementById("scoreImprovement");

    div.innerHTML = "";

    if (!target) return;

    const rules = {{
        "A": f => ["critical", "high"].includes(f.severity),
        "B": f => ["critical"].includes(f.severity),
        "C": f => ["critical"].includes(f.severity),
        "D": f => false
    }};

    const violations = (data.findings || []).filter(f => rules[target](f));

    if (violations.length === 0) {{
        div.innerHTML = "<div>Você já atende os critérios para esse nível.</div>";
        return;
    }}

    violations.forEach(f => {{
        div.innerHTML += `
            <div class="action-block">
                <strong>${{f.title}}</strong><br>
                ${{f.recommendation || ""}}
            </div>
        `;
    }});
}}

// CHARTS
recalculatePlan();
new Chart(document.getElementById('scoreChart'), {{
    type: 'doughnut',
    data: {{
        labels: ['Segurança','Privacidade'],
        datasets: [{{
            data: [data.security_score, data.privacy_score]
        }}]
    }}
}});

const counts = {{critical:0, high:0, medium:0, low:0, info:0}};
(data.findings || []).forEach(f => {{
    if (counts[f.severity] !== undefined) counts[f.severity]++;
}});

new Chart(document.getElementById('severityChart'), {{
    type: 'doughnut',
    data: {{
        labels: ['Critical','High','Medium','Low','Info'],
        datasets: [{{
            data: [
                counts.critical,
                counts.high,
                counts.medium,
                counts.low,
                counts.info
            ]
        }}]
    }}
}});
</script>

</body>
</html>
"""