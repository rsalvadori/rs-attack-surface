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
<div class="header" style="
    display:flex;
    justify-content:space-between;
    align-items:center;
    margin-bottom:30px;
    padding-bottom:12px;
    border-bottom:1px solid rgba(255,255,255,0.08);
">

    <div style="display:flex; align-items:center; gap:12px;">
        <img src="/frontend/logo.png" style="height:38px;">
        <div style="font-size:12px; opacity:0.7;">Attack Surface Intelligence</div>
    </div>

    <div style="display:flex; gap:16px; align-items:center;">

        <a href="mailto:comercial@rsdatasecurity.com.br" style="
            background: linear-gradient(135deg, #22c55e, #16a34a);
            color:#0b1220;
            padding:6px 12px;
            border-radius:6px;
            text-decoration:none;
            font-weight:bold;
            font-size:13px;
        ">
            Fale com especialista
        </a>

        <a href="https://rsdatasecurity.com.br" target="_blank" style="
            color:#4ade80;
            text-decoration:none;
            font-size:13px;
            font-weight:bold;
        ">
            Nosso site →
        </a>

    </div>

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
const reportId = data.report_id;
let nucleiLoaded = false;
window.addEventListener("DOMContentLoaded", function () {{
    if (data.pdf_url) {{
        const btn = document.getElementById("downloadPdfBtn");
        if (btn) {{
            btn.href = data.pdf_url;
        }}
    }}
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
    if (score >= 85) return "A";
    if (score >= 70) return "B";
    if (score >= 55) return "C";
    if (score >= 40) return "D";
    return "E";
}}

function getColorByGrade(grade) {{
    if (grade === "A") return "#16a34a"; // verde
    if (grade === "B") return "#22c55e"; // verde claro
    if (grade === "C") return "#f59e0b"; // amarelo
    if (grade === "D") return "#f97316"; // laranja
    return "#dc2626"; // E vermelho
}}

function isLgpdFinding(f) {{
    if ((f.type || "").toLowerCase() === "privacy") return true;

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

function uniqByTitle(items) {{
    const seen = new Set();
    return items.filter(item => {{
        const key = `${{item.title || ""}}|${{item.recommendation || ""}}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    }});
}}

const score = Number(data.score || 0);
const currentGrade = getGrade(score);
const lgpdFindings = uniqByTitle(findings.filter(isLgpdFinding));
const securityFindings = uniqByTitle(findings.filter(f => !isLgpdFinding(f)));

document.getElementById("scoreValue").innerText = score;
document.getElementById("scoreGrade").innerText = currentGrade;
document.getElementById("currentGrade").innerText = currentGrade;
document.getElementById("riskLevel").innerText = String(data.risk || "").toUpperCase();
document.getElementById("scoreCircle").style.background = getColorByGrade(currentGrade);

// KPIs
document.getElementById("kpiVuln").innerText = findings.length;
document.getElementById("kpiLgpd").innerText = lgpdFindings.length;
document.getElementById("kpiInfra").innerText = (data.infra && Array.isArray(data.infra.ips)) ? data.infra.ips.length : 0;
document.getElementById("kpiScore").innerText = score;

// Resumo
let summary = "";

if (score < 60) {{
    summary += "Ambiente com alto risco e exposição relevante. ";
}} else if (score < 80) {{
    summary += "Ambiente com maturidade intermediária, com gaps de segurança. ";
}} else {{
    summary += "Ambiente com boa postura de segurança. ";
}}

if (findings.some(f => ["critical", "high"].includes(normalizeSeverity(f.severity)))) {{
    summary += "Existem vulnerabilidades críticas que exigem ação imediata. ";
}}

if (lgpdFindings.length > 0) {{
    summary += "Existem achados de privacidade/LGPD com potencial risco regulatório. ";
}}

if (!summary.trim()) {{
    summary = "Nenhum achado relevante foi identificado no escopo analisado.";
}}

document.getElementById("executiveSummary").innerText = summary.trim();

// Top riscos
const topList = document.getElementById("topFindings");
const topFindings = Array.isArray(data.top_findings) && data.top_findings.length
    ? data.top_findings
    : findings
        .filter(f => normalizeSeverity(f.severity) !== "info")
        .slice(0, 3);

if (!topFindings.length) {{
    topList.innerHTML = "<li>Nenhum risco relevante identificado.</li>";
}} else {{
    topFindings.forEach(f => {{
        topList.innerHTML += `<li>${{escapeHtml(f.title)}}</li>`;
    }});
}}

// Infraestrutura
const infraDiv = document.getElementById("infraContainer");
const ips = (data.infra && Array.isArray(data.infra.ips)) ? data.infra.ips : [];
const geoMap = (data.infra && data.infra.geo) ? data.infra.geo : {{}};
const services = (data.infra && Array.isArray(data.infra.services)) ? data.infra.services : [];

if (!ips.length) {{
    infraDiv.innerHTML = `<div class="muted">Nenhum IP exposto identificado.</div>`;
}} else {{
    ips.forEach(ip => {{
        const geo = geoMap[ip] || {{}};
        infraDiv.innerHTML += `
            <div class="infra-block">
                <strong>${{escapeHtml(ip)}}</strong><br>
                <span class="small">🌎 ${{escapeHtml(geo.country || "N/A")}} - ${{escapeHtml(geo.city || "")}}</span><br>
                <span class="small">${{escapeHtml(geo.isp || geo.org || "")}}</span>
            </div>
        `;
    }});
}}

if (services.length) {{
    infraDiv.innerHTML += `
        <div class="infra-block">
            <strong>Serviços expostos</strong><br>
            <span class="small">${{escapeHtml(services.join(", "))}}</span>
        </div>
    `;
}}

// Vulnerabilidades
const vulnDiv = document.getElementById("vulnContainer");

// 1. Renderiza findings normais
if (!findings.length) {{
    vulnDiv.innerHTML = `<div class="muted">Nenhuma vulnerabilidade identificada.</div>`;
}} else {{
    findings.forEach(f => {{
        let border = "#334155";
        const sev = normalizeSeverity(f.severity);

        if (sev === "critical" || sev === "high") border = "#dc2626";
        else if (sev === "medium") border = "#f59e0b";

        vulnDiv.innerHTML += `
            <div style="border-left:4px solid ${{border}}; padding:10px; margin-bottom:10px;">
                <strong>${{escapeHtml(f.title)}}</strong><br>
                <span class="small">Severidade: ${{escapeHtml(f.severity || "")}}</span><br>
                ${{escapeHtml(f.evidence || "")}}
            </div>
        `;
    }});
}}

// 2. NUCLEI (LOADING + RESULTADO INICIAL)
if (!data.nuclei_done) {{

    vulnDiv.innerHTML += `
        <div class="action-block">
            🔍 Executando análise aprofundada (Nuclei)...
        </div>
    `;

}} else if (data.nuclei_findings && data.nuclei_findings.length) {{

    data.nuclei_findings.forEach(f => {{
        vulnDiv.innerHTML += `
            <div class="action-block">
                <strong>${{escapeHtml(f.title)}}</strong><br>
                ${{escapeHtml(f.severity || "")}}
            </div>
        `;
    }});

}}

// Plano de ação
const actionDiv = document.getElementById("actionPlan");
const actionable = uniqByTitle(findings.filter(f => String(f.recommendation || "").trim() !== ""));

if (!actionable.length) {{
    actionDiv.innerHTML = `<div class="muted">Nenhuma ação recomendada no momento.</div>`;
}} else {{
    actionable.forEach(f => {{
        actionDiv.innerHTML += `
            <div class="action-block">
                <strong>${{escapeHtml(f.title)}}</strong><br>
                ${{escapeHtml(f.recommendation || "")}}
            </div>
        `;
    }});
}}

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
                <strong>${{escapeHtml(f.title)}}</strong><br>
                ${{escapeHtml(f.recommendation || f.impact || "")}}
            </div>
        `;
    }});
}}

// Select de melhoria
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

// Melhoria de score
function recalculatePlan() {{
    const target = select.value;
    const div = document.getElementById("scoreImprovement");

    div.innerHTML = "";

    const rules = {{
        "D": ["critical"],
        "C": ["critical", "high"],
            "B": ["critical", "high", "medium"],
    "A": ["critical", "high", "medium", "low"]
    }};

    const needed = rules[target] || [];
    const blockers = uniqByTitle(findings.filter(f =>
        needed.includes(normalizeSeverity(f.severity))
    ));

    div.innerHTML += `<strong>${{currentGrade}} → ${{target}}</strong><br><br>`;

    if (!blockers.length) {{
        div.innerHTML += `
            <div class="action-block">
                Nenhuma ação crítica necessária para este nível.
            </div>
        `;
        return;
    }}

    blockers.forEach(f => {{
        div.innerHTML += `
            <div class="action-block">
                <strong>${{escapeHtml(f.title)}}</strong><br>
                ${{escapeHtml(f.recommendation || f.impact || "")}}
            </div>
        `;
    }});
}}

recalculatePlan();

// Gráfico score
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

// Gráfico severidade
const counts = {{ critical: 0, high: 0, medium: 0, low: 0, info: 0 }};

findings.forEach(f => {{
    const sev = normalizeSeverity(f.severity);
    if (counts[sev] !== undefined) {{
        counts[sev] += 1;
    }}
}});

new Chart(document.getElementById("severityChart"), {{
    type: "doughnut",
    data: {{
        labels: ["Critical", "High", "Medium", "Low", "Info"],
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


setInterval(async () => {{

    if (reportId === null || nucleiLoaded) return;

    try {{

        const res = await fetch(`/report-json?id=${{reportId}}`);
        const updated = await res.json();

        if (updated.nuclei_done && updated.nuclei_findings) {{

            nucleiLoaded = true;

            const vulnDiv = document.getElementById("vulnContainer");

            updated.nuclei_findings.forEach(f => {{
                vulnDiv.innerHTML += `
                    <div class="action-block">
                        <strong>${{escapeHtml(f.title)}}</strong><br>
                        ${{escapeHtml(f.impact || "")}}
                    </div>
                `;
            }});

        }}

    }} catch (e) {{

    }}

}}, 4000);

</script>

</body>
</html>
"""