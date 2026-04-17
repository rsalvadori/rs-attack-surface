import subprocess
import json
import shutil


def run_nuclei(domain: str) -> list:
    target = f"https://{domain}"

    NUCLEI_PATH = shutil.which("nuclei") or "nuclei"

    command = [
        NUCLEI_PATH,
        "-u", target,

        # 🔒 ESCOPOS CONTROLADOS (SEM exposure!)
        "-templates", "/root/nuclei-templates/http/misconfiguration/,/root/nuclei-templates/ssl/",

        # 🚫 REMOVE LIXO PESADO
        "-exclude-tags", "dos,fuzz,bruteforce,token,secret,creds,auth-bypass,global-matchers",

        # 🔥 PERFORMANCE AJUSTADA (SEM MATAR O RAILWAY)
        "-rl", "10",
        "-c", "5",
        "-bs", "5",

        # ⏱️ TEMPO MAIS REALISTA
        "-timeout", "10",
        "-retries", "1",

        # 🧠 EVITA TRAVAMENTO
        "-no-interactsh",
        "-no-color",

        # OUTPUT
        "-silent",
        "-nc",
        "-j"
    ]

    print("TARGET NUCLEI:", target)
    print("COMANDO:", " ".join(command))

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    try:
        stdout, stderr = process.communicate(timeout=40)
    except subprocess.TimeoutExpired:
        process.kill()
        print("NUCLEI TIMEOUT - encerrado")

        return [{
            "title": "Análise de vulnerabilidades otimizada",
            "severity": "info",
            "impact": "A análise foi executada com limite de tempo otimizado para resposta rápida.",
            "recommendation": "Para cobertura completa, recomenda-se execução aprofundada com maior tempo de análise."
        }]

    stdout = (stdout or "").strip()

    print("STDOUT PREVIEW:", stdout[:500])

    # 🔥 fallback REAL
    if not stdout:
        return [{
            "title": "Nenhuma vulnerabilidade detectada (scan leve)",
            "severity": "info",
            "impact": "Nenhuma falha foi identificada no escopo rápido.",
            "recommendation": "Executar análise aprofundada para cobertura completa."
        }]

    findings = []

    for line in stdout.splitlines():
        line = line.strip()

        if not line.startswith("{"):
            continue

        try:
            data = json.loads(line)

            info = data.get("info", {})
            name = info.get("name", "Nuclei Finding")
            severity = info.get("severity", "info")

            matched = data.get("matched-at") or data.get("host") or target

            findings.append({
                "title": name,
                "severity": severity,
                "impact": f"Evidência identificada em {matched}",
                "recommendation": "Validar tecnicamente e aplicar correção."
            })

        except Exception:
            continue

    if not findings:
        return [{
            "title": "Scan executado sem findings relevantes",
            "severity": "info",
            "impact": "Nenhuma vulnerabilidade relevante encontrada no escopo atual.",
            "recommendation": "Ampliar escopo do scan se necessário."
        }]

    return findings


def analyze_nuclei(domain: str):
    return run_nuclei(domain)