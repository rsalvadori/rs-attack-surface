import subprocess
import json
import shutil


def run_nuclei(domain: str) -> list:
    target = f"https://{domain}"

    NUCLEI_PATH = shutil.which("nuclei") or "nuclei"

    command = [
        NUCLEI_PATH,
        "-u", target,
        "-tags", "misconfig,exposure",
        "-templates", "/root/nuclei-templates",
        "-severity", "medium,high",
        "-rl", "10",
        "-timeout", "10",
        "-j"
    ]

    print("TARGET NUCLEI:", target)
    print("NUCLEI PATH:", NUCLEI_PATH)
    print("COMANDO NUCLEI:", " ".join(command))

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    try:
        stdout, stderr = process.communicate(timeout=90)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        print("NUCLEI TIMEOUT - PARTIAL OUTPUT:", stdout[:500])

    stdout = (stdout or "").strip()
    stderr = (stderr or "").strip()

    print("RETURN CODE:", process.returncode)
    print("STDOUT:", stdout[:500])
    print("STDERR:", stderr[:500])

    # 🚨 ERRO REAL DO NUCLEI
    if process.returncode != 0:
        return [{
            "title": "Erro na execução do Nuclei",
            "severity": "high",
            "impact": f"Erro retornado pelo Nuclei: {stderr or 'sem mensagem'}",
            "recommendation": "Verificar execução do binário e templates no ambiente."
        }]

    if not stdout:
        return [{
            "title": "Nenhuma evidência retornada pelo Nuclei",
            "severity": "info",
            "impact": "A varredura foi executada, mas não encontrou achados relevantes dentro do escopo.",
            "recommendation": "Executar análise mais profunda sob demanda."
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
                "recommendation": "Validar tecnicamente e aplicar correção ou hardening conforme aplicável."
            })

        except Exception:
            continue

    if not findings:
        return [{
            "title": "Nenhuma evidência relevante identificada",
            "severity": "info",
            "impact": "O scan não encontrou vulnerabilidades dentro do escopo configurado.",
            "recommendation": "Para maior profundidade, executar análise ampliada."
        }]

    return findings


def analyze_nuclei(domain: str):
    return run_nuclei(domain)