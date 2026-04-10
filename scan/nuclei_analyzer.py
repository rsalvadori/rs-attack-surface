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
        "-templates", "/root/.nuclei-templates",
        "-severity", "critical,medium,high",
        "-rl", "10",
        "-timeout", "10",
        "-duc",
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
        stdout, stderr = process.communicate(timeout=300)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        print("TIMEOUT - PARTIAL STDOUT:", stdout[:500])

    stdout = (stdout or "").strip()

    print("STDOUT PREVIEW:", stdout[:500])

    # 🔥 NÃO CONFIA MAIS EM returncode / stderr

    if not stdout:
        return [{
            "title": "Scan executado sem retorno",
            "severity": "info",
            "impact": "O Nuclei executou, mas não retornou dados no stdout.",
            "recommendation": "Aumentar escopo ou validar alvo."
        }]

    findings = []

    for line in stdout.splitlines():
        line = line.strip()

        # ignora linhas sem JSON
        if "{" not in line:
            continue

        # pega apenas a parte JSON
        json_part = line[line.find("{"):]

        try:
            data = json.loads(json_part)

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

    # 🔥 fallback se não parseou nada
    if not findings:
        return [{
            "title": "Scan executado sem findings parseáveis",
            "severity": "info",
            "impact": "O Nuclei retornou saída, mas sem dados estruturados aproveitáveis.",
            "recommendation": "Revisar escopo ou ampliar severidade."
        }]

    return findings


def analyze_nuclei(domain: str):
    return run_nuclei(domain)