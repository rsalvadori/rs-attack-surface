import subprocess
import json
import shutil


def run_nuclei(domain: str) -> list:
    target = f"https://{domain}"

    NUCLEI_PATH = shutil.which("nuclei") or "nuclei"

command = [
    NUCLEI_PATH,
    "-u", target,

    "-templates",
    "/root/.nuclei-templates/http/misconfiguration/http-headers.yaml,/root/.nuclei-templates/http/misconfiguration/cors.yaml,/root/.nuclei-templates/http/misconfiguration/security-headers.yaml",

    "-exclude-tags", "dos,fuzz,bruteforce,token,secret,creds,auth-bypass,global-matchers",

    "-rl", "10",
    "-c", "5",
    "-bs", "5",

    "-timeout", "15",
    "-retries", "1",

    "-no-interactsh",
    "-no-color",

    "-silent",
    "-nc",
    "-j"
]
    print("TARGET NUCLEI:", target)
    print("COMANDO:", " ".join(command))

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()

    print("STDOUT PREVIEW:", stdout[:500])
    if stderr:
        print("STDERR PREVIEW:", stderr[:500])

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