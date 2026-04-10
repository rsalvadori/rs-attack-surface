import subprocess
import shutil


def run_nuclei(domain: str) -> list:
    target = f"https://{domain}"

    NUCLEI_PATH = shutil.which("nuclei") or "nuclei"

    command = [
        NUCLEI_PATH,
        "-u", target,
        "-t", "/root/.nuclei-templates/http",
        "-rl", "10",
        "-timeout", "10"
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
        stdout, stderr = process.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        print("NUCLEI TIMEOUT - PARTIAL OUTPUT:", stdout[:500])

    stdout = (stdout or "").strip()
    stderr = (stderr or "").strip()

    print("STDOUT FULL:", stdout[:1000])

    if stderr:
        print("[NUCLEI STDERR]", stderr)

    if not stdout:
        return [{
            "title": "Nenhuma evidência retornada pelo Nuclei",
            "severity": "info",
            "impact": "A varredura foi executada, mas não retornou achados dentro do escopo configurado.",
            "recommendation": "Manter monitoramento contínuo e realizar testes mais aprofundados."
        }]

    findings = []

    for line in stdout.splitlines():
        line = line.strip()

        if not line:
            continue

        findings.append({
            "title": line,
            "severity": "info",
            "impact": "Resultado bruto do Nuclei",
            "recommendation": "Analisar manualmente"
        })

    return findings


def analyze_nuclei(domain: str):
    return run_nuclei(domain)