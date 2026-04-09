import subprocess
import json
import shutil


def run_nuclei(domain: str) -> list:
    """
    Execução do Nuclei replicando comportamento do terminal.
    """

    target = f"https://{domain}"

    # 🔥 PATH DINÂMICO (funciona local + Railway + Docker)
    NUCLEI_PATH = shutil.which("nuclei") or "nuclei"

    command = [
        NUCLEI_PATH,
        "-u", target,
        "-t", "/root/.nuclei-templates/http",
        "-t", "/root/.nuclei-templates/cves",
        "-t", "/root/.nuclei-templates/misconfiguration",
        "-severity", "critical,high,medium",
        "-rl", "5",
        "-timeout", "10",
        "-retries", "1",
    ]

    print("TARGET NUCLEI:", target)
    print("NUCLEI PATH:", NUCLEI_PATH)
    print("COMANDO NUCLEI:", " ".join(command))

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300
        )

        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()

        print("STDOUT FULL:", stdout)

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
                "title": "Nenhuma evidência parseada do Nuclei",
                "severity": "info",
                "impact": "O Nuclei retornou dados, mas nenhum foi convertido em achado.",
                "recommendation": "Revisar parsing ou aumentar escopo do scan."
            }]

        return findings

    except subprocess.TimeoutExpired:
        return [{
            "title": "Timeout na execução do Nuclei",
            "severity": "info",
            "impact": "O scanner demorou além do esperado.",
            "recommendation": "Aumentar timeout ou reduzir escopo."
        }]

    except Exception as e:
        return [{
            "title": "Erro na execução do Nuclei",
            "severity": "info",
            "impact": f"Erro: {str(e)}",
            "recommendation": "Verificar ambiente do Nuclei."
        }]


def analyze_nuclei(domain: str):
    return run_nuclei(domain)