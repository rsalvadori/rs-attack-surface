import subprocess
import json
import shutil


def run_nuclei(domain: str) -> list[dict]:
    target = f"https://{domain}"
    nuclei_path = shutil.which("nuclei") or "/usr/local/bin/nuclei"

    command = [
        nuclei_path,
        "-u", target,

        # escopo enxuto e funcional
        "-tags", "misconfig,exposure,default-login",

        # remove categorias pesadas / irrelevantes
        "-exclude-tags", "dos,fuzz,bruteforce,token,secret,creds,auth-bypass,global-matchers",

        # performance conservadora para container
        "-rl", "10",
        "-c", "2",
        "-bs", "2",
        "-rl 5,"

        # timeout interno do nuclei
        "-timeout", "15",
        "-retries", "1",

        # estabilidade
        "-no-interactsh",
        "-no-color",

        # output
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

    # erro real do nuclei
    if result.returncode != 0 and not stdout:
        return [{
            "title": "Falha na execução do scan de vulnerabilidades",
            "severity": "info",
            "impact": f"O Nuclei não conseguiu concluir a execução. Detalhe: {stderr[:300] or 'erro não detalhado'}",
            "recommendation": "Validar o ambiente de execução e os templates carregados."
        }]

    # sem output
    if not stdout:
        return [{
            "title": "Scan executado sem findings relevantes",
            "severity": "info",
            "impact": "Nenhuma vulnerabilidade relevante foi identificada no escopo atual do Nuclei.",
            "recommendation": "Ampliar ou aprofundar o escopo do scan se necessário."
        }]

    findings: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    for line in stdout.splitlines():
        line = line.strip()

        if not line or not line.startswith("{"):
            continue

        try:
            data = json.loads(line)
        except Exception:
            continue

        info = data.get("info", {}) or {}

        template_id = str(data.get("template-id", "") or "").strip()
        name = str(info.get("name", "Nuclei Finding") or "Nuclei Finding").strip()
        severity = str(info.get("severity", "info") or "info").strip().lower()
        matched = str(data.get("matched-at") or data.get("host") or target).strip()

        # chave de deduplicação
        dedupe_key = (template_id, name, matched)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        findings.append({
            "title": name,
            "severity": severity,
            "impact": f"Evidência identificada em {matched}",
            "recommendation": info.get("description") or "Validar e corrigir conforme boas práticas."
        })

    if not findings:
        return [{
            "title": "Scan executado sem findings relevantes",
            "severity": "info",
            "impact": "Nenhuma vulnerabilidade relevante foi identificada no escopo atual do Nuclei.",
            "recommendation": "Ampliar ou aprofundar o escopo do scan se necessário."
        }]

    return findings


def analyze_nuclei(domain: str):
    return run_nuclei(domain)