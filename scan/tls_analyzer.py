import subprocess


class TLSAnalyzerError(Exception):
    pass


def run_testssl(domain: str) -> str:
    cmd = [
        "testssl.sh",
        "--quiet",
        "--protocols",
        domain
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
    except Exception as exc:
        raise TLSAnalyzerError(f"Erro ao executar testssl: {exc}")

    if not result.stdout:
        raise TLSAnalyzerError("testssl não retornou saída.")

    return result.stdout


def analyze_tls(domain: str) -> list[dict]:
    findings = []

    try:
        output = run_testssl(domain)
    except TLSAnalyzerError:
        return findings

    lines = output.lower().splitlines()

    for line in lines:

        # 🔥 TLS 1.0 / 1.1 habilitado (corrigido)
        if ("tls 1.0" in line or "tls 1.1" in line) and "not offered" not in line:
            findings.append({
                "title": "Protocolo TLS obsoleto habilitado",
                "severity": "high",
                "impact": "Uso de TLS 1.0/1.1 permite ataques conhecidos.",
                "recommendation": "Desabilitar TLS 1.0 e 1.1."
            })

        # 🔥 Cipher fraco
        if ("cbc" in line or "3des" in line) and "not offered" not in line:
            findings.append({
                "title": "Cipher fraco identificado",
                "severity": "medium",
                "impact": "Uso de cifragem fraca compromete segurança.",
                "recommendation": "Remover cipher suites fracas."
            })

        # 🔥 Certificado inválido
        if ("expired" in line or "not valid" in line) and "ok" not in line:
            findings.append({
                "title": "Problema no certificado SSL",
                "severity": "high",
                "impact": "Certificado inválido compromete confiança.",
                "recommendation": "Corrigir certificado SSL."
            })

    return findings