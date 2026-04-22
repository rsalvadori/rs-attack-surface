import subprocess


class TLSAnalyzerError(Exception):
    pass


def run_testssl(domain: str) -> str:
    target = f"https://{domain}"

    cmd = [
        "testssl.sh",
        "--quiet",
        "--protocols",
        target
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
    seen = set()

    try:
        output = run_testssl(domain)
    except TLSAnalyzerError:
        return findings

    lines = output.lower().splitlines()

    for line in lines:

        # =========================
        # TLS 1.0 / 1.1
        # =========================
        if (
            ("tls 1.0" in line or "tls 1.1" in line)
            and "offered" in line
        ):
            key = "tls_obsolete"

            if key not in seen:
                seen.add(key)

                findings.append({
                    "title": "Protocolo TLS obsoleto habilitado",
                    "severity": "high",
                    "impact": "O servidor aceita TLS 1.0/1.1, protocolos vulneráveis a ataques conhecidos.",
                    "recommendation": "Desabilitar TLS 1.0 e TLS 1.1 e manter apenas TLS 1.2 ou superior."
                })

        # =========================
        # Cipher fraco
        # =========================
        if (
            ("cbc" in line or "3des" in line)
            and "offered" in line
        ):
            key = "weak_cipher"

            if key not in seen:
                seen.add(key)

                findings.append({
                    "title": "Cipher fraco identificado",
                    "severity": "medium",
                    "impact": "Uso de algoritmos criptográficos considerados inseguros pode permitir quebra de confidencialidade.",
                    "recommendation": "Remover suites CBC, 3DES e priorizar AES-GCM ou ChaCha20."
                })

        # =========================
        # Certificado inválido
        # =========================
        if (
            "certificate" in line
            and (
                "expired" in line
                or "not valid" in line
                or "self signed" in line
            )
        ):
            key = "invalid_cert"

            if key not in seen:
                seen.add(key)

                findings.append({
                    "title": "Problema no certificado SSL",
                    "severity": "high",
                    "impact": "Certificado inválido compromete a confiança e pode permitir ataques MITM.",
                    "recommendation": "Emitir certificado válido por autoridade confiável e garantir cadeia completa."
                })

    return findings