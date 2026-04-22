import subprocess


class TLSAnalyzerError(Exception):
    pass


def run_testssl(domain: str) -> str:
    target = f"https://{domain}"

    cmd = [
        "testssl.sh",
        "--quiet",
        "--protocols",
        "--warnings",
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
        # TLS 1.0 / 1.1 habilitado
        # =========================
        if (
            ("tls 1.0" in line or "tls 1.1" in line)
            and ("offered" in line or "supported" in line)
        ):
            key = "tls_obsolete"

            if key not in seen:
                seen.add(key)

                findings.append({
                    "title": "Protocolo TLS obsoleto habilitado",
                    "severity": "high",
                    "impact": "O servidor aceita TLS 1.0/1.1, vulneráveis a ataques conhecidos.",
                    "recommendation": "Desabilitar TLS 1.0 e 1.1 e manter apenas TLS 1.2 ou superior."
                })

        # =========================
        # Cipher fraco (CBC / 3DES / RC4)
        # =========================
        if (
            ("cbc" in line or "3des" in line or "rc4" in line)
            and ("offered" in line or "accepted" in line)
        ):
            key = "weak_cipher"

            if key not in seen:
                seen.add(key)

                findings.append({
                    "title": "Cipher fraco identificado",
                    "severity": "medium",
                    "impact": "Algoritmos criptográficos fracos podem permitir quebra de confidencialidade.",
                    "recommendation": "Remover CBC, 3DES e RC4. Priorizar AES-GCM ou ChaCha20."
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
                or "verify error" in line
            )
        ):
            key = "invalid_cert"

            if key not in seen:
                seen.add(key)

                findings.append({
                    "title": "Problema no certificado SSL",
                    "severity": "high",
                    "impact": "Certificado inválido compromete confiança e permite MITM.",
                    "recommendation": "Emitir certificado válido e garantir cadeia completa."
                })

        # =========================
        # Falta de Forward Secrecy
        # =========================
        if "forward secrecy" in line and "not" in line:
            key = "no_forward_secrecy"

            if key not in seen:
                seen.add(key)

                findings.append({
                    "title": "Ausência de Forward Secrecy",
                    "severity": "medium",
                    "impact": "Comprometimento de chave privada pode expor comunicações passadas.",
                    "recommendation": "Habilitar ECDHE para garantir Perfect Forward Secrecy."
                })

    return findings