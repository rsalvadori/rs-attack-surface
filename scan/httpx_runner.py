import json
import shutil
import subprocess
from typing import Any


class HttpxRunnerError(Exception):
    pass


def check_httpx_installed() -> None:
    if shutil.which("httpx") is None:
        raise HttpxRunnerError(
            "O binário 'httpx' não foi encontrado no PATH. Instale-o antes de continuar."
        )


def _extract_json_from_stdout(stdout: str, domain: str) -> dict[str, Any]:
    stdout = stdout.strip()

    if not stdout:
        raise HttpxRunnerError(f"Nenhum resultado retornado pelo httpx para {domain}.")

    # 1) tenta parsear tudo de uma vez
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        pass

    # 2) tenta parsear linha a linha, pegando a primeira linha que pareça JSON
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if not line.startswith("{"):
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue

    preview = stdout[:1000]
    raise HttpxRunnerError(
        f"Falha ao interpretar JSON do httpx para {domain}. "
        f"Saída recebida (prévia): {preview}"
    )


def run_httpx(domain: str) -> dict[str, Any]:
    check_httpx_installed()

    cmd = [
        "httpx",
        "-u", domain,
        "-json",
        "-silent",
        "-follow-redirects",
        "-status-code",
        "-title",
        "-tech-detect",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise HttpxRunnerError(f"Timeout ao executar httpx para {domain}.") from exc
    except Exception as exc:
        raise HttpxRunnerError(f"Erro ao executar httpx: {exc}") from exc

    if result.returncode != 0 and not result.stdout.strip():
        stderr = result.stderr.strip() or "sem detalhes"
        raise HttpxRunnerError(f"httpx retornou erro: {stderr}")

    return _extract_json_from_stdout(result.stdout, domain)