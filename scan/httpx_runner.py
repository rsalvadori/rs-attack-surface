import json
import shutil
import subprocess
from typing import Any


class HttpxRunnerError(Exception):
    pass


def check_httpx_installed() -> None:
    if shutil.which("httpx") is None:
        raise HttpxRunnerError(
            "O binário 'httpx' não foi encontrado no PATH."
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
        "-web-server",
        "-ip",
        "-cdn"
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
        raise HttpxRunnerError(f"Timeout httpx: {domain}") from exc
    except Exception as exc:
        raise HttpxRunnerError(f"Erro httpx: {exc}") from exc

    stdout = (result.stdout or "").strip()

    if not stdout:
        raise HttpxRunnerError(f"Sem saída do httpx para {domain}")

    # pega PRIMEIRA linha válida JSON
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue

        try:
            data = json.loads(line)

            # 🔥 NORMALIZAÇÃO PADRÃO (IMPORTANTE)
            return {
                "url": data.get("url"),
                "final_url": data.get("final_url"),
                "status_code": data.get("status_code"),
                "title": data.get("title"),
                "technologies": data.get("technologies", []),
                "webserver": data.get("webserver"),
                "ip": data.get("ip"),
                "cdn": data.get("cdn"),
                "response_time": data.get("response_time"),
            }

        except Exception:
            continue

    raise HttpxRunnerError(f"Falha parse JSON httpx: {domain}")