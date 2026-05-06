import json
import os

from scan.lgpd_analyzer import analyze_lgpd
# analyze_nuclei removido — módulo scan.nuclei não existe.
# O fluxo Nuclei atual roda via worker externo em run_nuclei_background() no main.py.


REPORTS_DIR = "reports"

# garante que a pasta existe
os.makedirs(REPORTS_DIR, exist_ok=True)


def run_full_scan(scan_id: str, domain: str):
    """
    Executa o scan completo (LGPD + Nuclei)
    e salva o resultado em arquivo.
    """

    path = f"{REPORTS_DIR}/{scan_id}.json"

    # marca como rodando
    with open(path, "w") as f:
        json.dump({
            "status": "running",
            "target": domain
        }, f)

    try:
        # executa scans
        lgpd = analyze_lgpd(domain)
        nuclei = analyze_nuclei(domain)

        result = {
            "status": "done",
            "target": domain,
            "findings": lgpd + nuclei
        }

    except Exception as e:
        result = {
            "status": "error",
            "target": domain,
            "error": str(e)
        }

    # salva resultado final
    with open(path, "w") as f:
        json.dump(result, f)
