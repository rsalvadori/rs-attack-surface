import requests


def fetch_headers(domain: str) -> dict:
    urls = [
        f"https://{domain}",
        f"http://{domain}",
    ]

    for url in urls:
        try:
            response = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                verify=False
            )
            return dict(response.headers)
        except Exception:
            continue

    return {}