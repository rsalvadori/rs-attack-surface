# utils/email_sender.py

import requests

RESEND_API_KEY = "re_jBBWhuEX_JAGjT36prrG1kbPpKeBabd46"

def send_email(to_email, subject, body, attachment_path=None):

    url = "https://api.resend.com/emails"

    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "from": "onboarding@resend.dev",
        "to": ["comercial@rsdatasecurity.com.br"],
        "subject": "TESTE FINAL",
        "text": "TESTE"
    }

    response = requests.post(
        url,
        headers=headers,
        json=payload
    )

    print("DEBUG TO:", payload["to"])
    print("RESEND STATUS:", response.status_code)
    print("RESEND BODY:", response.text)