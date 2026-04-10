# utils/email_sender.py

import requests
import base64

RESEND_API_KEY = "re_jBBWhuEX_JAGjT36prrG1kbPpKeBabd46"

def send_email(to_email, subject, body, attachment_path=None):

    url = "https://api.resend.com/emails"

    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "from": "RS Attack Surface <onboarding@resend.dev>",
        "to": [to_email],
        "subject": subject,
        "text": body
    }

    if attachment_path:
        with open(attachment_path, "rb") as f:
            encoded = base64.b64encode(f.read()).decode()

        payload["attachments"] = [
            {
                "filename": "relatorio.pdf",
                "content": encoded
            }
        ]

    response = requests.post(
        url,
        headers=headers,
        json=payload
    )

    print("RESEND STATUS:", response.status_code)
    print("RESEND BODY:", response.text)