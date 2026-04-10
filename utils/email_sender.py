import requests

RESEND_API_KEY = "re_jBBWhuEX_JAGjT36prrG1kbPpKeBabd46"


def send_email(to_email, subject, body, attachment_path=None):

    url = "https://api.resend.com/emails"

    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}"
    }

    data = {
        "from": "RS Attack Surface <onboarding@resend.dev>",
        "to": to_email,
        "subject": subject,
        "text": body
    }

    files = None

    if attachment_path:
        files = [
            ("attachments", open(attachment_path, "rb"))
        ]

    response = requests.post(
        url,
        headers=headers,
        data=data,
        files=files
    )

    print("RESEND RESPONSE:", response.text)