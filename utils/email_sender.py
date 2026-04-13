import requests

RESEND_API_KEY = "re_jBBWhuEX_JAGjT36prrG1kbPpKeBabd46"

def send_email_lead(company, client, email, phone, domain):

    url = "https://api.resend.com/emails"

    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "from": "onboarding@resend.dev",
        "to": ["comercial@rsdatasecurity.com.br"],  # único permitido
        "subject": "NOVO LEAD - RS Attack Surface",
        "text": f"""
Empresa: {company}
Responsável: {client}
Email: {email}
Telefone: {phone}
Domínio: {domain}
"""
    }

    response = requests.post(url, headers=headers, json=payload)

    print("RESEND STATUS:", response.status_code)
    print("RESEND BODY:", response.text)