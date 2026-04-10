import smtplib
from email.message import EmailMessage

SMTP_SERVER = "email-ssl.com.br"
SMTP_PORT = 465
SMTP_EMAIL = "reportsattacksurface@rsdatasecurity.com.br"
SMTP_PASSWORD = "H+_W/vGg&f9B/UZ"


def send_email(to_email, subject, body, attachment_path=None):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_EMAIL
    msg["To"] = to_email

    msg.set_content(body)

    if attachment_path:
        with open(attachment_path, "rb") as f:
            msg.add_attachment(
                f.read(),
                maintype="application",
                subtype="pdf",
                filename=attachment_path.split("/")[-1]
            )

    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as smtp:
        smtp.login(SMTP_EMAIL, SMTP_PASSWORD)
        smtp.send_message(msg)
