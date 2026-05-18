import smtplib
import ssl
import logging
from email.mime.text import MIMEText
from core.config import settings

logging.basicConfig(level=logging.INFO)

def send_email(to_email: str, subject: str, body: str):
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = settings.FROM_EMAIL
        msg["To"] = to_email

        context = ssl.create_default_context()

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.ehlo()

            # TLS Security
            server.starttls(context=context)
            server.ehlo()

            # Login
            server.login(
                settings.SMTP_USER,
                settings.SMTP_PASSWORD
            )

            # Send Mail
            server.sendmail(
                settings.FROM_EMAIL,
                [to_email],
                msg.as_string()
            )

        print(f"✅ Email sent to {to_email}")

    except Exception as e:
        print("❌ Email sending failed")
        print(e)
        raise e


def build_otp_body(name: str, otp: str) -> str:
    return f"""
Hi {name},

Your OTP is: {otp}

This OTP will expire soon.

Thanks
"""


def build_reset_body(name: str, otp: str) -> str:
    return f"""
Hi {name},

Your password reset OTP is: {otp}

This OTP will expire soon.

Thanks
"""