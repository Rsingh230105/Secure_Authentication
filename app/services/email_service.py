"""SMTP email delivery service for transactional application emails."""

import smtplib
from email.mime.text import MIMEText

from app.core.config import settings


def _send(to_email: str, subject: str, body: str) -> None:
    """Open one SMTP connection, send a plain-text email, and close it."""

    message = MIMEText(body, "plain")
    message["Subject"] = subject
    message["From"] = settings.smtp_from_email
    message["To"] = to_email

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
        server.ehlo()
        server.starttls()
        server.login(
            settings.smtp_username,
            settings.smtp_password.get_secret_value(),
        )
        server.sendmail(settings.smtp_from_email, to_email, message.as_string())


def send_verification_email(to_email: str, token: str) -> None:
    """Send an account verification link containing a one-time token."""

    body = (
        f"Hello,\n\n"
        f"Please verify your email address by submitting the token below "
        f"to POST /api/v1/auth/verify-email\n\n"
        f"Token: {token}\n\n"
        f"This token expires in 24 hours.\n"
    )
    _send(to_email, "Verify your email address", body)


def send_password_reset_email(to_email: str, token: str) -> None:
    """Send a password reset link containing a one-time token."""

    body = (
        f"Hello,\n\n"
        f"Submit the token below to POST /api/v1/auth/reset-password "
        f"along with your new password.\n\n"
        f"Token: {token}\n\n"
        f"This token expires in 1 hour. If you did not request this, "
        f"ignore this email.\n"
    )
    _send(to_email, "Reset your password", body)
