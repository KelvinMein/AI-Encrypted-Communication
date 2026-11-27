"""Sends email. Never raises: a mail problem must not break the request that triggered it.

If SMTP_HOST is set in backend/.env, real email is sent. Otherwise (development) the message
is printed in the backend window and saved under backend/outbox/.
"""
import os
import re
import smtplib
import ssl
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path

OUTBOX = Path(__file__).resolve().parents[1] / "outbox"


def send_email(to: str, subject: str, body: str) -> None:
    try:
        host = os.getenv("SMTP_HOST")
        if host:
            user = os.getenv("SMTP_USER")
            sender = os.getenv("MAIL_FROM") or user or "noreply@securemessenger.local"
            msg = EmailMessage()
            msg["From"] = sender
            msg["To"] = to
            msg["Subject"] = subject
            msg.set_content(body)
            with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=15) as server:
                server.starttls(context=ssl.create_default_context())
                if user:
                    server.login(user, os.getenv("SMTP_PASSWORD", ""))
                server.send_message(msg)
            print(f"[mail] sent to {to}")
        else:
            OUTBOX.mkdir(exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = OUTBOX / f"{stamp}_{re.sub(r'[^A-Za-z0-9_.-]', '_', to)}.txt"
            path.write_text(f"To: {to}\nSubject: {subject}\n\n{body}", encoding="utf-8")
            print(f"[mail] No SMTP server configured. Email for {to} saved to {path}")
            print(body)
    except Exception as exc:
        print(f"[mail] could not send to {to}: {exc}")