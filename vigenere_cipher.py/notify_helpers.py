# notify_helpers.py

import smtplib
from email.message import EmailMessage
import requests
import logging

logger = logging.getLogger("vigenere_tool.notify")

# ─── Email Notification ───────────────────────────────────────────────────────
def send_email_report(
    smtp_server: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    sender: str,
    recipients: list,
    subject: str,
    body: str,
    attachment_path: str = None
) -> None:
    """
    Send an email with optional attachment (JSON/CSV report).
    """
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)

    if attachment_path and os.path.isfile(attachment_path):
        with open(attachment_path, "rb") as f:
            data = f.read()
        maintype, subtype = ("application", "octet-stream")
        filename = os.path.basename(attachment_path)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
        logger.info(f"Email sent to {recipients}")
    except Exception as e:
        logger.error(f"Failed to send email: {e}")

# ─── Slack Notification ────────────────────────────────────────────────────────
def post_to_slack(text: str, webhook_url: str) -> None:
    """
    Post a message `text` to a Slack channel via an Incoming Webhook URL.
    """
    payload = {"text": text}
    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code != 200:
            logger.error(f"Slack post failed: {response.status_code} {response.text}")
        else:
            logger.info("Posted report to Slack.")
    except Exception as e:
        logger.error(f"Exception posting to Slack: {e}")

