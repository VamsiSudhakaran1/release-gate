"""
Email helper for release-gate.

Tries providers in order: Resend (HTTP API) → SMTP (fallback).
If neither is configured, logs to stderr and returns False.

Environment variables:
  RESEND_API_KEY  Resend API key (re_...) — recommended on Vercel
  RESEND_FROM     From address (default: onboarding@resend.dev for testing,
                  set to your verified domain address in production)

  SMTP_HOST       e.g. smtp.gmail.com  (fallback if no RESEND_API_KEY)
  SMTP_PORT       default 587
  SMTP_USER       SMTP username
  SMTP_PASSWORD   SMTP password / app password
  SMTP_FROM       From address (defaults to SMTP_USER)
  SMTP_TLS        "true" (default) uses STARTTLS; "ssl" uses SMTP_SSL

  APP_BASE_URL    Public site URL for building links (default https://release-gate.com)
"""
from __future__ import annotations

import json
import os
import smtplib
import sys
import urllib.request
from email.message import EmailMessage
from typing import Optional


def app_base_url() -> str:
    return os.environ.get("APP_BASE_URL", "https://release-gate.com").rstrip("/")


def _resend_configured() -> bool:
    return bool(os.environ.get("RESEND_API_KEY"))


def _smtp_configured() -> bool:
    return bool(os.environ.get("SMTP_HOST") and os.environ.get("SMTP_USER")
                and os.environ.get("SMTP_PASSWORD"))


def _send_via_resend(to: str, subject: str, text: str, html: Optional[str]) -> bool:
    api_key = os.environ["RESEND_API_KEY"]
    from_addr = os.environ.get("RESEND_FROM", "onboarding@resend.dev")
    payload = {"from": from_addr, "to": [to], "subject": subject, "text": text}
    if html:
        payload["html"] = html
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=data,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status in (200, 201):
                return True
            body = resp.read().decode()
            print(f"[email] Resend non-200 ({resp.status}): {body}", file=sys.stderr)
            return False
    except Exception as exc:
        print(f"[email] Resend send failed to {to}: {exc}", file=sys.stderr)
        return False


def _send_via_smtp(to: str, subject: str, text: str, html: Optional[str]) -> bool:
    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ["SMTP_USER"]
    password = os.environ["SMTP_PASSWORD"]
    from_addr = os.environ.get("SMTP_FROM", user)
    mode = os.environ.get("SMTP_TLS", "true").lower()

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")

    try:
        if mode == "ssl":
            with smtplib.SMTP_SSL(host, port, timeout=15) as s:
                s.login(user, password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as s:
                s.ehlo()
                s.starttls()
                s.login(user, password)
                s.send_message(msg)
        return True
    except Exception as exc:
        print(f"[email] SMTP send failed to {to}: {exc}", file=sys.stderr)
        return False


def send_email(to: str, subject: str, text: str, html: Optional[str] = None) -> bool:
    """Send an email. Tries Resend first, then SMTP. Returns True if sent."""
    if _resend_configured():
        return _send_via_resend(to, subject, text, html)
    if _smtp_configured():
        return _send_via_smtp(to, subject, text, html)
    print(f"[email] no provider configured — would have sent to {to}:\n"
          f"  Subject: {subject}\n  {text}", file=sys.stderr)
    return False


def send_password_reset(to: str, reset_url: str) -> bool:
    subject = "Reset your release-gate password"
    text = (
        f"You requested a password reset for release-gate.\n\n"
        f"Reset your password here (link expires in 1 hour):\n{reset_url}\n\n"
        f"If you didn't request this, you can safely ignore this email."
    )
    html = f"""\
<div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto">
  <h2 style="color:#6366f1">🚪 release-gate</h2>
  <p>You requested a password reset.</p>
  <p><a href="{reset_url}" style="display:inline-block;background:#6366f1;color:#fff;
     padding:10px 22px;border-radius:8px;text-decoration:none;font-weight:600">
     Reset password →</a></p>
  <p style="color:#6b7280;font-size:.85rem">This link expires in 1 hour.
     If you didn't request this, ignore this email.</p>
</div>"""
    return send_email(to, subject, text, html)


def send_temp_password(to: str, temp_password: str) -> bool:
    login_url = app_base_url() + "/#login"
    subject = "Your release-gate temporary password"
    text = (
        f"An account has been created for you on release-gate.\n\n"
        f"Temporary password: {temp_password}\n\n"
        f"Log in at {login_url} and you'll be asked to set a new password immediately."
    )
    html = f"""\
<div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto">
  <h2 style="color:#6366f1">🚪 release-gate</h2>
  <p>An account has been created for you. Use this temporary password to log in:</p>
  <p style="font-size:1.2rem;font-weight:700;background:#f3f4f6;padding:10px 16px;
     border-radius:8px;letter-spacing:1px;font-family:monospace">{temp_password}</p>
  <p><a href="{login_url}" style="display:inline-block;background:#6366f1;color:#fff;
     padding:10px 22px;border-radius:8px;text-decoration:none;font-weight:600">
     Log in →</a></p>
  <p style="color:#6b7280;font-size:.85rem">You'll be prompted to set a new password
     on first login.</p>
</div>"""
    return send_email(to, subject, text, html)
