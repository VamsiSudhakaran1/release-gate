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
import urllib.error
import urllib.request
from email.message import EmailMessage
from typing import Optional


def _env(name: str, default: str = "") -> str:
    """Read an env var, stripping surrounding whitespace/newlines.

    Pasting secrets into dashboards (Vercel, etc.) frequently appends a
    trailing newline or space. An API key with a trailing '\\n' produces an
    'Authorization: Bearer <key>\\n' header, which Resend rejects with 403.
    Stripping here makes the config forgiving.
    """
    return os.environ.get(name, default).strip()


def app_base_url() -> str:
    return _env("APP_BASE_URL", "https://release-gate.com").rstrip("/")


def _resend_configured() -> bool:
    return bool(_env("RESEND_API_KEY"))


def _smtp_configured() -> bool:
    return bool(_env("SMTP_HOST") and _env("SMTP_USER") and _env("SMTP_PASSWORD"))


def _send_via_resend(to: str, subject: str, text: str, html: Optional[str]) -> bool:
    api_key = _env("RESEND_API_KEY")
    from_addr = _env("RESEND_FROM") or "onboarding@resend.dev"
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
                print(f"[email] Resend accepted message to {to} (from {from_addr})",
                      file=sys.stderr)
                return True
            body = resp.read().decode(errors="replace")
            print(f"[email] Resend non-2xx ({resp.status}) from={from_addr}: {body}",
                  file=sys.stderr)
            return False
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        print(f"[email] Resend {exc.code} sending to {to} (from={from_addr}): {body}",
              file=sys.stderr)
        return False
    except Exception as exc:
        print(f"[email] Resend send failed to {to} (from={from_addr}): {exc}",
              file=sys.stderr)
        return False


def _send_via_smtp(to: str, subject: str, text: str, html: Optional[str]) -> bool:
    host = _env("SMTP_HOST")
    port = int(_env("SMTP_PORT", "587"))
    user = _env("SMTP_USER")
    password = _env("SMTP_PASSWORD")
    from_addr = _env("SMTP_FROM") or user
    mode = (_env("SMTP_TLS", "true")).lower()

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


def email_config_status() -> dict:
    """Non-secret summary of the active email config, for diagnostics.

    Never returns the API key or password — only whether they're present,
    their length, and the from/host values so misconfig is obvious.
    """
    api_key = _env("RESEND_API_KEY")
    return {
        "provider": "resend" if _resend_configured() else ("smtp" if _smtp_configured() else "none"),
        "resend": {
            "api_key_present": bool(api_key),
            "api_key_len": len(api_key),
            "api_key_prefix": (api_key[:3] + "…") if api_key else "",
            "from": _env("RESEND_FROM") or "onboarding@resend.dev (default)",
        },
        "smtp": {
            "host": _env("SMTP_HOST"),
            "user_present": bool(_env("SMTP_USER")),
        },
        "app_base_url": app_base_url(),
    }


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
