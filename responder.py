"""Stages 7-8: alert the security team (quarantine itself lives on the mailbox object)."""
import logging
import smtplib
from email.message import EmailMessage

import config
from email_ingest import ALERT_HEADER

log = logging.getLogger("phishguard.responder")


def build_alert(parsed, decision, quarantined: bool, sender: str, recipient: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = f"[PhishGuard] {decision.verdict.upper()} email detected (risk {decision.risk:.0%})"
    msg["From"] = sender or "phishguard@localhost"
    msg["To"] = recipient or "security-team@example.com"
    msg[ALERT_HEADER] = "1"   # lets the scanner ignore this message later
    reasons = "\n".join(f"  - {r}" for r in decision.reasons) or "  - none"
    msg.set_content(
        f"PhishGuard AI flagged an email.\n\n"
        f"Verdict    : {decision.verdict}\n"
        f"Risk score : {decision.risk:.0%}\n"
        f"From       : {parsed.sender}\n"
        f"Subject    : {parsed.subject}\n"
        f"Quarantined: {'yes' if quarantined else 'no'}\n\n"
        f"Why:\n{reasons}\n\n"
        f"Review it on the PhishGuard dashboard."
    )
    return msg


def send_alert(parsed, decision, quarantined: bool, settings: dict, live: bool) -> bool:
    recipient = settings.get("alert_recipient") or settings.get("email", "")
    msg = build_alert(parsed, decision, quarantined, settings.get("email", ""), recipient)
    if not live:
        with open(config.ALERT_OUTBOX, "a", encoding="utf-8") as f:
            f.write(f"{'=' * 60}\nTo: {msg['To']}\nSubject: {msg['Subject']}\n\n{msg.get_content()}\n")
        return True
    try:
        with smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT, timeout=30) as s:
            s.starttls()
            s.login(settings["email"], settings["app_password"])
            s.send_message(msg)
        log.info("Alert sent to %s", recipient)
        return True
    except Exception as exc:
        log.error("Could not send alert: %s", exc)
        return False
