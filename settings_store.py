"""User settings saved from the dashboard (Gmail login, preferences).

Stored in var/settings.json with owner-only permissions (chmod 600). The App Password never leaves
this machine except to log in to Gmail. Values in .env are used as fallbacks.
"""
import json
import os

import config

PATH = config.VAR_DIR / "settings.json"

DEFAULTS = {
    "email": "",
    "app_password": "",
    "alert_recipient": "",      # blank = send alerts to your own Gmail address
    "send_alerts": True,
    "vt_key": "",
    "auto_quarantine": False,   # OFF by default: flag only, never move mail unless you opt in
    "auto_scan": False,
    "interval_minutes": 5,
    "scope": "recent",          # "recent" = last N emails, "unread" = unread only
    "recent_count": 25,
}


def _read() -> dict:
    d = DEFAULTS.copy()
    if PATH.exists():
        try:
            d.update(json.loads(PATH.read_text()))
        except (json.JSONDecodeError, OSError):
            pass
    return d


def load() -> dict:
    d = _read()
    d["email"] = d["email"] or config.EMAIL_ADDRESS
    d["app_password"] = d["app_password"] or config.EMAIL_PASSWORD
    d["vt_key"] = d["vt_key"] or config.VT_API_KEY
    d["alert_recipient"] = d["alert_recipient"] or config.ALERT_RECIPIENT
    return d


def save(**updates) -> None:
    d = _read()
    d.update(updates)
    PATH.parent.mkdir(exist_ok=True)
    PATH.write_text(json.dumps(d, indent=2))
    try:
        os.chmod(PATH, 0o600)
    except OSError:
        pass


def clear_credentials() -> None:
    save(email="", app_password="", auto_scan=False)


def connected() -> bool:
    s = load()
    return bool(s["email"] and s["app_password"])
