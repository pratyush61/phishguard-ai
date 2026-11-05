"""Central configuration. Values come from environment variables / .env."""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


# Paths
VAR_DIR = BASE_DIR / "var"
VAR_DIR.mkdir(exist_ok=True)
DB_PATH = Path(os.getenv("DB_PATH", VAR_DIR / "phishguard.db"))
ALERT_OUTBOX = VAR_DIR / "alert_outbox.txt"
MODEL_PATH = BASE_DIR / "models" / "content_model.joblib"
METRICS_PATH = BASE_DIR / "models" / "metrics.json"

# Mailbox
IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
IMAP_PORT = int(os.getenv("IMAP_PORT", 993))
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
QUARANTINE_FOLDER = os.getenv("QUARANTINE_FOLDER", "PhishGuard-Quarantine")

# Alerts
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
ALERT_RECIPIENT = os.getenv("ALERT_RECIPIENT", "")

# VirusTotal
VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_DELAY_SECONDS = _float("VT_DELAY_SECONDS", 16)
MAX_URLS_PER_EMAIL = int(os.getenv("MAX_URLS_PER_EMAIL", 5))

# Decision engine
URL_WEIGHT = _float("URL_WEIGHT", 0.5)
CONTENT_WEIGHT = _float("CONTENT_WEIGHT", 0.5)
PHISHING_THRESHOLD = _float("PHISHING_THRESHOLD", 0.70)
SUSPICIOUS_THRESHOLD = _float("SUSPICIOUS_THRESHOLD", 0.40)
STRONG_CONTENT_THRESHOLD = _float("STRONG_CONTENT_THRESHOLD", 0.90)

# Scheduler
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", 120))


def live_ready() -> list[str]:
    """Return the list of missing settings needed for live mode."""
    missing = []
    for name, val in [
        ("EMAIL_ADDRESS", EMAIL_ADDRESS),
        ("EMAIL_PASSWORD", EMAIL_PASSWORD),
        ("ALERT_RECIPIENT", ALERT_RECIPIENT),
        ("VT_API_KEY", VT_API_KEY),
    ]:
        if not val:
            missing.append(name)
    return missing
