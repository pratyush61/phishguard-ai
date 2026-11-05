import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

import config
import database as db
import email_ingest as ing
import pipeline
import risk_engine
import settings_store
import url_tools
from demo_data import SAMPLE_EMAILS


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.db")
    monkeypatch.setattr(config, "ALERT_OUTBOX", tmp_path / "alerts.txt")
    monkeypatch.setattr(settings_store, "PATH", tmp_path / "settings.json")
    for name in ("EMAIL_ADDRESS", "EMAIL_PASSWORD", "VT_API_KEY", "ALERT_RECIPIENT"):
        monkeypatch.setattr(config, name, "")
    db.init_db()


class FakeGmail:
    """Stands in for ImapMailbox: serves the sample emails as if they were in a Gmail inbox."""
    moved: list = []

    def __init__(self, extra=()):
        self.extra = list(extra)

    def __enter__(self): return self
    def __exit__(self, *a): pass

    def fetch(self, scope="recent", limit=25):
        for i, raw in enumerate(list(SAMPLE_EMAILS) + self.extra, 1):
            yield ing.parse_message(raw.encode(), uid=str(i))

    def quarantine(self, uid):
        FakeGmail.moved.append(uid)
        return True


# ---------------------------------------------------------------- units
def test_extract_urls_text_and_html():
    urls = ing.extract_urls("Visit http://a.example/x. Also www.b.example!", '<a href="https://c.example/y">c</a>')
    assert {"http://a.example/x", "http://www.b.example", "https://c.example/y"} <= set(urls)


def test_mailto_ignored():
    assert ing.extract_urls("", '<a href="mailto:a@b.c">x</a>') == []


def test_heuristic_flags_bad_url_and_passes_good():
    assert url_tools.heuristic_score("http://paypal-secure-login.xyz/verify").score >= 0.6
    assert url_tools.heuristic_score("https://www.college.example/newsletter").score < 0.3


def test_risk_engine_thresholds():
    assert risk_engine.decide(0.0, 0.05, True).verdict == "safe"
    assert risk_engine.decide(1.0, 0.2, True).verdict == "phishing"
    assert risk_engine.decide(0.0, 0.95, False).verdict == "phishing"


def test_friendly_auth_error():
    import imaplib
    msg = ing.friendly_error(imaplib.IMAP4.error("[AUTHENTICATIONFAILED] Invalid credentials (Failure)"))
    assert "App Password" in msg


def test_settings_roundtrip_and_permissions():
    settings_store.save(email="a@gmail.com", app_password="abcd", auto_scan=True)
    s = settings_store.load()
    assert s["email"] == "a@gmail.com" and settings_store.connected()
    assert oct(settings_store.PATH.stat().st_mode)[-3:] == "600"
    settings_store.clear_credentials()
    assert not settings_store.connected()


# ---------------------------------------------------------------- pipeline
def test_demo_pipeline_end_to_end():
    r = pipeline.run_demo()
    assert r["processed"] == 6
    by = {e["subject"]: e for e in db.list_events()}
    assert by["URGENT: Your account has been suspended"]["verdict"] == "phishing"
    assert by["URGENT: Your account has been suspended"]["quarantined"] == 1
    assert by["Quick favour - confidential"]["verdict"] in ("phishing", "suspicious")
    assert by["Project review moved to Thursday"]["verdict"] == "safe"
    assert config.ALERT_OUTBOX.exists()


def test_gmail_scan_flags_but_does_not_move_when_quarantine_off(monkeypatch):
    settings_store.save(email="a@gmail.com", app_password="x", auto_quarantine=False, send_alerts=False)
    FakeGmail.moved = []
    monkeypatch.setattr(pipeline, "open_mailbox", lambda source, s: FakeGmail())
    r = pipeline.run_scan("gmail")
    assert r["phishing"] >= 2 and FakeGmail.moved == []
    assert all(e["quarantined"] == 0 for e in db.list_events())


def test_gmail_scan_quarantines_when_enabled(monkeypatch):
    settings_store.save(email="a@gmail.com", app_password="x", auto_quarantine=True, send_alerts=False)
    FakeGmail.moved = []
    monkeypatch.setattr(pipeline, "open_mailbox", lambda source, s: FakeGmail())
    pipeline.run_scan("gmail")
    assert len(FakeGmail.moved) >= 2


def test_own_alert_emails_are_never_rescanned(monkeypatch):
    alert = ("Message-ID: <alert-1@x>\nFrom: a@gmail.com\nTo: a@gmail.com\nX-PhishGuard-Alert: 1\n"
             "Subject: [PhishGuard] PHISHING email detected (risk 100%)\n\nverify your password immediately http://evil.xyz/login\n")
    settings_store.save(email="a@gmail.com", app_password="x", send_alerts=False)
    monkeypatch.setattr(pipeline, "open_mailbox", lambda source, s: FakeGmail(extra=[alert]))
    r = pipeline.run_scan("gmail")
    assert r["skipped"] == 1 and r["processed"] == 6


def test_duplicates_skipped(monkeypatch):
    settings_store.save(email="a@gmail.com", app_password="x", send_alerts=False)
    monkeypatch.setattr(pipeline, "open_mailbox", lambda source, s: FakeGmail())
    pipeline.run_scan("gmail")
    assert pipeline.run_scan("gmail")["processed"] == 0


# ---------------------------------------------------------------- dashboard
def test_dashboard_pages_and_connect_flow(monkeypatch):
    import app as appmod
    monkeypatch.setattr(ing, "test_connection", lambda a, p: {"ok": True, "message": "Connected", "total": 120, "unseen": 4})
    c = appmod.app.test_client()
    for path in ("/", "/mailbox", "/connect", "/api/status", "/healthz"):
        assert c.get(path).status_code == 200
    assert c.post("/scan", follow_redirects=True).status_code == 200       # not connected -> redirected with message
    r = c.post("/connect", data={"email": "me@gmail.com", "app_password": "abcd efgh ijkl mnop",
                                 "scope": "recent", "recent_count": "25", "send_alerts": "on"}, follow_redirects=True)
    assert b"Connected to me@gmail.com" in r.data
    assert settings_store.connected()
    assert b"abcdefghijklmnop" not in c.get("/connect").data               # password is never echoed back
    c.post("/run-demo")
    assert c.get("/").status_code == 200 and c.get("/mailbox?verdict=phishing&q=PayPal").status_code == 200
    assert c.get("/event/1").status_code == 200
    assert c.post("/disconnect", follow_redirects=True).status_code == 200
    assert not settings_store.connected()


def test_failed_login_is_not_saved(monkeypatch):
    import app as appmod
    monkeypatch.setattr(ing, "test_connection", lambda a, p: {"ok": False, "message": "Gmail rejected the login.", "total": 0, "unseen": 0})
    c = appmod.app.test_client()
    r = c.post("/connect", data={"email": "me@gmail.com", "app_password": "wrong"}, follow_redirects=True)
    assert b"Gmail rejected the login" in r.data and not settings_store.connected()


def test_scan_can_be_cancelled_before_next_email(monkeypatch):
    import threading
    settings_store.save(email="a@gmail.com", app_password="x", send_alerts=False)
    monkeypatch.setattr(pipeline, "open_mailbox", lambda source, s: FakeGmail())
    cancel = threading.Event()
    seen = {"count": 0}
    original = pipeline.process_email

    def stop_after_first(parsed, mailbox, source, settings, cancel_event=None):
        result = original(parsed, mailbox, source, settings, cancel_event)
        seen["count"] += 1
        if seen["count"] == 1:
            cancel.set()
        return result

    monkeypatch.setattr(pipeline, "process_email", stop_after_first)
    result = pipeline.run_scan("gmail", cancel_event=cancel)
    assert result["processed"] == 1
    assert len(db.list_events()) == 1


def test_stop_scan_route_requests_cancellation(monkeypatch):
    import app as appmod
    monkeypatch.setattr(appmod.scanner, "stop_scan", lambda: True)
    client = appmod.app.test_client()
    response = client.post("/stop-scan", follow_redirects=True)
    assert response.status_code == 200
    assert b"Stop requested" in response.data
