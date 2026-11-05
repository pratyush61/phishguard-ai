"""Stages 1-3: connect to Gmail (IMAP), fetch mail, parse headers/body, extract URLs.

Two mailbox back-ends share one interface (fetch / quarantine):
  * ImapMailbox  - your real Gmail inbox, using an App Password
  * DemoMailbox  - bundled sample emails, no credentials needed
"""
import email
import imaplib
import logging
import re
import socket
from dataclasses import dataclass, field
from email import policy
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser

import config
import settings_store

log = logging.getLogger("phishguard.ingest")

URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'\)\]]+)""")
HREF_RE = re.compile(r"""(?i)href\s*=\s*["']([^"']+)["']""")
ALERT_HEADER = "X-PhishGuard-Alert"


@dataclass
class ParsedEmail:
    uid: str
    message_id: str
    sender: str
    subject: str
    body_text: str
    urls: list[str] = field(default_factory=list)
    email_date: str = ""
    is_alert: bool = False   # PhishGuard's own alert emails must never be scanned again


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.chunks: list[str] = []
        self._skip = False

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip = True

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = False

    def handle_data(self, data):
        if not self._skip:
            self.chunks.append(data)


def html_to_text(html: str) -> str:
    p = _TextExtractor()
    p.feed(html)
    return " ".join(" ".join(p.chunks).split())


def extract_urls(text: str, html: str = "") -> list[str]:
    """Find every link in plain text and in HTML href attributes (de-duplicated, ordered)."""
    found: list[str] = []
    for raw in HREF_RE.findall(html or "") + URL_RE.findall(text or "") + URL_RE.findall(html or ""):
        url = raw.rstrip(".,;:!?'\"")
        if url.lower().startswith(("mailto:", "tel:", "#")):
            continue
        if url.lower().startswith("www."):
            url = "http://" + url
        if url not in found:
            found.append(url)
    return found


def _decode(value) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(str(value))))
    except Exception:
        return str(value)


def parse_message(raw: bytes, uid: str = "") -> ParsedEmail:
    msg = email.message_from_bytes(raw, policy=policy.default)
    plain, html = [], []
    for part in msg.walk():
        ctype = part.get_content_type()
        if part.get_content_maintype() == "multipart" or part.get_filename():
            continue
        try:
            content = part.get_content()
        except Exception:
            continue
        if ctype == "text/plain":
            plain.append(content)
        elif ctype == "text/html":
            html.append(content)
    text = "\n".join(plain).strip()
    html_body = "\n".join(html)
    if not text and html_body:
        text = html_to_text(html_body)
    try:
        date_iso = parsedate_to_datetime(str(msg.get("Date"))).isoformat(timespec="minutes")
    except Exception:
        date_iso = ""
    subject = _decode(msg.get("Subject"))
    return ParsedEmail(
        uid=uid,
        message_id=(msg.get("Message-ID") or f"no-id-{uid}").strip(),
        sender=_decode(msg.get("From")),
        subject=subject,
        body_text=text,
        urls=extract_urls(text, html_body),
        email_date=date_iso,
        is_alert=bool(msg.get(ALERT_HEADER)) or subject.startswith("[PhishGuard]"),
    )


def friendly_error(exc: Exception) -> str:
    """Turn low-level IMAP/network errors into messages a person can act on."""
    text = str(exc)
    if isinstance(exc, imaplib.IMAP4.error):
        if "AUTHENTICATIONFAILED" in text.upper() or "invalid credentials" in text.lower() or "login" in text.lower():
            return ("Gmail rejected the login. Use a 16-character App Password (not your normal Gmail "
                    "password), and check that IMAP is enabled in Gmail settings.")
        return f"Gmail returned an error: {text}"
    if isinstance(exc, (socket.gaierror, TimeoutError, ConnectionError, OSError)):
        return "Could not reach imap.gmail.com. Check your internet connection and try again."
    return f"Unexpected error: {text}"


def test_connection(address: str, password: str) -> dict:
    """Try logging in. Returns {ok, message, total, unseen}."""
    try:
        conn = imaplib.IMAP4_SSL(config.IMAP_SERVER, config.IMAP_PORT, timeout=20)
        conn.login(address, password)
        typ, data = conn.status("INBOX", "(MESSAGES UNSEEN)")
        nums = re.findall(r"(\d+)", data[0].decode()) if typ == "OK" and data and data[0] else ["0", "0"]
        conn.logout()
        return {"ok": True, "message": "Connected", "total": int(nums[0]), "unseen": int(nums[1])}
    except Exception as exc:
        return {"ok": False, "message": friendly_error(exc), "total": 0, "unseen": 0}


class ImapMailbox:
    """Live Gmail mailbox. Use as a context manager."""

    def __init__(self, settings: dict | None = None):
        self.s = settings or settings_store.load()
        self.conn: imaplib.IMAP4_SSL | None = None

    def __enter__(self):
        self.conn = imaplib.IMAP4_SSL(config.IMAP_SERVER, config.IMAP_PORT, timeout=60)
        self.conn.login(self.s["email"], self.s["app_password"])
        self.conn.select("INBOX")
        if self.s.get("auto_quarantine"):
            self.conn.create(f'"{config.QUARANTINE_FOLDER}"')  # "NO" just means it already exists
        return self

    def __exit__(self, *exc):
        try:
            self.conn.logout()
        except Exception:
            pass

    def fetch(self, scope: str = "recent", limit: int = 25):
        """Yield up to `limit` emails, newest first. scope: 'recent' (any) or 'unread'."""
        typ, data = self.conn.uid("SEARCH", None, "UNSEEN" if scope == "unread" else "ALL")
        if typ != "OK" or not data or not data[0]:
            return
        uids = data[0].split()[-int(limit):][::-1]
        for uid in uids:
            uid_s = uid.decode()
            typ, msg_data = self.conn.uid("FETCH", uid_s, "(BODY.PEEK[])")  # PEEK keeps it unread
            if typ != "OK" or not msg_data or not msg_data[0]:
                continue
            yield parse_message(msg_data[0][1], uid_s)

    def quarantine(self, uid: str) -> bool:
        """Copy to the PhishGuard-Quarantine label, then remove from the inbox (Gmail keeps it in All Mail)."""
        typ, _ = self.conn.uid("COPY", uid, f'"{config.QUARANTINE_FOLDER}"')
        if typ != "OK":
            log.error("Could not copy UID %s to quarantine folder", uid)
            return False
        self.conn.uid("STORE", uid, "+FLAGS", r"(\Deleted)")
        self.conn.expunge()
        return True


class DemoMailbox:
    """Offline mailbox that serves the bundled sample emails."""

    def fetch(self, scope: str = "recent", limit: int = 25):
        from demo_data import SAMPLE_EMAILS
        for i, raw in enumerate(SAMPLE_EMAILS, start=1):
            yield parse_message(raw.encode("utf-8"), uid=f"demo-{i}")

    def quarantine(self, uid: str) -> bool:
        log.info("[demo] simulated move of %s to quarantine folder", uid)
        return True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass
