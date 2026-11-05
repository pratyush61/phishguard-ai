"""Orchestrates the nine stages for one scan of a mailbox."""
import logging
import time
from collections import Counter

import classifier
import database as db
import responder
import risk_engine
import settings_store
import url_tools
from email_ingest import DemoMailbox, ImapMailbox

log = logging.getLogger("phishguard.pipeline")


def open_mailbox(source: str, settings: dict):
    return DemoMailbox() if source == "demo" else ImapMailbox(settings)


def process_email(parsed, mailbox, source: str, s: dict, cancel_event=None):
    """Stages 4-9 for one parsed email. Returns the Decision, or None if it was skipped."""
    if parsed.is_alert or db.already_processed(parsed.message_id):
        return None
    t0 = time.perf_counter()
    live = source != "demo"

    if cancel_event and cancel_event.is_set():
        raise url_tools.ScanCancelled()
    url_results = url_tools.scan_urls(parsed.urls, s["vt_key"] if live else "", cancel_event)  # 4
    if cancel_event and cancel_event.is_set():
        raise url_tools.ScanCancelled()
    url_score = max((r.score for r in url_results), default=0.0)
    content = classifier.classify(parsed.subject, parsed.body_text)                  # 5
    decision = risk_engine.decide(url_score, content.score, bool(parsed.urls),        # 6
                                  url_results, content.cues, content.method)

    quarantined = alerted = False
    if cancel_event and cancel_event.is_set():
        raise url_tools.ScanCancelled()
    if decision.verdict == "phishing" and (s["auto_quarantine"] or not live):        # 7
        quarantined = mailbox.quarantine(parsed.uid)
    if decision.verdict in ("phishing", "suspicious") and (s["send_alerts"] or not live):   # 8
        alerted = responder.send_alert(parsed, decision, quarantined, s, live)

    response_ms = round((time.perf_counter() - t0) * 1000, 1)
    db.insert_event(                                                                 # 9
        message_id=parsed.message_id, sender=parsed.sender, subject=parsed.subject,
        url_results=[r.as_dict() for r in url_results], url_score=url_score,
        content_score=content.score, risk_score=decision.risk, verdict=decision.verdict,
        reasons=decision.reasons, quarantined=quarantined, alerted=alerted,
        response_ms=response_ms, mode=source, email_date=parsed.email_date,
    )
    log.info("%-10s risk=%.2f  %s", decision.verdict.upper(), decision.risk, parsed.subject[:60])
    return decision


def run_scan(source: str = "gmail", progress_cb=None, cancel_event=None) -> dict:
    """One full pass over the mailbox. Returns counts: processed, skipped, phishing, suspicious, safe."""
    db.init_db()
    s = settings_store.load()
    summary: Counter = Counter()
    with open_mailbox(source, s) as mailbox:                                          # 1
        for parsed in mailbox.fetch(s["scope"], int(s["recent_count"])):              # 2-3
            if cancel_event and cancel_event.is_set():
                break
            decision = process_email(parsed, mailbox, source, s, cancel_event)
            if decision is None:
                summary["skipped"] += 1
                continue
            summary["processed"] += 1
            summary[decision.verdict] += 1
            if progress_cb:
                progress_cb(summary["processed"], parsed.subject)
    return {k: summary.get(k, 0) for k in ("processed", "skipped", "phishing", "suspicious", "safe")}


def run_demo() -> dict:
    import config
    db.init_db()
    db.clear_demo_events()
    if config.ALERT_OUTBOX.exists():
        config.ALERT_OUTBOX.unlink()
    return run_scan("demo")
