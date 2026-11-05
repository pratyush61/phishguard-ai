"""Background scanning: 'Scan now' button and optional automatic polling (APScheduler)."""
import logging
import threading
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler

import email_ingest
import pipeline
import url_tools
import settings_store

log = logging.getLogger("phishguard.scanner")

state = {"running": False, "processed": 0, "current": "", "error": None,
         "last_finished": None, "last_summary": None}
_lock = threading.Lock()
_cancel_event = threading.Event()
_scheduler = BackgroundScheduler(daemon=True)


def _progress(n: int, subject: str):
    state["processed"], state["current"] = n, subject[:60]


def _worker(source: str):
    try:
        state["last_summary"] = pipeline.run_scan(source, _progress, _cancel_event)
    except url_tools.ScanCancelled:
        state["last_summary"] = {"cancelled": True, "processed": state["processed"]}
    except Exception as exc:
        log.exception("Scan failed")
        state["error"] = email_ingest.friendly_error(exc)
    finally:
        state["last_finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        state["running"] = False
        state["current"] = ""


def start_scan(source: str = "gmail") -> bool:
    """Start a scan in the background. Returns False if one is already running."""
    with _lock:
        if state["running"]:
            return False
        _cancel_event.clear()
        state.update(running=True, processed=0, current="", error=None, last_summary=None)
    threading.Thread(target=_worker, args=(source,), daemon=True).start()
    return True


def apply_schedule() -> None:
    """(Re)create the automatic scan job from the saved settings."""
    if not _scheduler.running:
        _scheduler.start()
    if _scheduler.get_job("autoscan"):
        _scheduler.remove_job("autoscan")
    s = settings_store.load()
    if s["auto_scan"] and settings_store.connected():
        _scheduler.add_job(start_scan, "interval", minutes=int(s["interval_minutes"]),
                           id="autoscan", args=["gmail"], max_instances=1, coalesce=True)
        log.info("Auto-scan every %s minutes", s["interval_minutes"])


def stop_scan() -> bool:
    """Request cancellation of the active scan."""
    with _lock:
        if not state["running"]:
            return False
        _cancel_event.set()
        return True
