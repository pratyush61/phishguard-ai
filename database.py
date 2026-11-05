"""SQLite persistence: every decision is stored for audit and the dashboard."""
import json
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    processed_at  TEXT NOT NULL,
    message_id    TEXT NOT NULL,
    sender        TEXT,
    subject       TEXT,
    url_results   TEXT,
    url_score     REAL,
    content_score REAL,
    risk_score    REAL,
    verdict       TEXT,
    reasons       TEXT,
    quarantined   INTEGER DEFAULT 0,
    alerted       INTEGER DEFAULT 0,
    response_ms   REAL,
    mode          TEXT,
    email_date    TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_msg ON events(message_id);
CREATE INDEX IF NOT EXISTS idx_events_verdict ON events(verdict);
"""


@contextmanager
def connect():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as c:
        c.executescript(SCHEMA)
        cols = {r["name"] for r in c.execute("PRAGMA table_info(events)")}
        if "email_date" not in cols:  # upgrade databases made by the first version
            c.execute("ALTER TABLE events ADD COLUMN email_date TEXT")


def already_processed(message_id: str) -> bool:
    with connect() as c:
        return c.execute("SELECT 1 FROM events WHERE message_id = ?", (message_id,)).fetchone() is not None


def insert_event(**e) -> int:
    with connect() as c:
        cur = c.execute(
            """INSERT INTO events (processed_at, message_id, sender, subject, url_results,
                   url_score, content_score, risk_score, verdict, reasons, quarantined,
                   alerted, response_ms, mode, email_date)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                e["message_id"], e["sender"], e["subject"],
                json.dumps(e["url_results"]), e["url_score"], e["content_score"],
                e["risk_score"], e["verdict"], json.dumps(e["reasons"]),
                int(e["quarantined"]), int(e["alerted"]), e["response_ms"], e["mode"],
                e.get("email_date", ""),
            ),
        )
        return cur.lastrowid


def list_events(limit: int = 200, verdict: str | None = None, q: str | None = None) -> list[sqlite3.Row]:
    sql, args, where = "SELECT * FROM events", [], []
    if verdict in ("phishing", "suspicious", "safe"):
        where.append("verdict = ?"); args.append(verdict)
    if q:
        where.append("(subject LIKE ? OR sender LIKE ?)"); args += [f"%{q}%", f"%{q}%"]
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with connect() as c:
        return c.execute(sql, args).fetchall()


def get_event(event_id: int) -> dict | None:
    with connect() as c:
        row = c.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if not row:
        return None
    ev = dict(row)
    ev["url_results"] = json.loads(ev["url_results"] or "[]")
    ev["reasons"] = json.loads(ev["reasons"] or "[]")
    return ev


def clear_demo_events() -> None:
    with connect() as c:
        c.execute("DELETE FROM events WHERE mode = 'demo'")


def clear_all_events() -> None:
    with connect() as c:
        c.execute("DELETE FROM events")


def stats() -> dict:
    with connect() as c:
        r = c.execute(
            """SELECT COUNT(*) AS total,
                      COALESCE(SUM(verdict='phishing'),0)   AS phishing,
                      COALESCE(SUM(verdict='suspicious'),0) AS suspicious,
                      COALESCE(SUM(verdict='safe'),0)       AS safe,
                      COALESCE(SUM(quarantined),0)          AS quarantined,
                      COALESCE(SUM(alerted),0)              AS alerted,
                      COALESCE(AVG(response_ms),0)          AS avg_ms,
                      MAX(processed_at)                     AS last_processed
               FROM events"""
        ).fetchone()
    return dict(r)


def daily_counts(days: int = 14) -> list[dict]:
    """Verdict counts per day (UTC) for the last `days` days, oldest first, gaps filled with zeros."""
    today = datetime.now(timezone.utc).date()
    start = today - timedelta(days=days - 1)
    with connect() as c:
        rows = c.execute(
            """SELECT substr(processed_at,1,10) AS d, verdict, COUNT(*) AS n
               FROM events WHERE substr(processed_at,1,10) >= ? GROUP BY d, verdict""",
            (start.isoformat(),),
        ).fetchall()
    table = {(start + timedelta(days=i)).isoformat(): {"phishing": 0, "suspicious": 0, "safe": 0} for i in range(days)}
    for r in rows:
        if r["d"] in table and r["verdict"] in table[r["d"]]:
            table[r["d"]][r["verdict"]] = r["n"]
    return [{"date": d, **v} for d, v in table.items()]
