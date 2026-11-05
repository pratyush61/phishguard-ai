"""Flask dashboard: python app.py  ->  http://127.0.0.1:5000"""
import json
import os
from datetime import datetime, timezone

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, url_for

import config
import database as db
import email_ingest
import scanner
import settings_store

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "phishguard-local-dashboard")
db.init_db()
scanner.apply_schedule()


# ------------------------------------------------------------------ helpers
def model_info():
    if config.METRICS_PATH.exists():
        m = json.loads(config.METRICS_PATH.read_text())
        return {"name": m["selected"], "dataset": m["dataset"], **m["results"][m["selected"]]}
    return None


def build_chart(days: int = 14) -> dict:
    rows = db.daily_counts(days)
    top = max([r["phishing"] + r["suspicious"] + r["safe"] for r in rows] + [1])
    H, BW, GAP = 140, 24, 12
    bars = []
    for i, r in enumerate(rows):
        x = i * (BW + GAP)
        h = {k: r[k] / top * H for k in ("safe", "suspicious", "phishing")}
        y_safe = H - h["safe"]
        y_sus = y_safe - h["suspicious"]
        y_phi = y_sus - h["phishing"]
        d = datetime.fromisoformat(r["date"])
        bars.append({"x": x, "w": BW, "label": d.strftime("%d %b"), "show_label": i % 2 == 0 or days <= 7,
                     "y_safe": y_safe, "h_safe": h["safe"], "y_sus": y_sus, "h_sus": h["suspicious"],
                     "y_phi": y_phi, "h_phi": h["phishing"], **{k: r[k] for k in ("safe", "suspicious", "phishing")}})
    return {"bars": bars, "w": days * (BW + GAP) - GAP, "h": H + 22, "base": H, "top": top}


def public_settings() -> dict:
    s = settings_store.load()
    s["has_password"] = bool(s["app_password"])
    s["app_password"] = ""     # never send the saved password back to the browser
    s["has_vt"] = bool(s["vt_key"])
    s["vt_key"] = ""
    return s


@app.context_processor
def inject_globals():
    s = settings_store.load()
    return {"gmail_connected": bool(s["email"] and s["app_password"]), "gmail_address": s["email"],
            "scan_state": scanner.state}


@app.template_filter("pct")
def pct(v):
    return f"{(v or 0) * 100:.0f}%"


@app.template_filter("when")
def when(iso):
    if not iso:
        return ""
    try:
        d = datetime.fromisoformat(iso)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        secs = (datetime.now(timezone.utc) - d).total_seconds()
        if secs < 60:
            return "just now"
        if secs < 3600:
            return f"{int(secs // 60)} min ago"
        if secs < 86400:
            return f"{int(secs // 3600)} h ago"
        return d.strftime("%d %b %Y, %H:%M")
    except ValueError:
        return iso


def _ints(name, default, lo, hi):
    try:
        return max(lo, min(hi, int(request.form.get(name, default))))
    except ValueError:
        return default


# ------------------------------------------------------------------ pages
@app.route("/")
def overview():
    stats = db.stats()
    total = stats["total"] or 1
    flagged = [e for e in db.list_events(60) if e["verdict"] != "safe"][:6]
    return render_template(
        "overview.html", stats=stats, chart=build_chart(), flagged=flagged,
        split={k: round(stats[k] / total * 100, 1) for k in ("phishing", "suspicious", "safe")},
        t_sus=config.SUSPICIOUS_THRESHOLD, t_phish=config.PHISHING_THRESHOLD,
    )


@app.route("/mailbox")
def mailbox():
    verdict, q = request.args.get("verdict"), request.args.get("q", "").strip()
    return render_template(
        "mailbox.html", events=db.list_events(300, verdict, q or None), stats=db.stats(),
        verdict=verdict, q=q, model=model_info(),
        t_sus=config.SUSPICIOUS_THRESHOLD, t_phish=config.PHISHING_THRESHOLD,
    )


@app.route("/event/<int:event_id>")
def event(event_id):
    ev = db.get_event(event_id)
    if not ev:
        abort(404)
    return render_template("event.html", ev=ev, t_sus=config.SUSPICIOUS_THRESHOLD, t_phish=config.PHISHING_THRESHOLD)


@app.route("/connect", methods=["GET", "POST"])
def connect():
    if request.method == "GET":
        return render_template("connect.html", s=public_settings())

    f, cur = request.form, settings_store.load()
    address = f.get("email", "").strip()
    password = f.get("app_password", "").replace(" ", "").strip()

    if password or address != cur["email"]:        # new login details: prove they work first
        if not address or not password:
            flash("Enter both your Gmail address and a 16-character App Password.", "error")
            return redirect(url_for("connect"))
        result = email_ingest.test_connection(address, password)
        if not result["ok"]:
            flash(result["message"], "error")
            return redirect(url_for("connect"))
        flash(f"Connected to {address}. Inbox has {result['total']} emails ({result['unseen']} unread).", "ok")
        settings_store.save(email=address, app_password=password)
    else:
        flash("Settings saved.", "ok")

    updates = {
        "alert_recipient": f.get("alert_recipient", "").strip(),
        "send_alerts": "send_alerts" in f,
        "auto_quarantine": "auto_quarantine" in f,
        "auto_scan": "auto_scan" in f,
        "interval_minutes": _ints("interval_minutes", 5, 1, 120),
        "scope": "unread" if f.get("scope") == "unread" else "recent",
        "recent_count": _ints("recent_count", 25, 5, 100),
    }
    if f.get("vt_key", "").strip():
        updates["vt_key"] = f["vt_key"].strip()
    settings_store.save(**updates)
    scanner.apply_schedule()
    return redirect(url_for("connect"))


@app.post("/disconnect")
def disconnect():
    settings_store.clear_credentials()
    scanner.apply_schedule()
    flash("Gmail disconnected and the saved App Password was deleted from this computer.", "ok")
    return redirect(url_for("connect"))


@app.post("/scan")
def scan():
    if not settings_store.connected():
        flash("Connect your Gmail account first.", "error")
        return redirect(url_for("connect"))
    if not scanner.start_scan("gmail"):
        flash("A scan is already running.", "ok")
    return redirect(request.referrer or url_for("overview"))


@app.post("/stop-scan")
def stop_scan():
    if scanner.stop_scan():
        flash("Stop requested. PhishGuard will finish the current network operation and stop safely.", "ok")
    else:
        flash("No scan is currently running.", "error")
    return redirect(request.referrer or url_for("overview"))


@app.post("/run-demo")
def run_demo():
    import pipeline
    pipeline.run_demo()
    flash("Demo scan finished: 6 sample emails were checked.", "ok")
    return redirect(url_for("overview"))


@app.post("/clear-history")
def clear_history():
    db.clear_all_events()
    flash("Scan history cleared.", "ok")
    return redirect(url_for("connect"))


@app.route("/api/status")
def api_status():
    return jsonify({**scanner.state, "stats": db.stats()})


@app.route("/api/events")
def api_events():
    return jsonify([dict(r) for r in db.list_events(200, request.args.get("verdict"))])


@app.route("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", 5000)), debug=False)
