# PhishGuard AI: Automated Email Phishing Detection, Quarantine & Alert System

ABESEC Ghaziabad, Department of CSE (Session 2026-27)
Team: Pratyush Dubey, Naina Gupta. Guide: Mr. Sumit Agrawal

Connect your Gmail from the dashboard. PhishGuard reads your inbox over IMAP, checks every link
(VirusTotal or a built-in checker), scores the message wording with a trained ML model, combines both
into one explainable risk score, optionally quarantines phishing, emails you an alert over SMTP, and
logs every decision to SQLite for the dashboard.

## Run it (macOS / Linux)

```bash
cd phishguard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python train_model.py
python app.py
```
Open http://127.0.0.1:5000 (if port 5000 is busy on a Mac: `PORT=5001 python app.py`).

1. Click **Connect Gmail** in the sidebar and follow the 4 steps shown beside the form (App Password).
2. Press **Save**. PhishGuard logs in to prove the details work.
3. Press **Scan my inbox now** on the Overview page. Results appear when the scan finishes.
4. Optional: tick "Scan automatically" to keep checking every few minutes while the app runs.

No Gmail yet? Press **Run demo scan** to see the full pipeline on 6 sample emails.

## Safety defaults
- Automatic quarantine is **off**. Phishing is flagged only, until you tick the box on the Connect page.
- When on, phishing is copied to a `PhishGuard-Quarantine` label and removed from the inbox. Gmail keeps it in All Mail, so nothing is deleted.
- Mail is read with `BODY.PEEK`, so emails are not marked as read.
- PhishGuard's own alert emails are tagged and never re-scanned (prevents alert loops).
- Your App Password is stored in `var/settings.json` (owner-only permissions) and is only sent to Google. "Disconnect" deletes it.
- Only monitor mailboxes you own or have permission to monitor.

## Pipeline (matches Section 1.4 of the synopsis)

| # | Stage | File |
|---|-------|------|
| 1 | Connect to mailbox (IMAP) | `email_ingest.py` (`ImapMailbox`) |
| 2 | Fetch emails, on demand or on a schedule (APScheduler) | `scanner.py` |
| 3 | Parse email, extract URLs | `email_ingest.py` |
| 4 | URL reputation (VirusTotal v3, or local checker) | `url_tools.py` |
| 5 | NLP/ML content classification | `classifier.py`, `train_model.py` |
| 6 | Risk scoring and decision engine | `risk_engine.py` |
| 7 | Quarantine | `email_ingest.py` (`quarantine`) |
| 8 | SMTP alert | `responder.py` |
| 9 | Log and dashboard | `database.py`, `app.py`, `templates/` |

`pipeline.py` ties the stages together. `settings_store.py` holds the saved Gmail login and preferences.

## Risk score
- URL score: VirusTotal `(malicious + 0.5 x suspicious) / 5`, capped at 1. Highest-scoring link wins.
- Content score: probability of "phishing" from the TF-IDF + Naive Bayes / Random Forest model.
- Combined: `0.5 x url + 0.5 x content` (content only if there are no links).
- Escalation: URL score >= 0.6 forces risk to at least 0.85; content score >= 0.90 forces at least 0.70.
- Verdict: `>= 0.70` phishing, `0.40-0.70` suspicious, below that safe.
Weights and thresholds can be set in `.env` (see `.env.example`). Every reason is shown on the email's detail page.

## Train on a real dataset (do this for your final report)
The built-in dataset is **synthetic**, so its near-100% scores are not a valid evaluation. Save a real labelled
corpus (e.g. Nazario phishing + SpamAssassin/Enron legitimate mail, or a Kaggle phishing email dataset) as a CSV
with columns `subject,body,label` (1 = phishing, 0 = legitimate), then:
```bash
python train_model.py --data my_emails.csv
```
Precision, recall, F1 and false-positive rate are printed and saved to `models/metrics.json`.

## Other commands
```bash
python main.py --mode demo     # command-line demo
python main.py --mode live     # one scan of the saved Gmail account
python -m pytest               # 13 tests
docker compose up --build      # dashboard in Docker on port 5000
```

## Limitations
One mailbox at a time. Email only (no SMS/voice). No attachment scanning. The VirusTotal free plan allows
4 lookups a minute, so only the first 5 links per email are checked.

## Attribution
The idea of an IMAP + VirusTotal quarantine/alert tool was inspired by
[jagdishtripathy/Email-phishing-detector](https://github.com/jagdishtripathy/Email-phishing-detector) (MIT).
This codebase was written independently and adds the ML classifier, risk engine, SQLite logging, Flask
dashboard with in-app Gmail connection, scheduler, tests and Docker setup.
