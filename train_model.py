"""Train the content classifier (Stage 5).

  python train_model.py                      # builds a synthetic starter dataset, trains, evaluates
  python train_model.py --data my_emails.csv # use a real labelled dataset (columns: subject,body,label)

label: 1 = phishing, 0 = legitimate.

IMPORTANT: the built-in dataset is SYNTHETIC (template generated) so the project runs out of the box.
Scores on it are optimistic. For your final report, train on a real corpus, e.g. the Nazario phishing
corpus + Enron/SpamAssassin ham, or the Kaggle "Phishing Email Dataset", and report those numbers.
"""
import argparse
import csv
import json
import random
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

import config
from classifier import prepare_text

DATA_CSV = config.BASE_DIR / "data" / "emails_synthetic.csv"

# ------------------------------------------------------------------ synthetic data
BRANDS = ["PayPal", "Microsoft", "Amazon", "Apple", "Netflix", "State Bank", "HDFC Bank", "Google", "DHL", "Instagram"]
NAMES = ["Anita", "Rohit", "Meera", "Karan", "Sana", "Vikram", "Neha", "Arjun", "Divya", "Imran"]
TOPICS = ["the project review", "the lab schedule", "the quarterly report", "the workshop", "the internship drive", "the budget sheet"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]

PHISH = [
    ("URGENT: {b} account suspended", "Dear customer, we detected unauthorized activity. Your account will be suspended within {h} hours. Verify your password immediately at {url}"),
    ("{b} security alert", "We noticed a login from a new device. Confirm your identity now or your account will be locked. Sign in: {url}"),
    ("Payment failed - update billing", "Your {b} payment was declined. Update your payment details to avoid account termination. Final notice. {url}"),
    ("You have won a prize!", "Congratulations winner! Claim your ${n}00 reward today. Provide your bank account details to receive the transfer. {url}"),
    ("Invoice #{n}{n} attached - action required", "Please find the overdue invoice. Failure to pay immediately may lead to legal action. Review and confirm here: {url}"),
    ("Password expires today", "Your {b} password expires in {h} hours. Reset your password now to keep access to your mailbox. {url}"),
    ("Quick favour", "Hi {nm}, I'm in a meeting and can't talk. I need you to buy gift cards for a client urgently and send the codes. Keep this confidential, I will refund you."),
    ("Confidential - wire transfer", "{nm}, please process a wire transfer today to the account below. This is a private matter, do not tell anyone. I am the CEO and will explain later."),
    ("Package delivery failed", "Dear user, your {b} parcel could not be delivered. Pay a small redelivery fee within {h} hours or it will be returned. {url}"),
    ("Unusual sign-in activity", "Dear account holder, unauthorized access detected. Verify your account immediately using the secure link: {url} Act now."),
    ("IT support: mailbox quota full", "Dear user, your mailbox is full and will be closed. Log in to the IT support portal to confirm your password and avoid suspension. {url}"),
    ("Refund pending", "{b} owes you a refund of ${n}0. Confirm your bank account and security code to receive it right away. {url}"),
]
HAM = [
    ("{t} moved to {d}", "Hi {nm}, just a note that {t} is now on {d} at 3 pm. Please bring your slides. Thanks!"),
    ("Notes from today's meeting", "Hello team, attaching my notes from the meeting about {t}. Let me know if I missed anything. Regards, {nm}"),
    ("Lunch tomorrow?", "Hey {nm}, are you free for lunch on {d}? We can discuss {t} afterwards."),
    ("Wi-Fi maintenance on {d}", "Dear students, campus Wi-Fi will be offline for scheduled maintenance. No action is needed from you. IT Helpdesk"),
    ("Your {b} order has shipped", "Thanks for your order. Your package will arrive on {d}. Track it from your account in the {b} app. No further action needed."),
    ("Newsletter: this month's highlights", "Hello, read about placements, workshops and alumni meets in this month's newsletter: {url} Regards, Alumni Office"),
    ("Invoice for {t}", "Hi {nm}, attached is the invoice for {t} as agreed last week. Payment is due in 30 days; call me if you have questions."),
    ("Password policy update (info only)", "Dear staff, the password policy changes next month. No action is needed today; details will follow on the intranet. IT Department"),
    ("Assignment submission reminder", "Reminder: the assignment on {t} is due on {d}. Submit it through the college portal as usual. {url}"),
    ("Happy birthday!", "Many happy returns of the day, {nm}! Hope you have a great one. Cake in the pantry at 4."),
    ("Meeting minutes and action items", "Hi all, minutes for {t} are in the shared drive: {url} Please add comments by {d}."),
    ("Security tip of the month", "Hello, a friendly reminder to enable two-step verification on your accounts. Learn more at {url}. This is an awareness mail; nothing is required from you."),
]
BAD_HOSTS = ["secure-{b}-login.xyz", "{b}-verify-account.top", "account-{b}.click", "192.168.{n}.{n}", "login-{b}.support", "{b}.update-center.link"]
GOOD_HOSTS = ["www.college.example", "docs.college.example", "portal.company.example", "www.{b}.com", "drive.team.example"]


def _fill(tpl, rng, bad_url):
    b = rng.choice(BRANDS)
    slug = b.lower().replace(" ", "")
    host = rng.choice(BAD_HOSTS if bad_url else GOOD_HOSTS).format(b=slug, n=rng.randint(2, 250))
    scheme = "http" if bad_url and rng.random() < 0.6 else "https"
    url = f"{scheme}://{host}/{rng.choice(['verify', 'login', 'update', 'view', 'open'])}/{rng.randint(1000, 99999)}"
    return tpl.format(b=b, h=rng.choice([12, 24, 48]), n=rng.randint(1, 9), nm=rng.choice(NAMES),
                      t=rng.choice(TOPICS), d=rng.choice(DAYS), url=url)


def build_dataset(path: Path, per_class: int = 500, seed: int = 7):
    rng = random.Random(seed)
    rows = []
    for _ in range(per_class):
        s, b = rng.choice(PHISH)
        rows.append((_fill(s, rng, True), _fill(b, rng, True), 1))
        s, b = rng.choice(HAM)
        rows.append((_fill(s, rng, False), _fill(b, rng, False), 0))
    rng.shuffle(rows)
    path.parent.mkdir(exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["subject", "body", "label"])
        w.writerows(rows)
    return path


def load_csv(path: Path):
    X, y = [], []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            X.append(prepare_text(r.get("subject", ""), r.get("body", "")))
            y.append(int(r["label"]))
    return X, np.array(y)


# ------------------------------------------------------------------ training
def evaluate(model, X_te, y_te):
    pred = model.predict(X_te)
    tn, fp, fn, tp = confusion_matrix(y_te, pred, labels=[0, 1]).ravel()
    return {
        "precision": round(precision_score(y_te, pred, zero_division=0), 4),
        "recall": round(recall_score(y_te, pred, zero_division=0), 4),
        "f1": round(f1_score(y_te, pred, zero_division=0), 4),
        "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=None, help="CSV with columns subject,body,label")
    args = ap.parse_args()

    synthetic = args.data is None
    data_path = args.data or DATA_CSV
    if synthetic and not data_path.exists():
        build_dataset(data_path)
        print(f"Generated synthetic dataset: {data_path}")

    X, y = load_csv(data_path)
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    def vec():
        return TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, stop_words="english")

    candidates = {
        "NaiveBayes": Pipeline([("tfidf", vec()), ("clf", MultinomialNB(alpha=0.3))]),
        "RandomForest": Pipeline([("tfidf", vec()), ("clf", RandomForestClassifier(n_estimators=250, random_state=42, n_jobs=-1))]),
    }
    report = {}
    for name, model in candidates.items():
        model.fit(X_tr, y_tr)
        report[name] = evaluate(model, X_te, y_te)
        m = report[name]
        print(f"{name:13s} precision={m['precision']:.3f} recall={m['recall']:.3f} "
              f"f1={m['f1']:.3f} FPR={m['false_positive_rate']:.3f}")

    best = max(report, key=lambda k: (report[k]["f1"], -report[k]["false_positive_rate"]))
    final = candidates[best].fit(X, y)  # refit on all data after evaluation
    config.MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(final, config.MODEL_PATH)
    config.METRICS_PATH.write_text(json.dumps({
        "selected": best, "dataset": "synthetic" if synthetic else data_path.name,
        "n_train": len(X_tr), "n_test": len(X_te), "results": report,
    }, indent=2))
    print(f"\nSelected {best}. Saved model -> {config.MODEL_PATH}")
    if synthetic:
        print("Note: dataset is synthetic; use --data with a real corpus for final results.")


if __name__ == "__main__":
    main()
