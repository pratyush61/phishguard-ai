"""Stage 5: content-based phishing classification.

Primary scorer : scikit-learn model (TF-IDF + Naive Bayes / Random Forest) trained by train_model.py
Fallback       : keyword/cue heuristic (used only if no trained model file exists)
Explanations   : social-engineering cue detector, shown on the dashboard either way
"""
import logging
import re
from dataclasses import dataclass, field

import joblib

import config

log = logging.getLogger("phishguard.classifier")

CUES = {
    "urgency / time pressure": (0.25, r"\b(urgent(ly)?|immediately|within \d+ ?(hours?|hrs?|minutes?)|act now|final notice|expires?|last warning|asap|right away)\b"),
    "credential request": (0.30, r"\b(verify your (account|identity|password|details)|confirm your (password|identity|account|details)|log ?in|sign ?in|update your (payment|billing|password|details)|reset your password|security code|one[- ]time (password|code)|otp)\b"),
    "financial lure": (0.25, r"\b(wire transfer|gift cards?|payment (failed|declined|overdue)|refund|bank account|lottery|prize|winner|bitcoin|crypto)\b"),
    "threat of account loss": (0.25, r"\b(account (will be |has been )?(closed|locked|terminated|suspended|limited)|legal action|unauthori[sz]ed (access|activity|login))\b"),
    "secrecy request": (0.15, r"\b(confidential|do not tell|don'?t tell|keep this between|private matter|don'?t share|do not share)\b"),
    "generic greeting": (0.15, r"\b(dear (customer|user|member|client|account holder)|valued customer)\b"),
    "authority impersonation": (0.10, r"\b(ceo|it (support|department|help ?desk)|security team|system administrator|paypal|microsoft|amazon|apple|netflix)\b"),
}
_CUE_RE = {k: (w, re.compile(p, re.I)) for k, (w, p) in CUES.items()}
_URL_SUB = re.compile(r"(?i)(https?://|www\.)\S+")

_model = None
_model_loaded = False


def prepare_text(subject: str, body: str) -> str:
    """Single normalisation used by BOTH training and inference."""
    text = f"{subject} . {body}"
    text = _URL_SUB.sub(" urltoken ", text)
    return re.sub(r"\s+", " ", text).strip().lower()


def detect_cues(subject: str, body: str) -> list[str]:
    text = f"{subject} {body}"
    return [name for name, (_, rx) in _CUE_RE.items() if rx.search(text)]


def heuristic_score(subject: str, body: str) -> float:
    text = f"{subject} {body}"
    score = sum(w for _, (w, rx) in _CUE_RE.items() if rx.search(text))
    if subject.isupper() and len(subject) > 8:
        score += 0.1
    if text.count("!") >= 3:
        score += 0.1
    return min(1.0, score)


def _load_model():
    global _model, _model_loaded
    if not _model_loaded:
        _model_loaded = True
        if config.MODEL_PATH.exists():
            _model = joblib.load(config.MODEL_PATH)
            log.info("Loaded content model from %s", config.MODEL_PATH)
        else:
            log.warning("No trained model at %s - using keyword heuristic. Run: python train_model.py", config.MODEL_PATH)
    return _model


@dataclass
class ContentResult:
    score: float
    method: str                       # "ml-model" | "keyword-heuristic"
    cues: list[str] = field(default_factory=list)


def classify(subject: str, body: str) -> ContentResult:
    cues = detect_cues(subject, body)
    model = _load_model()
    if model is None:
        return ContentResult(heuristic_score(subject, body), "keyword-heuristic", cues)
    proba = model.predict_proba([prepare_text(subject, body)])[0]
    phishing_idx = list(model.classes_).index(1)
    return ContentResult(float(proba[phishing_idx]), "ml-model", cues)
