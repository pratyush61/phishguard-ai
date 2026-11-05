"""Stage 6: combine URL reputation and content score into one explainable risk score."""
from dataclasses import dataclass, field

import config


@dataclass
class Decision:
    risk: float
    verdict: str                      # "phishing" | "suspicious" | "safe"
    reasons: list[str] = field(default_factory=list)


def decide(url_score: float, content_score: float, has_urls: bool,
           url_details: list | None = None, cues: list[str] | None = None,
           content_method: str = "ml-model") -> Decision:
    reasons: list[str] = []

    if has_urls:
        total_w = config.URL_WEIGHT + config.CONTENT_WEIGHT
        risk = (config.URL_WEIGHT * url_score + config.CONTENT_WEIGHT * content_score) / total_w
    else:
        # No links to check: the text is the only evidence, so it carries full weight.
        risk = content_score
        reasons.append("No links found - decision based on message text only")

    # Escalation rules (each one is logged so the decision stays explainable)
    if url_score >= 0.6:
        if risk < 0.85:
            risk = 0.85
        reasons.append("A link was rated malicious by the URL reputation check")
    if content_score >= config.STRONG_CONTENT_THRESHOLD and risk < config.PHISHING_THRESHOLD:
        risk = config.PHISHING_THRESHOLD
        reasons.append("Message text strongly matches phishing patterns")

    for d in (url_details or []):
        if d.score >= 0.3:
            reasons.append(f"Link {d.url[:60]} - {d.detail}")
    if cues:
        reasons.append("Social-engineering cues: " + ", ".join(cues))
    if content_method == "keyword-heuristic":
        reasons.append("Content score from keyword heuristic (ML model not trained yet)")

    risk = round(min(1.0, max(0.0, risk)), 3)
    if risk >= config.PHISHING_THRESHOLD:
        verdict = "phishing"
    elif risk >= config.SUSPICIOUS_THRESHOLD:
        verdict = "suspicious"
    else:
        verdict = "safe"
    return Decision(risk, verdict, reasons)
