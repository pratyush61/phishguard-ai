"""Stage 4: URL reputation.

Live mode  -> VirusTotal API v3 (needs VT_API_KEY).
Demo mode  -> local rule-based stand-in so the pipeline runs with no API key.

Every result is normalised to a 0-1 score so the risk engine can combine it.
"""
import base64
import ipaddress
import logging
import re
import time
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

import requests

import config

log = logging.getLogger("phishguard.url")

VT_BASE = "https://www.virustotal.com/api/v3"
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"}
RISKY_TLDS = {"xyz", "top", "click", "link", "work", "support", "zip", "mov", "loan", "gq", "tk", "ml", "cf", "ga", "country", "icu"}
LURE_WORDS = ("login", "signin", "verify", "secure", "account", "update", "billing", "wallet", "password", "confirm", "suspend", "unlock")
BRANDS = ("paypal", "microsoft", "google", "apple", "amazon", "netflix", "sbi", "hdfc", "icici", "paytm", "facebook", "instagram")

_cache: dict[str, "UrlResult"] = {}


@dataclass
class UrlResult:
    url: str
    score: float          # 0 (clean) .. 1 (malicious)
    source: str           # "virustotal" | "local-heuristic" | "error"
    detail: str

    def as_dict(self):
        return asdict(self)


# ---------------------------------------------------------------- VirusTotal
def _vt_score(stats: dict) -> tuple[float, str]:
    mal = int(stats.get("malicious", 0))
    sus = int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) or 1
    # 5 weighted detections (malicious=1, suspicious=0.5) saturate the score.
    score = min(1.0, (mal + 0.5 * sus) / 5)
    return score, f"{mal} malicious, {sus} suspicious of {total} engines"


def vt_lookup(url: str, api_key: str, cancel_event=None) -> UrlResult:
    headers = {"x-apikey": api_key}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        r = requests.get(f"{VT_BASE}/urls/{url_id}", headers=headers, timeout=20)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            score, detail = _vt_score(stats)
            return UrlResult(url, score, "virustotal", detail)
        if r.status_code == 404:  # never seen before: submit for analysis
            sub = requests.post(f"{VT_BASE}/urls", headers=headers, data={"url": url}, timeout=20)
            sub.raise_for_status()
            analysis_id = sub.json()["data"]["id"]
            for _ in range(6):
                if cancel_event and cancel_event.is_set():
                    raise ScanCancelled()
                if cancel_event and cancel_event.wait(5):
                    raise ScanCancelled()
                if not cancel_event:
                    time.sleep(5)
                a = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=20)
                a.raise_for_status()
                attrs = a.json()["data"]["attributes"]
                if attrs.get("status") == "completed":
                    score, detail = _vt_score(attrs["stats"])
                    return UrlResult(url, score, "virustotal", detail)
            return UrlResult(url, 0.0, "error", "VirusTotal analysis still pending")
        if r.status_code == 429:
            return UrlResult(url, 0.0, "error", "VirusTotal rate limit reached")
        return UrlResult(url, 0.0, "error", f"VirusTotal HTTP {r.status_code}")
    except requests.RequestException as exc:
        log.warning("VirusTotal request failed: %s", exc)
        return UrlResult(url, 0.0, "error", f"VirusTotal unreachable: {exc.__class__.__name__}")


# ------------------------------------------------------------ local stand-in
def heuristic_score(url: str) -> UrlResult:
    """Transparent rules that approximate a reputation service for demos/tests."""
    p = urlparse(url)
    host = (p.hostname or "").lower()
    pts, why = 0.0, []

    try:
        ipaddress.ip_address(host)
        pts += 0.5; why.append("host is a raw IP address")
    except ValueError:
        pass

    if host in SHORTENERS:
        pts += 0.3; why.append("URL shortener hides the real destination")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in RISKY_TLDS:
        pts += 0.3; why.append(f"high-abuse TLD .{tld}")
    if host.startswith("xn--") or ".xn--" in host:
        pts += 0.3; why.append("punycode (look-alike characters)")
    if "@" in p.netloc:
        pts += 0.3; why.append("'@' in URL hides the real host")
    if host.count("-") >= 2:
        pts += 0.2; why.append("many hyphens in domain")
    if host.count(".") >= 3:
        pts += 0.15; why.append("many subdomains")
    if p.scheme == "http":
        pts += 0.1; why.append("no HTTPS")
    for brand in BRANDS:
        # brand name inside a domain that is not the brand's own domain
        if brand in host and not re.search(rf"(^|\.){brand}\.(com|in|co\.in|net)$", host):
            pts += 0.35; why.append(f"impersonates brand '{brand}'")
            break
    if any(w in (host + p.path).lower() for w in LURE_WORDS):
        pts += 0.15; why.append("credential-lure keyword in URL")

    score = min(1.0, pts)
    return UrlResult(url, score, "local-heuristic", "; ".join(why) or "no risky traits found")


# ------------------------------------------------------------------ public
class ScanCancelled(Exception):
    """Raised when the user asks the active scan to stop."""


def scan_urls(urls: list[str], vt_key: str = "", cancel_event=None) -> list[UrlResult]:
    """Score each link. Uses VirusTotal when a key is given, else the local rule-based checker."""
    results = []
    for url in urls[: config.MAX_URLS_PER_EMAIL]:
        if cancel_event and cancel_event.is_set():
            raise ScanCancelled()
        cache_key = f"{'vt' if vt_key else 'local'}:{url}"
        if cache_key in _cache:
            results.append(_cache[cache_key])
            continue
        if vt_key:
            res = vt_lookup(url, vt_key, cancel_event)
            if res.source == "error":      # VirusTotal failed: fall back so the email is still checked
                local = heuristic_score(url)
                local.detail = f"{res.detail}. Local check: {local.detail}"
                res = local
            if cancel_event and cancel_event.wait(config.VT_DELAY_SECONDS):
                raise ScanCancelled()
            if not cancel_event:
                time.sleep(config.VT_DELAY_SECONDS)  # respect free-tier rate limit (4 requests/minute)
        else:
            res = heuristic_score(url)
        _cache[cache_key] = res
        results.append(res)
    return results
