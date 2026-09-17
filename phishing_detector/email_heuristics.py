"""Heuristic checks for suspicious email text.

Accepts plain text or simple HTML-ish text (e.g. containing
``<a href="...">...</a>`` anchors). Nothing here sends network requests or
renders HTML; anchors are located with a regex, which is sufficient for the
narrow "does the visible text point somewhere different than the href"
check this tool performs.
"""

import re
from urllib.parse import urlsplit

from .data import GENERIC_GREETINGS, SENSITIVE_INFO_KEYWORDS, URGENCY_PHRASES
from .signals import Assessment, Signal

WEIGHT_URGENCY_PER_HIT = 10
WEIGHT_URGENCY_MAX = 30
WEIGHT_MISMATCHED_LINK = 35
WEIGHT_GENERIC_GREETING = 10
WEIGHT_SENSITIVE_INFO = 30

_ANCHOR_RE = re.compile(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
_DOMAIN_IN_TEXT_RE = re.compile(r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b')
_TAG_RE = re.compile(r"<[^>]+>")
_REQUEST_VERBS = {
    "enter", "provide", "confirm", "verify", "send", "update", "re-enter",
    "reenter", "submit", "share", "give", "reply with", "type in",
}


def _hostname(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    host = urlsplit(url).hostname or ""
    return host.lower()


def _registrable(host: str) -> str:
    labels = [l for l in host.split(".") if l]
    if len(labels) <= 2:
        return host
    return ".".join(labels[-2:])


def check_urgency_language(text: str) -> Signal:
    lowered = (text or "").lower()
    hits = sorted({phrase for phrase in URGENCY_PHRASES if phrase in lowered})
    fired = len(hits) > 0
    weight = min(WEIGHT_URGENCY_PER_HIT * len(hits), WEIGHT_URGENCY_MAX) if fired else 0
    detail = (
        f"urgency/pressure phrase(s) found: {', '.join(hits)}"
        if fired
        else "no urgency/pressure phrases found"
    )
    return Signal("urgency_language", fired, weight, detail)


def check_mismatched_links(text: str) -> Signal:
    anchors = _ANCHOR_RE.findall(text or "")
    mismatches = []
    for href, display_raw in anchors:
        display = _TAG_RE.sub(" ", display_raw)
        href_domain = _registrable(_hostname(href))
        if not href_domain:
            continue
        for match in _DOMAIN_IN_TEXT_RE.finditer(display):
            shown_domain = match.group(1).lower()
            shown_registrable = _registrable(shown_domain)
            if shown_registrable != href_domain:
                mismatches.append(f"text shows '{shown_domain}' but link goes to '{href_domain}'")
    fired = len(mismatches) > 0
    detail = "; ".join(mismatches) if fired else "no display-text/destination mismatches found"
    return Signal("mismatched_link", fired, WEIGHT_MISMATCHED_LINK, detail)


def check_generic_greeting(text: str) -> Signal:
    lowered = (text or "").lower()
    head = lowered[:200]
    hits = [g for g in GENERIC_GREETINGS if g in head]
    fired = len(hits) > 0
    detail = (
        f"generic greeting found: '{hits[0]}' (no personalization)"
        if fired
        else "no generic greeting detected"
    )
    return Signal("generic_greeting", fired, WEIGHT_GENERIC_GREETING, detail)


def check_sensitive_info_request(text: str) -> Signal:
    lowered = (text or "").lower()
    keyword_hits = sorted({kw for kw in SENSITIVE_INFO_KEYWORDS if kw in lowered})
    verb_hit = any(verb in lowered for verb in _REQUEST_VERBS)
    fired = len(keyword_hits) > 0 and verb_hit
    detail = (
        f"requests sensitive info ({', '.join(keyword_hits)}) alongside a request/action verb"
        if fired
        else "no combined sensitive-info request detected"
    )
    return Signal("sensitive_info_request", fired, WEIGHT_SENSITIVE_INFO, detail)


def assess_email_text(text: str) -> Assessment:
    """Run every email heuristic and return a combined Assessment."""
    from .scoring import combine  # local import avoids a circular import

    signals = [
        check_urgency_language(text),
        check_mismatched_links(text),
        check_generic_greeting(text),
        check_sensitive_info_request(text),
    ]
    score, verdict = combine(signals)
    subject = (text or "").strip().splitlines()[0][:60] + ("..." if len(text or "") > 60 else "") if text else "(empty)"
    return Assessment(subject=f"email text: {subject}", signals=signals, score=score, verdict=verdict)
