"""Heuristic checks for suspicious URLs.

Every check returns a Signal. See README.md "Methodology" section for the
rationale and weight of each one. All checks are pure/local -- nothing
here makes a network request.
"""

import ipaddress
from urllib.parse import urlsplit

from .data import POPULAR_DOMAINS, SUSPICIOUS_PATH_KEYWORDS, SUSPICIOUS_TLDS, URL_SHORTENERS
from .signals import Assessment, Signal
from .utils import levenshtein_distance

# Weights (documented in README "Scoring" table). Kept as module-level
# constants so tests and README stay honest about the same numbers.
WEIGHT_IP_HOSTNAME = 25
WEIGHT_EXCESSIVE_SUBDOMAINS = 15
WEIGHT_AT_SYMBOL = 20
WEIGHT_SUSPICIOUS_TLD = 15
WEIGHT_TYPOSQUAT = 30
WEIGHT_URL_SHORTENER = 10
WEIGHT_SUSPICIOUS_KEYWORDS = 15
WEIGHT_NON_STANDARD_PORT = 10
WEIGHT_EXCESSIVE_LENGTH = 10

SUBDOMAIN_THRESHOLD = 3   # subdomain labels beyond "domain.tld"
LENGTH_THRESHOLD = 75     # characters
TYPOSQUAT_MAX_DISTANCE = 2


def _normalize(url: str) -> str:
    url = (url or "").strip()
    if "://" not in url:
        url = "http://" + url
    return url


def _hostname_only(netloc: str) -> str:
    """Strip userinfo (user:pass@) and port from a netloc."""
    host = netloc.split("@")[-1]
    if host.startswith("["):  # IPv6 literal, e.g. [::1]:8080
        return host.split("]")[0].lstrip("[")
    return host.split(":")[0]


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _registrable_domain(hostname: str) -> str:
    """Best-effort last-two-labels domain, e.g. 'a.b.paypal.com' -> 'paypal.com'.

    Not fully public-suffix-list correct (e.g. co.uk cases), which is a
    documented, acceptable limitation for a lightweight local heuristic.
    """
    labels = hostname.split(".")
    if len(labels) <= 2:
        return hostname
    return ".".join(labels[-2:])


def check_ip_hostname(hostname: str) -> Signal:
    fired = _is_ip(hostname)
    detail = (
        f"hostname '{hostname}' is a bare IP address (no domain name)"
        if fired
        else "hostname is not a bare IP address"
    )
    return Signal("ip_hostname", fired, WEIGHT_IP_HOSTNAME, detail)


def check_excessive_subdomains(hostname: str) -> Signal:
    if _is_ip(hostname):
        return Signal("excessive_subdomains", False, WEIGHT_EXCESSIVE_SUBDOMAINS, "n/a (IP hostname)")
    labels = [label for label in hostname.split(".") if label]
    subdomain_count = max(len(labels) - 2, 0)
    fired = subdomain_count >= SUBDOMAIN_THRESHOLD
    detail = f"{subdomain_count} subdomain label(s) before the base domain"
    return Signal("excessive_subdomains", fired, WEIGHT_EXCESSIVE_SUBDOMAINS, detail)


def check_at_symbol(url: str) -> Signal:
    parsed = urlsplit(_normalize(url))
    fired = "@" in parsed.netloc
    detail = (
        "'@' found before the host -- browsers treat everything before it as "
        "discarded userinfo, a classic destination-hiding trick"
        if fired
        else "no '@' obfuscation found in the authority section"
    )
    return Signal("at_symbol", fired, WEIGHT_AT_SYMBOL, detail)


def check_suspicious_tld(hostname: str) -> Signal:
    if _is_ip(hostname):
        return Signal("suspicious_tld", False, WEIGHT_SUSPICIOUS_TLD, "n/a (IP hostname)")
    tld = hostname.rsplit(".", 1)[-1].lower() if "." in hostname else ""
    fired = tld in SUSPICIOUS_TLDS
    detail = (
        f"'.{tld}' is on the curated frequently-abused TLD list"
        if fired
        else f"TLD '.{tld}' is not on the curated frequently-abused TLD list"
    )
    return Signal("suspicious_tld", fired, WEIGHT_SUSPICIOUS_TLD, detail)


def check_typosquat(hostname: str):
    """Returns (Signal, closest_domain_or_None)."""
    if _is_ip(hostname):
        return Signal("typosquat", False, WEIGHT_TYPOSQUAT, "n/a (IP hostname)"), None

    domain = _registrable_domain(hostname).lower()
    best_domain = None
    best_distance = None
    for popular in POPULAR_DOMAINS:
        if domain == popular:
            # Exact match against a known popular domain: this IS the real
            # thing, not an impersonation of it.
            return (
                Signal("typosquat", False, WEIGHT_TYPOSQUAT, f"matches known domain '{popular}' exactly"),
                None,
            )
        if abs(len(domain) - len(popular)) > TYPOSQUAT_MAX_DISTANCE:
            continue
        distance = levenshtein_distance(domain, popular)
        if best_distance is None or distance < best_distance:
            best_distance = distance
            best_domain = popular

    fired = best_distance is not None and 0 < best_distance <= TYPOSQUAT_MAX_DISTANCE
    if fired:
        detail = f"'{domain}' is only {best_distance} edit(s) away from popular domain '{best_domain}' (possible typosquat)"
        return Signal("typosquat", True, WEIGHT_TYPOSQUAT, detail), best_domain
    detail = "no close match to a known popular domain"
    return Signal("typosquat", False, WEIGHT_TYPOSQUAT, detail), None


def check_url_shortener(hostname: str) -> Signal:
    host = hostname.lower()
    if host.startswith("www."):
        host = host[4:]
    fired = host in URL_SHORTENERS
    detail = (
        f"'{host}' is a known URL shortener -- real destination is hidden"
        if fired
        else "hostname is not a known URL shortener"
    )
    return Signal("url_shortener", fired, WEIGHT_URL_SHORTENER, detail)


def check_suspicious_keywords(url: str) -> Signal:
    parsed = urlsplit(_normalize(url))
    haystack = f"{parsed.path}?{parsed.query}".lower()
    hits = sorted({kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in haystack})
    fired = len(hits) > 0
    detail = (
        f"path/query contains sensitive-sounding keyword(s): {', '.join(hits)}"
        if fired
        else "no sensitive-sounding keywords in path/query"
    )
    return Signal("suspicious_keywords", fired, WEIGHT_SUSPICIOUS_KEYWORDS, detail)


def check_non_standard_port(url: str) -> Signal:
    parsed = urlsplit(_normalize(url))
    try:
        port = parsed.port
    except ValueError:
        port = None
    fired = port is not None and port not in (80, 443)
    detail = f"non-standard port {port} in URL" if fired else "no non-standard port"
    return Signal("non_standard_port", fired, WEIGHT_NON_STANDARD_PORT, detail)


def check_excessive_length(url: str) -> Signal:
    length = len(url)
    fired = length > LENGTH_THRESHOLD
    detail = f"URL is {length} characters long (> {LENGTH_THRESHOLD})" if fired else f"URL length {length} is within normal range"
    return Signal("excessive_length", fired, WEIGHT_EXCESSIVE_LENGTH, detail)


def assess_url(url: str) -> Assessment:
    """Run every URL heuristic and return a combined Assessment."""
    from .scoring import combine  # local import avoids a circular import

    normalized = _normalize(url)
    parsed = urlsplit(normalized)
    hostname = _hostname_only(parsed.netloc)

    typosquat_signal, _closest = check_typosquat(hostname)

    signals = [
        check_ip_hostname(hostname),
        check_excessive_subdomains(hostname),
        check_at_symbol(url),
        check_suspicious_tld(hostname),
        typosquat_signal,
        check_url_shortener(hostname),
        check_suspicious_keywords(url),
        check_non_standard_port(url),
        check_excessive_length(url),
    ]
    score, verdict = combine(signals)
    return Assessment(subject=url, signals=signals, score=score, verdict=verdict)
