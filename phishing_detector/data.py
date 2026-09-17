"""Curated reference data used by the heuristic detectors.

Every list here is authored by hand for this project. Nothing is fetched
from a live threat-intel feed, so the tool works fully offline and its
behaviour is fully reproducible/testable.
"""

# --- Suspicious / frequently-abused top level domains ------------------
# These TLDs are cheap or free to register and are disproportionately
# represented in phishing campaigns (per widely reported industry
# observations from Spamhaus/Interisle-style TLD abuse reports). Presence
# of one of these TLDs is only a weak-to-moderate signal on its own -- lots
# of legitimate sites use them too -- so it is weighted accordingly and
# never used as the sole basis for a "high risk" verdict.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",          # Freenom free-domain TLDs
    "xyz", "top", "win", "click", "loan",
    "work", "support", "zip", "review",
    "country", "kim", "men", "party",
    "science", "stream", "bid", "date",
    "download", "racing", "accountant",
}

# --- Known URL-shortener hostnames --------------------------------------
# Shorteners are not inherently malicious, but they obscure the real
# destination of a link, which is exactly the property phishing campaigns
# rely on to bypass a quick visual check. Flagged as a mild signal.
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly",
    "bl.ink", "rb.gy", "tiny.cc", "shorturl.at", "soo.gd", "s.id",
    "v.gd", "qr.ae", "lnkd.in",
}

# --- Popular / commonly-impersonated domains ----------------------------
# Used as the comparison set for typosquat (edit-distance) detection. This
# is a small, hand-authored sample of well-known brands that are frequent
# phishing-impersonation targets, not an exhaustive top-domains list.
POPULAR_DOMAINS = [
    "paypal.com", "google.com", "amazon.com", "apple.com", "microsoft.com",
    "facebook.com", "instagram.com", "netflix.com", "ebay.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com",
    "americanexpress.com", "linkedin.com", "twitter.com", "x.com",
    "dropbox.com", "docusign.com", "irs.gov", "usps.com", "fedex.com",
    "ups.com", "dhl.com", "adobe.com", "spotify.com", "yahoo.com",
    "outlook.com", "hotmail.com", "gmail.com", "icloud.com",
    "coinbase.com", "binance.com", "venmo.com", "zelle.com",
    "steamcommunity.com", "steampowered.com", "github.com", "gitlab.com",
    "walmart.com", "target.com", "costco.com", "bestbuy.com",
    "capitalone.com", "citibank.com", "hsbc.com", "office.com",
]

# --- Suspicious keywords in a URL path/query ----------------------------
# Common in credential-harvesting landing pages. Weak signal on its own
# (lots of legitimate sites have a /login page); mainly useful combined
# with other signals.
SUSPICIOUS_PATH_KEYWORDS = {
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "confirm", "password", "banking", "wallet",
    "unlock", "suspended", "billing", "invoice",
}

# --- Urgency / pressure language in email bodies ------------------------
URGENCY_PHRASES = [
    "act now", "verify your account immediately", "act immediately",
    "your account has been suspended", "account suspended",
    "account will be suspended", "urgent action required",
    "immediate action required", "confirm your identity",
    "unauthorized login attempt", "unusual activity detected",
    "your account will be locked", "your account will be closed",
    "click here immediately", "final notice", "limited time",
    "expires within 24 hours", "expires in 24 hours",
    "avoid suspension", "restore access", "security alert",
    "failure to respond", "before it's too late", "respond immediately",
]

# --- Generic greetings (weak signal: mass phishing rarely personalizes) -
GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear valued customer",
    "dear account holder", "dear member", "dear client",
    "dear sir/madam", "dear sir or madam", "hello customer",
    "dear valued member", "attention customer", "dear valued client",
]

# --- Requests for sensitive information ---------------------------------
SENSITIVE_INFO_KEYWORDS = [
    "password", "social security number", "ssn", "credit card number",
    "credit card", "cvv", "pin number", "bank account number",
    "routing number", "date of birth", "mother's maiden name",
    "security code", "atm pin", "card verification",
]
