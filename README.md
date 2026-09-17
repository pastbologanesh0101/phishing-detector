# Phishing Detection Tool

A small, fully offline, heuristic phishing detector for **URLs** and
**email text**. Pure Python standard library, no external threat-intel
API calls, no network access at all -- every signal is computed locally
from curated, hand-authored reference data that ships with the repo.

This is a defensive/educational security tool in the spirit of the
heuristic warnings built into browsers and mail clients. It does not
crawl or scan third-party sites; it only inspects the URL string or
email text you give it.

## Quick start

```bash
git clone https://github.com/pastbologanesh0101/phishing-detector.git
cd phishing-detector
python3 check_url.py "http://paypa1.com/login/verify"
python3 check_email.py examples/phishing_email.txt
```

No dependencies to install -- everything is standard library.

## Example output

### A typosquatted, credential-harvesting-style URL

```
$ python3 check_url.py "http://paypa1.com/login/verify"
Subject: http://paypa1.com/login/verify
Risk score: 45/100
Verdict: MEDIUM RISK

Signal breakdown:
  [ ok ]     0  ip_hostname: hostname is not a bare IP address
  [ ok ]     0  excessive_subdomains: 0 subdomain label(s) before the base domain
  [ ok ]     0  at_symbol: no '@' obfuscation found in the authority section
  [ ok ]     0  suspicious_tld: TLD '.com' is not on the curated frequently-abused TLD list
  [FIRED]  +30  typosquat: 'paypa1.com' is only 1 edit(s) away from popular domain 'paypal.com' (possible typosquat)
  [ ok ]     0  url_shortener: hostname is not a known URL shortener
  [FIRED]  +15  suspicious_keywords: path/query contains sensitive-sounding keyword(s): login, verify
  [ ok ]     0  non_standard_port: no non-standard port
  [ ok ]     0  excessive_length: URL length 30 is within normal range
```

### A URL combining an `@` obfuscation trick with a raw IP host

```
$ python3 check_url.py "http://paypal.com@192.168.1.1/verify"
Subject: http://paypal.com@192.168.1.1/verify
Risk score: 60/100
Verdict: HIGH RISK

Signal breakdown:
  [FIRED]  +25  ip_hostname: hostname '192.168.1.1' is a bare IP address (no domain name)
  [ ok ]     0  excessive_subdomains: n/a (IP hostname)
  [FIRED]  +20  at_symbol: '@' found before the host -- browsers treat everything before it as discarded userinfo, a classic destination-hiding trick
  [ ok ]     0  suspicious_tld: n/a (IP hostname)
  [ ok ]     0  typosquat: n/a (IP hostname)
  [ ok ]     0  url_shortener: hostname is not a known URL shortener
  [FIRED]  +15  suspicious_keywords: path/query contains sensitive-sounding keyword(s): verify
  [ ok ]     0  non_standard_port: no non-standard port
  [ ok ]     0  excessive_length: URL length 37 is within normal range
```

### A clean, benign URL -- no false-positive flood

```
$ python3 check_url.py "https://www.wikipedia.org/wiki/Python"
Subject: https://www.wikipedia.org/wiki/Python
Risk score: 0/100
Verdict: LOW RISK
```

### A phishing-style email (`examples/phishing_email.txt`)

```
$ python3 check_email.py examples/phishing_email.txt
Subject: email text: Dear Customer,...
Risk score: 100/100
Verdict: HIGH RISK

Signal breakdown:
  [FIRED]  +30  urgency_language: urgency/pressure phrase(s) found: act now, unusual activity detected, verify your account immediately, your account has been suspended
  [FIRED]  +35  mismatched_link: text shows 'www.paypal.com' but link goes to 'evil-phish.ru'
  [FIRED]  +10  generic_greeting: generic greeting found: 'dear customer' (no personalization)
  [FIRED]  +30  sensitive_info_request: requests sensitive info (password) alongside a request/action verb
```

### A clean, benign email (`examples/clean_email.txt`)

```
$ python3 check_email.py examples/clean_email.txt
Subject: email text: Hi Priya,...
Risk score: 0/100
Verdict: LOW RISK
```

## Methodology

Every check below is a pure function that returns a `Signal` (fired
yes/no, a weight, and a human-readable explanation). `phishing_detector/scoring.py`
sums the weights of every fired signal (capped at 100) and maps the total
to a verdict:

| Score range | Verdict |
|---|---|
| 0 - 29 | low |
| 30 - 59 | medium |
| 60 - 100 | high |

Weights were chosen so that **no single weak signal alone reaches "high"**,
but two or three signals firing together do -- matching how real phishing
URLs/emails tend to stack several tells at once rather than exhibit just one.

### URL heuristics (`phishing_detector/url_heuristics.py`)

| Signal | Weight | Rationale |
|---|---|---|
| `ip_hostname` | 25 | Legitimate sites almost always use a domain name; a bare IP address as the host is a strong phishing/malware-hosting tell. |
| `excessive_subdomains` | 15 | `login.secure.account.paypal.verify-info.com` -- piling on subdomains is a common way to make a malicious host *look* like it belongs to the real brand while the actual registrable domain is something else entirely. Flags when there are 3+ subdomain labels before the base domain. |
| `at_symbol` | 20 | `http://paypal.com@evil.com/` -- everything before an unescaped `@` in a URL's authority section is discarded userinfo; browsers actually connect to `evil.com`. Classic destination-hiding trick. |
| `suspicious_tld` | 15 | A small, hand-curated list of TLDs (`.tk`, `.ml`, `.xyz`, `.top`, `.click`, ...) that are cheap/free to register and disproportionately used in abuse campaigns. Weak signal alone -- plenty of legitimate sites use them too. |
| `typosquat` | 30 | Computes Levenshtein (edit) distance between the URL's registrable domain and each of ~44 hand-authored popular/frequently-impersonated domains (`paypal.com`, `google.com`, `bankofamerica.com`, ...). An edit distance of 1-2 (and not an exact match) flags likely brand impersonation, e.g. `paypa1.com` vs `paypal.com`. This is the strongest single signal because it directly detects brand impersonation intent. |
| `url_shortener` | 10 | Known shorteners (`bit.ly`, `tinyurl.com`, `t.co`, ...) aren't malicious by themselves, but they hide the real destination, which is exactly what a phishing link needs. Flagged as a mild "obscures destination" signal, not a verdict on its own. |
| `suspicious_keywords` | 15 | Path/query containing credential-harvesting-flavoured words (`login`, `verify`, `secure`, `account`, `update`, ...). Weak alone (legit sites have `/login` pages too); most useful stacked with other signals. |
| `non_standard_port` | 10 | A URL pointing at a non-standard port (anything but 80/443) is unusual for a consumer-facing brand login page. |
| `excessive_length` | 10 | URLs longer than 75 characters are often padded with encoded junk/tracking parameters to bury the real host visually. |

### Email-text heuristics (`phishing_detector/email_heuristics.py`)

| Signal | Weight | Rationale |
|---|---|---|
| `urgency_language` | up to 30 (10 per matched phrase, capped) | A curated list of pressure/urgency phrases (`act now`, `your account has been suspended`, `verify your account immediately`, `security alert`, ...). Phishing relies on rushing the reader past careful thought. |
| `mismatched_link` | 35 | Parses `<a href="X">Y</a>`-style anchors; if the visible text `Y` contains a domain-looking string that differs from the actual `href` destination `X`, that's a direct, hard-to-fake tell that the link's advertised destination is a lie. Highest weight of all email signals for that reason. |
| `generic_greeting` | 10 | "Dear Customer" / "Dear Valued Member" instead of a real name. Weak signal by design -- mass phishing rarely personalizes, but plenty of legitimate transactional email doesn't either. |
| `sensitive_info_request` | 30 | Fires when the text mentions a sensitive-data keyword (`password`, `social security number`, `credit card`, `cvv`, ...) **together with** a request/action verb (`enter`, `provide`, `confirm`, `submit`, ...) -- i.e. it's actually asking the reader to hand something over, not just mentioning the word in passing. |

### Typosquat detection in detail

`phishing_detector/utils.py` implements a small, dependency-free
Levenshtein edit-distance function. `check_typosquat()`:

1. Extracts the URL's best-effort registrable domain (last two
   dot-separated labels -- a documented simplification; it is not fully
   public-suffix-list aware, so multi-part TLDs like `co.uk` are not
   handled perfectly).
2. Compares it against every domain in `phishing_detector/data.py`'s
   `POPULAR_DOMAINS` list (~44 hand-authored, commonly-impersonated
   brands).
3. An **exact match** means the URL genuinely is that popular domain --
   not flagged.
4. An edit distance of **1 or 2** characters away from a popular domain
   (and length within 2 characters, as a cheap pre-filter) is flagged as
   a likely typosquat, and names the domain it appears to be impersonating.
5. Anything further away is left alone -- this keeps the false-positive
   rate low for domains that just happen to share a few letters with a
   popular brand.

### Known limitations (by design, for an offline heuristic tool)

- Registrable-domain extraction is "last two labels", not a full public
  suffix list -- `example.co.uk` is treated as domain `co.uk`. Acceptable
  for a lightweight local tool; documented here rather than hidden.
- `mismatched_link` detection uses a regex, not an HTML parser -- fine for
  the simple single-anchor phishing patterns it targets, but not a
  general-purpose HTML sanitizer.
- All heuristics are inherently probabilistic signals, not proof. This
  tool is meant to flag things for a human (or another layer of defense)
  to review, not to make final trust/block decisions unattended.

## Running the tests

```bash
python3 -m unittest discover -s tests -v
# or, if pytest is installed:
python3 -m pytest -v
```

26 unit tests cover every individual heuristic (fires on the bad case,
stays quiet on the clean case) plus combined-scoring tests that verify
the verdict escalates low -> medium -> high as more signals fire, and that
a clean/benign URL and email each produce a `LOW RISK` verdict with zero
fired signals.

Continuous integration (`.github/workflows/tests.yml`) runs the same
suite on every push/PR against Python 3.11 and 3.12.

## Project layout

```
phishing-detector/
  check_url.py              CLI: assess a single URL
  check_email.py            CLI: assess an email text/HTML file
  phishing_detector/
    data.py                 curated TLD/shortener/popular-domain/phrase lists
    utils.py                Levenshtein edit-distance implementation
    signals.py               Signal / Assessment data types + report formatting
    scoring.py               weight-sum -> verdict thresholding
    url_heuristics.py        the 9 URL checks
    email_heuristics.py      the 4 email-text checks
  tests/                     26 unit tests (unittest, stdlib only)
  examples/                  sample clean + phishing email files
  .github/workflows/tests.yml
```

## License

MIT -- see [LICENSE](LICENSE).
