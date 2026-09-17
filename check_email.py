#!/usr/bin/env python3
"""CLI: assess a text/HTML-ish email file for phishing indicators.

Usage:
    python check_email.py email.txt
    cat email.txt | python check_email.py -
"""

import sys

from phishing_detector.email_heuristics import assess_email_text


def main(argv):
    if len(argv) != 2:
        print("Usage: python check_email.py <path-to-email.txt|->", file=sys.stderr)
        return 2

    path = argv[1]
    if path == "-":
        text = sys.stdin.read()
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()

    assessment = assess_email_text(text)
    print(assessment.format_report())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
