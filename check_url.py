#!/usr/bin/env python3
"""CLI: assess a single URL for phishing indicators.

Usage:
    python check_url.py "http://paypa1.com/login/verify"
"""

import sys

from phishing_detector.url_heuristics import assess_url


def main(argv):
    if len(argv) != 2:
        print("Usage: python check_url.py <url>", file=sys.stderr)
        return 2
    assessment = assess_url(argv[1])
    print(assessment.format_report())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
