"""Combine individual Signals into a final score + verdict.

Score = sum of weights of every fired signal, capped at 100.

Verdict thresholds (documented in README "Scoring" section):
    score <  30            -> "low"
    30 <= score < 60        -> "medium"
    score >= 60              -> "high"
"""

from typing import List, Tuple

from .signals import Signal

LOW_MEDIUM_THRESHOLD = 30
MEDIUM_HIGH_THRESHOLD = 60


def combine(signals: List[Signal]) -> Tuple[int, str]:
    raw_score = sum(s.weight for s in signals if s.fired)
    score = min(raw_score, 100)

    if score >= MEDIUM_HIGH_THRESHOLD:
        verdict = "high"
    elif score >= LOW_MEDIUM_THRESHOLD:
        verdict = "medium"
    else:
        verdict = "low"
    return score, verdict
