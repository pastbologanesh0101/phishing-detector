"""Shared Signal/Assessment data types used by both detectors."""

from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class Signal:
    """A single heuristic check result.

    name    -- short machine-friendly identifier, e.g. "ip_hostname"
    fired   -- True if the heuristic detected the suspicious pattern
    weight  -- points added to the risk score when fired
    detail  -- human-readable explanation, e.g. "hostname is a bare IP address"
    """

    name: str
    fired: bool
    weight: int
    detail: str


@dataclass
class Assessment:
    """The combined result of running every heuristic on one input."""

    subject: str
    signals: List[Signal] = field(default_factory=list)
    score: int = 0
    verdict: str = "low"

    def fired_signals(self) -> List[Signal]:
        return [s for s in self.signals if s.fired]

    def format_report(self) -> str:
        lines = [
            f"Subject: {self.subject}",
            f"Risk score: {self.score}/100",
            f"Verdict: {self.verdict.upper()} RISK",
            "",
            "Signal breakdown:",
        ]
        for s in self.signals:
            mark = "[FIRED]" if s.fired else "[ ok ] "
            weight_str = f"+{s.weight}" if s.fired else "  0"
            lines.append(f"  {mark} {weight_str:>4}  {s.name}: {s.detail}")
        return "\n".join(lines)
