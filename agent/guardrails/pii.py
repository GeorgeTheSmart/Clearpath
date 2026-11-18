"""PII redaction with validators (no ML dependency, fully testable).

Each detector is a regex plus, where one exists, a validator that removes
look-alikes: card numbers must pass the Luhn checksum, IPv4 octets must be
<= 255. Redactions are replaced by typed placeholders so the LLM still knows
*that* a card was present, and every redaction is recorded for the audit log.

Presidio is the drop-in upgrade (names/addresses need NER); it was not
installable in the build environment, so this module is the tested baseline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


def luhn_ok(digits: str) -> bool:
    ds = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(ds) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(ds)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _ipv4_ok(s: str) -> bool:
    return all(0 <= int(p) <= 255 for p in s.split("."))


@dataclass(frozen=True)
class Redaction:
    kind: str
    start: int
    end: int


_PATTERNS: list[tuple[str, re.Pattern[str], object]] = [
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), None),
    ("CARD", re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), luhn_ok),
    # international with "+", or formatted national (555) 123-4567 / 555-123-4567.
    # Bare digit runs are NOT treated as phones: they are usually order/trace IDs.
    ("PHONE", re.compile(r"(?<![\w.+])\+\d{1,3}[ -]?\d{6,12}(?![\w.])|(?<![\w.])\(?\d{3}\)?[ -]\d{3}[ -]\d{4}(?![\w.])"), None),
    ("IPV4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), _ipv4_ok),
    ("AWS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), None),
    ("BEARER", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*"), None),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), None),
]


def find(text: str) -> list[Redaction]:
    spans: list[Redaction] = []
    for kind, pat, validator in _PATTERNS:
        for m in pat.finditer(text):
            if validator is not None and not validator(m.group(0)):  # type: ignore[operator]
                continue
            spans.append(Redaction(kind, m.start(), m.end()))
    # resolve overlaps: earliest start, then longest
    spans.sort(key=lambda r: (r.start, -(r.end - r.start)))
    out: list[Redaction] = []
    for r in spans:
        if out and r.start < out[-1].end:
            continue
        out.append(r)
    return out


def redact(text: str) -> tuple[str, list[Redaction]]:
    spans = find(text)
    parts, last = [], 0
    for r in spans:
        parts.append(text[last : r.start])
        parts.append(f"<{r.kind}>")
        last = r.end
    parts.append(text[last:])
    return "".join(parts), spans
