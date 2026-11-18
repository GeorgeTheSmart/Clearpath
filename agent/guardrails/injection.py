"""Prompt-injection filtering for untrusted log text.

Defence in depth - this filter is layer 1 of 3:
  1. this filter quarantines lines that look like instructions to a model;
  2. surviving logs are passed inside a delimited data block that the system
     prompt declares non-executable (agent/prompt.py);
  3. whatever the model says, remediation only runs allow-listed, reversible
     actions after a human approves (agent/remediation.py). So a successful
     injection can at worst mislead a *draft*, never act.

Layer 1 is heuristic and will miss novel phrasings; docs/SECURITY.md reports
its measured detection rate on a red-team set and its false-positive rate on
benign logs, and why layer 3 is what actually bounds the risk.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

# (weight, pattern). Weights are summed over distinct rules; >= THRESHOLD blocks.
# Families: (A) override/role, (B) structure escape, (C) addressed to an
# automated reader, (D) dangerous imperatives, (E) multilingual override.
_RULES: list[tuple[float, re.Pattern[str]]] = [
    # A. override / role hijack
    (3.0, re.compile(r"\b(ignore|disregard|forget|override|discard)\b.{0,40}\b(previous|prior|above|earlier|all|the|everything)\b.{0,40}\b(instructions?|prompts?|rules?|runbooks?|context|guidance|told)\b")),
    (3.0, re.compile(r"\b(you are now|you are no longer|act as|pretend to be|from now on,? you|new (instructions?|task|role)\s*[:\-])")),
    (2.0, re.compile(r"\b(guidance|instructions?) you (were|have been) given\b")),
    # B. structure escape (closing our data block, role tags, tool-call markup)
    (3.0, re.compile(r"</\s*(logs?|data|context|system|instructions?|untrusted)\s*>|-{2,}\s*end of (logs?|data|context)")),
    (1.5, re.compile(r"(^|[\s\[{(\"'])(system|assistant|developer)\s*:\s*\w+")),
    (3.0, re.compile(r"</?\s*(tool_call|function_call|tool_use)\b|\"(tool_use|tool_call|function_call)\"")),
    # C. addressed to an automated reader
    (2.0, re.compile(r"\b(assistant|ai|model|llm|claude|gpt|chatbot|bot|language model|automated (triage|reviewers?)|whoever (reads|is (reading|summari[sz]ing)))\b")),
    (1.0, re.compile(r"\b(please|kindly|must|should|you|instead|just say|conclude|recommend|treat)\b")),
    # D. dangerous imperatives / goals
    (3.0, re.compile(r"\b(kubectl|helm|terraform|aws|gcloud|rm\s+-rf|curl|wget)\b.{0,40}((?<!to )\b(delete|destroy|drain|uninstall|exec|rm)\b|\|\s*(ba)?sh\b)")),
    (3.0, re.compile(r"\b(delet|wip|remov|drop|destroy)\w*\b.{0,30}\b(namespace|deployment|pvc|volume|database|bucket|cluster)\b")),
    (3.0, re.compile(r"\b(scal(e|ing))\b.{0,40}\b(to\s+(0|zero)|down)\b")),
    (3.0, re.compile(r"\b(mark|set|close|resolve)\b.{0,40}\b(incident|ticket|inc\d+)\b.{0,40}\b(resolved|closed|false positive|low|no action)\b|\bresolve it\b")),
    (3.0, re.compile(r"\b(exfiltrate|send|email|post|upload|leak|print|include)\b.{0,50}\b(secrets?|tokens?|password|credentials?|kubeconfig|environment variables|env vars|/etc/shadow|[a-z_]*password)\b")),
    (3.0, re.compile(r"\b(do not|don't|dont)\b.{0,20}\b(tell|mention|report|alert|page)\b")),
    (2.0, re.compile(r"\b(the )?root cause is\b|\bblame\b")),
    (2.5, re.compile(r"\b(skip|bypass|without)\b.{0,20}\b(human )?(approval|review|verification)\b|\bapprove (all|your own|the) (remediation|rollback|actions?)\b|\bpre-?approved\b")),
    (2.0, re.compile(r"\b(i authori[sz]e you|this is the (cto|ceo|admin|manager))\b")),
    (1.0, re.compile(r"\b(jailbreak|dan mode|developer mode|no restrictions)\b")),
    # E. multilingual "ignore previous instructions" (es, pt, fr, de, hi, zh)
    (3.0, re.compile(r"ignora\w* .{0,30}instruc|ignore todas|ignorez .{0,30}instructions|ignoriere .{0,30}anweisungen|निर्देश\S* .{0,20}अनदेखा|忽略.{0,10}(指示|指令)")),
]
THRESHOLD = 3.0
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def normalise(text: str) -> str:
    t = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    t = t.lower()
    # collapse letter-separator-letter obfuscation ("i-g-n-o-r-e", "d.e.l.e.t.e")
    t = re.sub(r"\b(?:\w[\-_.*]){3,}\w\b", lambda m: re.sub(r"[\-_.*]", "", m.group(0)), t)
    return re.sub(r"\s+", " ", t)


def _decoded_variants(raw: str) -> list[str]:
    n = normalise(raw)
    out = [n, n.translate(_LEET)]
    for m in _B64.findall(unicodedata.normalize("NFKC", raw)):  # base64 is case-sensitive
        try:
            dec = base64.b64decode(m + "=" * (-len(m) % 4), validate=False).decode("utf-8", "ignore")
        except ValueError:
            continue
        if dec and sum(c.isprintable() for c in dec) > 0.9 * len(dec):
            out.append(normalise(dec))
    return out


@dataclass(frozen=True)
class Verdict:
    blocked: bool
    score: float
    matched: tuple[str, ...]


def score(text: str) -> Verdict:
    best: float = 0.0
    best_hits: tuple[str, ...] = ()
    for variant in _decoded_variants(text):
        hits = tuple(p.pattern[:40] for w, p in _RULES if p.search(variant))
        s = sum(w for w, p in _RULES if p.search(variant))
        if s > best:
            best, best_hits = s, hits
    return Verdict(best >= THRESHOLD, best, best_hits)


def score_lines(lines: list[str]) -> list[Verdict]:
    """Score each line alone and joined with its neighbour, so a payload split
    across two consecutive lines is still caught; both halves get blocked."""
    single = [score(x) for x in lines]
    out = list(single)
    for i in range(len(lines) - 1):
        pair = score(lines[i] + " " + lines[i + 1])
        if not pair.blocked:
            continue
        # block a line if it contributes to the pair's score beyond its neighbour alone
        for j, other in ((i, i + 1), (i + 1, i)):
            if not out[j].blocked and pair.score > single[other].score:
                out[j] = pair
    return out
