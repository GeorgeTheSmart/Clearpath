"""Evidence verification: how hallucination is measured.

An evidence item is *verified* when its `ref` is an ID present in the gathered
context. Additionally, the claim must mention something the referenced item
actually contains (its service or a content word), so citing a real ID for an
unrelated claim is also caught. hallucination_rate = unverified / total.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from agent.context import known_services
from agent.schema import Context, Diagnosis

_WORD = re.compile(r"[a-z][a-z0-9_\-]{3,}")


@dataclass
class Report:
    total: int
    unverified: list[str] = field(default_factory=list)
    unknown_service: bool = False

    @property
    def hallucination_rate(self) -> float:
        return len(self.unverified) / self.total if self.total else 0.0


def verify(diag: Diagnosis, ctx: Context) -> Report:
    items = {i.id: i for i in ctx.items}
    rep = Report(total=len(diag.evidence))
    for ev in diag.evidence:
        it = items.get(ev.ref)
        if it is None:
            rep.unverified.append(ev.ref)
            continue
        claim = ev.claim.lower()
        support = set(_WORD.findall(it.text.lower())) | ({it.service} if it.service else set())
        if not any(w in claim for w in support):
            rep.unverified.append(ev.ref)
    rep.unknown_service = diag.root_cause_service not in known_services()
    return rep
