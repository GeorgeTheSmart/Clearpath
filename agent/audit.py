"""Append-only, hash-chained audit log (JSON lines).

Each record stores the SHA-256 of the previous record, so editing or deleting
any past line breaks `verify()` from that point on. It is tamper-evident, not
tamper-proof: ship it to write-once storage (S3 Object Lock) in production.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS
        last = self.path.read_text(encoding="utf-8").strip().splitlines()[-1]
        return str(json.loads(last)["hash"])

    def append(self, actor: str, event: str, data: dict[str, Any], ts: float | None = None) -> dict[str, Any]:
        rec = {"ts": ts if ts is not None else time.time(), "actor": actor, "event": event, "data": data, "prev": self._last_hash()}
        rec["hash"] = hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()
        with self.path.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        return rec

    def records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [json.loads(x) for x in self.path.read_text(encoding="utf-8").splitlines() if x.strip()]

    def verify(self) -> tuple[bool, int]:
        """(ok, index of first bad record or -1)."""
        prev = GENESIS
        for i, rec in enumerate(self.records()):
            body = {k: v for k, v in rec.items() if k != "hash"}
            if rec.get("prev") != prev or hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != rec.get("hash"):
                return False, i
            prev = rec["hash"]
        return True, -1
