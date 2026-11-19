"""Local stand-in for a ServiceNow Personal Developer Instance (Table API subset).

Implements GET/POST/PATCH on /api/now/table/<table>[/<sys_id>] with
sysparm_query (field=value joined by ^ for AND and ^OR for OR) and
sysparm_limit, HTTP Basic auth, and the response envelope {"result": ...}.
Seeded with the Online Boutique services as cmdb_ci_service CIs and
"Depends on::Used by" cmdb_rel_ci relationships. Stdlib only.

    python -m mock_servicenow.server --port 8090
"""

from __future__ import annotations

import argparse
import base64
import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from faults import topology as topo

USER, PASSWORD = "admin", "admin"


class Store:
    def __init__(self) -> None:
        self.tables: dict[str, dict[str, dict[str, Any]]] = {}
        self.lock = threading.Lock()
        self.counter = 10000
        self._seed()

    def _seed(self) -> None:
        ids = {}
        for s in topo.SERVICES:
            r = self.insert(
                "cmdb_ci_service",
                {
                    "name": s,
                    "operational_status": "1",
                    # sic: ServiceNow's real column name is misspelled; do not "fix" it
                    "busines_criticality": "1 - most critical" if s in ("frontend", "checkoutservice", "paymentservice") else "3 - less critical",
                },
            )
            ids[s] = r["sys_id"]
        for c, d in topo.edges():
            self.insert("cmdb_rel_ci", {"parent": ids[c], "child": ids[d], "type": "Depends on::Used by"})

    def insert(self, table: str, rec: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            rec = {**rec, "sys_id": uuid.uuid4().hex}
            if table == "incident":
                self.counter += 1
                rec.setdefault("number", f"INC{self.counter:07d}")
                rec.setdefault("state", "1")
            self.tables.setdefault(table, {})[rec["sys_id"]] = rec
            return rec

    def query(self, table: str, q: str, limit: int) -> list[dict[str, Any]]:
        rows = list(self.tables.get(table, {}).values())
        if q:
            ors = [clause.split("^") for clause in q.split("^OR")]

            def match(r: dict[str, Any]) -> bool:
                return any(all(r.get(k) == v for k, _, v in (t.partition("=") for t in conj if t)) for conj in ors)

            rows = [r for r in rows if match(r)]
        return rows[:limit]


STORE = Store()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: Any) -> None:  # quiet
        pass

    def _auth(self) -> bool:
        h = self.headers.get("Authorization", "")
        ok = h == "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
        if not ok:
            self._send(401, {"error": {"message": "User Not Authenticated"}})
        return ok

    def _send(self, code: int, body: Any) -> None:
        b = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _parts(self) -> tuple[str, str | None, dict[str, list[str]]] | None:
        u = urlparse(self.path)
        p = u.path.strip("/").split("/")
        if len(p) < 4 or p[:3] != ["api", "now", "table"]:
            self._send(404, {"error": {"message": "Invalid table"}})
            return None
        return p[3], (p[4] if len(p) > 4 else None), parse_qs(u.query)

    def do_GET(self) -> None:  # noqa: N802
        if not self._auth() or (parts := self._parts()) is None:
            return
        table, sid, qs = parts
        if sid:
            r = STORE.tables.get(table, {}).get(sid)
            self._send(200, {"result": r}) if r else self._send(404, {"error": {"message": "No Record found"}})
            return
        rows = STORE.query(table, qs.get("sysparm_query", [""])[0], int(qs.get("sysparm_limit", ["1000"])[0]))
        self._send(200, {"result": rows})

    def do_POST(self) -> None:  # noqa: N802
        if not self._auth() or (parts := self._parts()) is None:
            return
        table, _, _ = parts
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        self._send(201, {"result": STORE.insert(table, body)})

    def do_PATCH(self) -> None:  # noqa: N802
        if not self._auth() or (parts := self._parts()) is None:
            return
        table, sid, _ = parts
        rec = STORE.tables.get(table, {}).get(sid or "")
        if rec is None:
            self._send(404, {"error": {"message": "No Record found"}})
            return
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        with STORE.lock:
            rec.update(body)
        self._send(200, {"result": rec})


def serve(port: int = 8090) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8090)
    a = ap.parse_args()
    print(f"mock ServiceNow on http://127.0.0.1:{a.port} (admin/admin)")
    ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()
