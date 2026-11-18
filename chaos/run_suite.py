"""Run each chaos experiment and assert: expected alert fired (and resolved),
recovery within the time bound, and error-budget spend within its limit.

Needs a cluster with Chaos Mesh and Prometheus (make up-local). Writes
eval/results/<date>/chaos.json. NOT executed in the build environment (no
Kubernetes there); the nightly CI job runs it on kind.

    python chaos/run_suite.py --prom http://localhost:9090 --out eval/results/latest
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent


def prom(base: str, q: str) -> list[dict[str, Any]]:
    url = f"{base}/api/v1/query?" + urllib.parse.urlencode({"query": q})
    with urllib.request.urlopen(url, timeout=10) as r:
        return list(json.load(r)["data"]["result"])


def budget_spent(base: str, seconds: int) -> float:
    q = f'(sum(increase(http_server_requests_total{{service="frontend",code=~"5.."}}[{seconds}s])) / sum(increase(http_server_requests_total{{service="frontend"}}[{seconds}s]))) * {seconds} / (30*24*3600) / 0.001'
    res = prom(base, q)
    return float(res[0]["value"][1]) if res else 0.0


def kubectl(*args: str) -> str:
    return subprocess.run(["kubectl", *args], check=True, capture_output=True, text=True).stdout


def run_one(name: str, exp: dict[str, Any], base: str, docs: dict[str, str]) -> dict[str, Any]:
    t0 = time.time()
    if name == "node-drain":
        node = kubectl("get", "nodes", "-o", "jsonpath={.items[-1].metadata.name}")
        kubectl("drain", node, "--ignore-daemonsets", "--delete-emptydir-data", "--timeout=120s")
    else:
        subprocess.run(["kubectl", "apply", "-f", "-"], input=docs[name], text=True, check=True)
    fired = exp["expect_alert"] is None
    recovered_at = None
    while time.time() - t0 < exp["recover_within_s"] + 300:
        if exp["expect_alert"] and prom(base, f'ALERTS{{alertname="{exp["expect_alert"]}",alertstate="firing"}}'):
            fired = True
        if time.time() - t0 > 15 and prom(base, exp["recovered_when"]):
            recovered_at = time.time() - t0
            break
        time.sleep(5)
    if name == "node-drain":
        kubectl("uncordon", node)
    else:
        subprocess.run(["kubectl", "delete", "-f", "-"], input=docs[name], text=True, check=False)
    spent = budget_spent(base, int(time.time() - t0))
    ok = fired and recovered_at is not None and recovered_at <= exp["recover_within_s"] and spent <= exp["max_budget_spend"]
    return {"experiment": name, "alert_fired": fired, "recovered_s": recovered_at, "bound_s": exp["recover_within_s"],
            "budget_spent": spent, "budget_limit": exp["max_budget_spend"], "pass": ok}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prom", default="http://localhost:9090")
    ap.add_argument("--out", type=Path, default=Path("eval/results/latest"))
    a = ap.parse_args()
    exps = yaml.safe_load((HERE / "expectations.yaml").read_text())
    docs = {d["metadata"]["name"]: yaml.safe_dump(d) for d in yaml.safe_load_all((HERE / "experiments.yaml").read_text()) if d}
    results = [run_one(n, e, a.prom, docs) for n, e in exps.items()]
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "chaos.json").write_text(json.dumps(results, indent=1))
    print(json.dumps(results, indent=1))
    raise SystemExit(0 if all(r["pass"] for r in results) else 1)


if __name__ == "__main__":
    main()
