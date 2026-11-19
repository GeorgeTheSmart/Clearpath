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


def prom(base: str, q: str, attempts: int = 6) -> list[dict[str, Any]]:
    """Instant query, retried: a fault can briefly disturb the path to Prometheus."""
    url = f"{base}/api/v1/query?" + urllib.parse.urlencode({"query": q})
    for i in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                return list(json.load(r)["data"]["result"])
        except (OSError, json.JSONDecodeError):  # URLError, connection reset/aborted, timeout
            if i == attempts - 1:
                raise
            time.sleep(min(10, 2**i))
    raise AssertionError("unreachable")


FRONTEND_IN = 'namespace="boutique",service="frontend",direction="inbound"'  # Linkerd proxy SLI, as in slo-rules.yaml


SCRAPE_LAG_S = 60  # failures surface up to a scrape interval + rule eval late


def budget_spent(base: str, seconds: int) -> float:
    """Fraction of the 30-day availability budget (0.1% of requests) the experiment spent.

        failed requests during the experiment / (0.001 x baseline req/s x 30 d)

    The budget is sized from the last hour's traffic, not the experiment
    window: a short window (a pod kill that heals in 20 s) holds too few
    scrapes for a reliable rate, and replacement pods start new series.
    """
    w = seconds + SCRAPE_LAG_S
    failed = prom(base, f'sum(increase(response_total{{{FRONTEND_IN},classification="failure"}}[{w}s])) or vector(0)')
    rps = prom(base, f"sum(rate(response_total{{{FRONTEND_IN}}}[1h]))")
    if not rps or float(rps[0]["value"][1]) <= 0:
        # No request data at all. Reporting 0 spent here would let every
        # experiment pass its budget check without measuring anything.
        raise RuntimeError("no frontend request metrics in Prometheus (is the Linkerd PodMonitor applied?)")
    return float(failed[0]["value"][1]) / (0.001 * float(rps[0]["value"][1]) * 30 * 24 * 3600)


def kubectl(*args: str) -> str:
    return subprocess.run(["kubectl", *args], check=True, capture_output=True, text=True).stdout


OBSERVE_AFTER_S = 90  # alerts with `for: 1m` can fire after a fast recovery
QUIET_TIMEOUT_S = 900  # fast burn (5m window) and symptom alerts clear within minutes


def firing(base: str) -> set[tuple[str, str, str]]:
    """(alertname, service, severity) of Clearpath alerts firing now."""
    res = prom(base, 'ALERTS{clearpath="true",alertstate="firing"}')
    return {(r["metric"]["alertname"], r["metric"].get("service", ""), r["metric"].get("severity", "")) for r in res}


def long_lived(alert: tuple[str, str, str]) -> bool:
    """Slow-burn pages (30m short window) and tickets (6h/3d) are designed to
    stay active long after any error burst; they are not 'noise' to wait out."""
    return alert[2] == "ticket" or "BurnSlow" in alert[0]


def wait_quiet(base: str) -> float:
    """Block until no fast-signal alert fires, so experiments don't inherit
    each other's alerts. Long-lived alerts are handled by counting only alerts
    that START during an experiment (see run_one)."""

    def loud() -> set[tuple[str, str, str]]:
        return {a for a in firing(base) if not long_lived(a)}

    t0 = time.time()
    while loud():
        if time.time() - t0 > QUIET_TIMEOUT_S:
            raise RuntimeError(f"alerts still firing after {QUIET_TIMEOUT_S}s: {sorted(loud())}")
        time.sleep(10)
    return time.time() - t0


def drain_target() -> str:
    """A worker that does not host Prometheus. Never the control plane (draining
    it stalls a kind cluster), and never the node running the measurement: an
    earlier run drained Prometheus's own node and lost its connection and data."""
    workers = kubectl("get", "nodes", "-l", "!node-role.kubernetes.io/control-plane", "-o", "jsonpath={.items[*].metadata.name}").split()
    prom_nodes = set(kubectl("get", "pods", "-n", "monitoring", "-l", "app.kubernetes.io/name=prometheus", "-o", "jsonpath={.items[*].spec.nodeName}").split())
    candidates = [n for n in workers if n not in prom_nodes]
    if not candidates:
        raise RuntimeError(f"no worker without Prometheus to drain (workers {workers}, prometheus on {sorted(prom_nodes)})")
    return candidates[-1]


def run_one(name: str, exp: dict[str, Any], base: str, docs: dict[str, str]) -> dict[str, Any]:
    quiet_s = wait_quiet(base)
    before = firing(base)  # already active (long-lived): not caused by this experiment
    t0 = time.time()
    node = None
    seen: set[tuple[str, str, str]] = set()
    recovered_at = None
    try:
        if name == "node-drain":
            node = drain_target()
            kubectl("drain", node, "--ignore-daemonsets", "--delete-emptydir-data", "--timeout=120s")
        else:
            subprocess.run(["kubectl", "apply", "-f", "-"], input=docs[name], text=True, check=True)
        while time.time() - t0 < exp["recover_within_s"] + 300:
            seen |= firing(base)
            if time.time() - t0 > 15 and prom(base, exp["recovered_when"]):
                recovered_at = time.time() - t0
                break
            time.sleep(5)
    finally:
        # always undo the fault, even if Prometheus or kubectl raised mid-experiment
        if node:
            kubectl("uncordon", node)
        elif name != "node-drain":
            subprocess.run(["kubectl", "delete", "-f", "-", "--ignore-not-found"], input=docs[name], text=True, check=False)
    t_obs = time.time()
    while time.time() - t_obs < OBSERVE_AFTER_S:
        seen |= firing(base)
        time.sleep(5)
    spent = budget_spent(base, int(t_obs - t0))
    new = seen - before  # attributable to this experiment
    names = {a for a, _, _ in new}
    pages = sorted({f"{a}/{s}" for a, s, sev in new if sev == "page"})
    if exp["expect_alert"]:
        alert_ok = exp["expect_alert"] in names
    else:  # the claim is "absorbed without paging anyone"
        alert_ok = not pages
    ok = alert_ok and recovered_at is not None and recovered_at <= exp["recover_within_s"] and spent <= exp["max_budget_spend"]
    return {
        "experiment": name,
        "expected_alert": exp["expect_alert"],
        "alert_ok": alert_ok,
        "alerts_new": sorted(f"{a}/{s}" for a, s, _ in new),
        "already_active": sorted(f"{a}/{s}" for a, s, _ in before),
        "pages": pages,
        "recovered_s": None if recovered_at is None else round(recovered_at, 1),
        "bound_s": exp["recover_within_s"],
        "budget_spent": round(spent, 6),
        "budget_limit": exp["max_budget_spend"],
        "waited_for_quiet_s": round(quiet_s),
        "pass": ok,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prom", default="http://localhost:9090")
    ap.add_argument("--out", type=Path, default=Path("eval/results/latest"))
    a = ap.parse_args()
    exps = yaml.safe_load((HERE / "expectations.yaml").read_text(encoding="utf-8"))
    docs = {d["metadata"]["name"]: yaml.safe_dump(d) for d in yaml.safe_load_all((HERE / "experiments.yaml").read_text(encoding="utf-8")) if d}
    a.out.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for n, e in exps.items():
        try:
            r = run_one(n, e, a.prom, docs)
        except Exception as ex:  # one broken experiment must not discard the others' results
            r = {"experiment": n, "pass": False, "error": f"{type(ex).__name__}: {ex}"[:300]}
        results.append(r)
        print(json.dumps(r), flush=True)
        # written after every experiment: a crash late in a 30-min run keeps what was measured
        (a.out / "chaos.json").write_text(json.dumps(results, indent=1), encoding="utf-8", newline="\n")
    raise SystemExit(0 if all(r["pass"] for r in results) else 1)


if __name__ == "__main__":
    main()
