"""Render eval/results/<dir>/report.md and the README results block from JSON.

Nothing here computes a metric: it only formats numbers already written by
detect/evaluate.py, localize/evaluate.py, eval/harness.py and the Go bench.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent


def pct(d: dict[str, float] | None, digits: int = 1) -> str:
    if not d:
        return "n/a"
    return f"{100 * d['estimate']:.{digits}f}% [{100 * d['ci95_lo']:.{digits}f}, {100 * d['ci95_hi']:.{digits}f}]"


def num(d: dict[str, float] | None, digits: int = 2) -> str:
    if not d:
        return "n/a"
    return f"{d['estimate']:.{digits}f} [{d['ci95_lo']:.{digits}f}, {d['ci95_hi']:.{digits}f}]"


def p(x: float) -> str:
    return f"{x:.1e}" if x < 1e-3 else f"{x:.3f}"


def headline(m: dict[str, Any], loc: dict[str, Any], det: dict[str, Any]) -> dict[str, str]:
    return {
        "rca_top1": pct(loc["methods"]["ppr_full"]["top1"]),
        "rca_top1_baseline": pct(loc["methods"]["most_alerting"]["top1"]),
        "root_detect": pct(det["detectors"]["seasonal_robust_z"]["root_recall_10min"]),
        "root_detect_static": pct(det["detectors"]["static_as_deployed"]["root_recall_10min"]),
        "ttt_ms": f"{m['time_to_ticket']['median_ms']['estimate']:.0f} ms",
    }


def build(d: Path) -> str:
    m = json.loads((d / "metrics.json").read_text(encoding="utf-8"))
    det = json.loads((d / "detection.json").read_text(encoding="utf-8"))
    loc = json.loads((d / "localization.json").read_text(encoding="utf-8"))
    bench_p = ROOT / "eval/results/bench_correlator.json"
    bench = json.loads(bench_p.read_text(encoding="utf-8")) if bench_p.exists() else None
    L: list[str] = []
    w = L.append
    w(
        f"# Clearpath evaluation report\n\nGenerated {m['generated_at']} from `{d}`. Dataset: {m['dataset']['test_incidents']} held-out TEST incidents "
        f"({m['dataset']['source']}, generator v{m['dataset']['generator_version']}). Brackets are 95% bootstrap CIs (10,000 resamples over incidents).\n"
    )

    w(f"## 1. Detection (equal false-alarm budget: {det['protocol']['budget_pages_per_day']:.0f} pages/day fleet-wide)\n")
    w("| Detector | FP/day (test week) | Root service detected ≤10 min | Any alarm ≤10 min | Median delay (min) | p90 delay |")
    w("|---|---|---|---|---|---|")
    for name, r in det["detectors"].items():
        w(
            f"| {name} | {r['fp_per_day_test_week']:.2f} | {pct(r['root_recall_10min'])} | {pct(r['recall_10min'])} | "
            f"{num(r['delay_median_min'], 1) if r['delay_median_min'] else 'n/a'} | {r['delay_p90_min'] if r['delay_p90_min'] is not None else 'n/a'} |"
        )
    w("\nPaired vs calibrated static thresholds (root detected ≤10 min, exact McNemar, Holm-adjusted):\n")
    w("| Detector | Δ (pp) [95% CI] | wins/losses | p (Holm) |\n|---|---|---|---|")
    for name, c in det["paired_root_recall_vs_static_calibrated"].items():
        w(
            f"| {name} | {100 * c['diff']:+.1f} [{100 * c['diff_ci95_lo']:+.1f}, {100 * c['diff_ci95_hi']:+.1f}] | {c['b_only']}/{c['a_only']} | {p(c['p_holm'])} |"
        )

    w("\n## 2. Root-cause localization\n")
    w(f"Parameters tuned on DEV only: `{loc['chosen_params']}`.\n")
    w("| Method | Top-1 | Top-3 | Mean rank |\n|---|---|---|---|")
    for name, r in loc["methods"].items():
        w(f"| {name} | {pct(r['top1'])} | {pct(r['top3'])} | {num(r['mean_rank'])} |")
    w("\n| Comparison (PPR minus baseline) | Δ (pp) [95% CI] | wins/losses | p (Holm) |\n|---|---|---|---|")
    for k, c in loc["paired"].items():
        w(f"| {k} | {100 * c['diff']:+.1f} [{100 * c['diff_ci95_lo']:+.1f}, {100 * c['diff_ci95_hi']:+.1f}] | {c['b_only']}/{c['a_only']} | {p(c['p_holm'])} |")
    w("\nRobustness (TEST, no retuning), top-1:\n")
    w("| Perturbation | most_anomalous | downstream_most_anomalous | ppr_full | ppr no corr | PPR − downstream (pp) |\n|---|---|---|---|---|---|")
    for kind, rr in loc["robustness"].items():
        c = rr["ppr_vs_downstream_top1"]
        w(
            f"| {kind} | {pct(rr['most_anomalous']['top1'])} | {pct(rr['downstream_most_anomalous']['top1'])} | {pct(rr['ppr_full']['top1'])} | "
            f"{pct(rr['ablate_no_corr']['top1'])} | {100 * c['diff']:+.1f} [{100 * c['diff_ci95_lo']:+.1f}, {100 * c['diff_ci95_hi']:+.1f}], p={p(c['p_mcnemar_exact'])} |"
        )

    w("\n## 3. End-to-end systems\n")
    w("| System | n | Root top-1 | Fault-type acc. | Hallucination rate | LLM output unusable (fell back) |\n|---|---|---|---|---|---|")
    for name, r in m["systems"].items():
        if "status" in r:
            w(f"| {name} | | {r['status']} | | | |")
        else:
            fb = f"{100 * r['fallback_rate']:.1f}%" if "fallback_rate" in r else ""
            w(f"| {name} | {r['n']} | {pct(r['root_top1'])} | {pct(r['fault_type_acc'])} | {pct(r.get('hallucination_rate'))} | {fb} |")
    llm = m["cost_per_incident"]["llm"]
    if isinstance(llm, dict) and "e_full" in llm:
        e = llm["e_full"]
        w(
            f"\nLLM: `{e['model']}` via {e['provider']}, first {e['incidents']} TEST incidents, temperature 0. LLM systems are compared with b+ on those same incidents below."
        )
    w("\n| Paired comparison | Δ (pp) [95% CI] | wins/losses | p (exact McNemar) |\n|---|---|---|---|")
    for k, c in m["paired"].items():
        w(
            f"| {k} | {100 * c['diff']:+.1f} [{100 * c['diff_ci95_lo']:+.1f}, {100 * c['diff_ci95_hi']:+.1f}] | {c['b_only']}/{c['a_only']} | {p(c['p_mcnemar_exact'])} |"
        )
    w("\nRunbook retrieval (query = sanitized context of the top suspect):\n")
    w("| Mode | Recall@1 | Recall@3 |\n|---|---|---|")
    for mode in ("bm25", "dense", "hybrid"):
        r = m["retrieval"][mode]
        w(f"| {mode} | {pct(r['recall_at_1'])} | {pct(r['recall_at_3'])} |")

    g = m["guardrails"]
    w("\n## 4. Guardrails\n")
    w(
        f"* PII: {g['pii_planted']} planted values in TEST logs; leak rate after redaction **{100 * g['pii_leak_rate']:.2f}%** "
        f"(by kind: {', '.join(f'{k} {100 * v:.1f}%' for k, v in g['pii_leak_by_kind'].items())}); over-redaction on PII-free lines {100 * g['pii_over_redaction_rate']:.2f}%."
    )
    w(
        f"* Simulator-injected adversarial log lines quarantined: {100 * (g['sim_injection_quarantine_rate'] or 0):.1f}% of {g['sim_injection_lines']}; "
        f"benign lines falsely quarantined: {100 * g['benign_false_quarantine_rate']:.3f}% of {g['benign_log_lines']}."
    )
    rt = m["redteam"]
    w("\n| Red-team set | Attacks | Filter block rate | Hard negatives falsely blocked |\n|---|---|---|---|")
    for k in ("payloads", "payloads_heldout"):
        r = rt[k]
        w(f"| {k} | {r['attacks']} | {pct(r['filter_block_rate'])} | {100 * r['hard_negative_false_block_rate']:.1f}% of {r['hard_negatives']} |")
    fz = rt["action_policy_fuzz"]
    w(f"\nAction policy fuzz: {fz['out_of_policy_accepted']} of {fz['cases']:,} random action proposals outside the policy were accepted.")
    ras = m["cost_per_incident"]["llm"].get("redteam_attack_success") if isinstance(m["cost_per_incident"]["llm"], dict) else None
    if ras:
        w(
            "\nEnd to end against the LLM: each held-out attack planted as a log line on the root service; an attack succeeds if the "
            "diagnosis changes its root cause or proposes an out-of-policy action, vs the same incident without the payload.\n"
        )
        w("| Pipeline | Attack success rate [95% CI] |\n|---|---|")
        for k in ("without_guardrails", "with_guardrails"):
            w(f"| {k.replace('_', ' ')} | {pct(ras[k])} |")
        w(
            "\nOut-of-policy actions are also rejected at execution regardless (fuzz result above), so a successful injection can mislead the diagnosis but not act.\n"
        )
    else:
        w("End-to-end attack success rate with/without guardrails needs an LLM: **not run** (no LLM configured).\n")

    t = m["time_to_ticket"]
    w("## 5. Time to ticket and cost\n")
    w(
        f"* Scope: {t['scope']}.\n* Median {num(t['median_ms'], 1)} ms, p95 {t['p95_ms']:.1f} ms. Per-node medians (ms): "
        + ", ".join(f"{k} {v:.2f}" for k, v in t["per_node_median_ms"].items())
        + "."
    )
    w(f"* Cost per incident: no-LLM path {m['cost_per_incident']['no_llm_path']}.")
    if isinstance(llm, dict) and any(k.startswith(("c_", "d_", "e_")) for k in llm):
        w("\n| LLM system | Input tokens / incident | Output tokens / incident | LLM wall time / incident (s) |\n|---|---|---|---|")
        for k, v in llm.items():
            if k.startswith(("c_", "d_", "e_")):
                w(f"| {k} | {v['input_tokens_per_incident']:,.0f} | {v['output_tokens_per_incident']:,.0f} | {v['llm_wall_s_per_incident']:.1f} |")
        w("\nLocal open-weights model: no per-token price; wall time is on one consumer GPU (see the model line above).\n")
    else:
        w("* LLM: not run.\n")

    if bench:
        w(f"## 6. Correlator benchmark ({bench['go']}, {bench['cpus']} CPUs, window {bench['window']}, lateness {bench['lateness']})\n")
        w(
            "| Scenario | Alerts | Throughput (alerts/s) | p50 / p99 / p99.9 (µs) | Peak heap (MB)* | Incidents | Largest incident share | Conserved |\n|---|---|---|---|---|---|---|---|"
        )
        for r in bench["results"]:
            w(
                f"| {r['scenario']} | {r['alerts']:,} | {r['throughput_alerts_per_sec']:,.0f} | {r['p50_us']:.2f} / {r['p99_us']:.2f} / {r['p999_us']:.1f} | "
                f"{r['peak_heap_mb']:.0f} | {r['incidents']} | {r['largest_incident_share_of_alerts']:.3f} | {r['total_conserved']} |"
            )
        w("\n*Heap in use above the pre-loaded input, sampled every 20k alerts; includes not-yet-collected garbage, so it is an upper bound.")
        h = bench["results"][0].get("http_alerts_per_sec")
        if h:
            w(f"HTTP webhook path (batches of {bench['results'][0]['http_batch_size']}, localhost): {h:,.0f} alerts/s.")
        w("\nPercolation: predicted critical background noise (alerts/service/hour) vs observed — see docs/DESIGN.md#percolation.\n")
        w("| Cross window | Predicted ν_c | ν where largest incident > 50% of alerts |\n|---|---|---|")
        for wc in (300, 60):
            rows = [r for r in bench["results"] if r["scenario"].startswith("noise_sweep") and int(r["cross_window_s"]) == wc]
            if rows:
                crit = next((r["noise_alerts_per_service_per_hour"] for r in rows if r["largest_incident_share_of_alerts"] > 0.5), None)
                prev = max(
                    (r["noise_alerts_per_service_per_hour"] for r in rows if crit is not None and r["noise_alerts_per_service_per_hour"] < crit), default=None
                )
                w(f"| {wc} s | {rows[0]['predicted_critical_noise_per_service_hour']:.1f} | between {prev} and {crit} |")
    return "\n".join(L) + "\n"


def readme_block(d: Path) -> str:
    m = json.loads((d / "metrics.json").read_text(encoding="utf-8"))
    det = json.loads((d / "detection.json").read_text(encoding="utf-8"))
    loc = json.loads((d / "localization.json").read_text(encoding="utf-8"))
    h = headline(m, loc, det)
    rel = (d.resolve().relative_to(ROOT) if d.is_absolute() else d).as_posix()  # README links are URLs: always '/'
    rows = [
        ("Root cause ranked #1 (graph RCA)", h["rca_top1"], f"most-alerting baseline {h['rca_top1_baseline']}", f"{rel}/localization.json"),
        ("Root service detected ≤10 min at 3 pages/day", h["root_detect"], f"static rules as deployed {h['root_detect_static']}", f"{rel}/detection.json"),
        (
            "Fault type correct (localizer + RAG, no LLM)",
            pct(m["systems"]["b_plus_localizer_rag_no_llm"]["fault_type_acc"]),
            f"alert-name retrieval only {pct(m['systems']['b_localizer']['fault_type_acc'])}",
            f"{rel}/metrics.json",
        ),
        ("PII leak rate after redaction", f"{100 * m['guardrails']['pii_leak_rate']:.2f}% of {m['guardrails']['pii_planted']}", "", f"{rel}/metrics.json"),
        ("Pipeline time to ticket (median, no LLM)", h["ttt_ms"], "excl. detection + correlation window", f"{rel}/metrics.json"),
    ]
    e = m["systems"].get("e_full", {})
    if "fault_type_acc" in e:
        llm = m["cost_per_incident"]["llm"]["e_full"]
        rows.append(
            (
                f"Fault type correct, full system with LLM (`{llm['model']}`, n={e['n']})",
                pct(e["fault_type_acc"]),
                f"hallucinated evidence {pct(e['hallucination_rate'])}; {llm['llm_wall_s_per_incident']:.0f} s/incident on one GPU",
                f"{rel}/metrics.json",
            )
        )
    else:
        rows.append(("LLM rows (c)-(e), hallucination rate, $/incident", "not run here", "needs CLEARPATH_LLM", f"{rel}/metrics.json"))
    out = ["| Metric (300 held-out simulated incidents, 95% CI) | Result | Comparison | Source |", "|---|---|---|---|"]
    out += [f"| {a} | {b} | {c} | [{e.split('/')[-1]}]({e}) |" for a, b, c, e in rows]
    return "\n".join(out)


def write_report(d: Path) -> None:
    (d / "report.md").write_text(build(d), encoding="utf-8", newline="\n")
    readme = ROOT / "README.md"
    if not d.resolve().is_relative_to(ROOT):
        # The README links to committed results; a run elsewhere (scratch, CI
        # artefact dir) must not repoint them at files outside the repo.
        print(f"report: {d} is outside the repo; README table left unchanged")
        return
    if readme.exists():
        txt = readme.read_text(encoding="utf-8")
        block = "<!-- RESULTS:START (generated by eval/report.py; do not edit) -->\n" + readme_block(d) + "\n<!-- RESULTS:END -->"
        txt = re.sub(r"<!-- RESULTS:START.*?<!-- RESULTS:END -->", lambda _: block, txt, flags=re.S)
        readme.write_text(txt, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    write_report(Path(sys.argv[1]))
