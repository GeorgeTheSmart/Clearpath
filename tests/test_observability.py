"""Static checks on alerting-as-code: annotations, runbooks, burn-rate math."""

import re
from pathlib import Path

import yaml

from faults import sim

ROOT = Path(__file__).resolve().parent.parent
RULE_FILES = sorted((ROOT / "observability/prometheus").glob("*.yaml"))


def _alerts():
    for f in RULE_FILES:
        doc = yaml.safe_load(f.read_text())
        for g in doc["spec"]["groups"]:
            for r in g["rules"]:
                if "alert" in r:
                    yield f.name, r


def test_every_alert_has_required_annotations_and_existing_runbook():
    seen = 0
    for fname, r in _alerts():
        seen += 1
        ann, lab = r.get("annotations", {}), r.get("labels", {})
        assert "summary" in ann and "runbook_url" in ann, (fname, r["alert"])
        assert "severity" in lab, r["alert"]
        assert "service" in lab or "service" in ann, r["alert"]
        assert (ROOT / ann["runbook_url"]).exists(), ann["runbook_url"]
    assert seen >= 11


def test_symptom_alerts_match_simulator_vocabulary():
    names = {r["alert"] for _, r in _alerts()}
    assert set(sim.STATIC_RULES) | {"PodCrashLooping", "TargetDown"} <= names


def test_burn_rate_thresholds_are_consistent_with_slo():
    # 14.4x for 1h spends 14.4 * 1h / 720h = 2% of a 30-day budget; 6x for 6h = 5%.
    assert abs(14.4 * 1 / (30 * 24) - 0.02) < 1e-9
    assert abs(6 * 6 / (30 * 24) - 0.05) < 1e-9
    for _, r in _alerts():
        if r.get("labels", {}).get("slo") == "availability":
            factors = [float(x) for x in re.findall(r"\((\d+(?:\.\d+)?) \* 0\.001\)", r["expr"])]
            assert len(factors) == 2 and factors[0] == factors[1]
            # multi-window: long AND short window
            assert " and " in r["expr"]
