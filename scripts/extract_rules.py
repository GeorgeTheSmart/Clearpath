"""Write the rule groups of each PrometheusRule CRD as a plain Prometheus rule
file, so `promtool check rules` / `promtool test rules` can load them.

    python scripts/extract_rules.py [out_dir]   # default var/rules
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for f in sorted((ROOT / "observability/prometheus").glob("*.yaml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        assert doc["kind"] == "PrometheusRule", f
        (out / f.name).write_text(yaml.safe_dump({"groups": doc["spec"]["groups"]}, sort_keys=False), encoding="utf-8", newline="\n")
        print(f"{f.name}: {sum(len(g['rules']) for g in doc['spec']['groups'])} rules")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "var/rules")
