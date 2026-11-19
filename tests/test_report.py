"""eval/report.py must be safe to run on any machine and any output dir."""

import shutil
from pathlib import Path

from eval import report

ROOT = Path(__file__).resolve().parent.parent
COMMITTED = ROOT / "eval/results/latest"


def _copy_results(dst: Path) -> Path:
    dst.mkdir(parents=True)
    for name in ("metrics.json", "detection.json", "localization.json"):
        shutil.copy(COMMITTED / name, dst / name)
    return dst


def test_run_outside_repo_writes_report_but_leaves_readme(tmp_path):
    readme = (ROOT / "README.md").read_bytes()
    d = _copy_results(tmp_path / "out")
    report.write_report(d)  # used to raise ValueError from relative_to()
    assert (d / "report.md").read_text(encoding="utf-8").startswith("#")
    assert (ROOT / "README.md").read_bytes() == readme


def test_readme_links_are_posix_and_match_committed_table():
    block = report.readme_block(COMMITTED.resolve())
    assert "\\" not in block and "](eval/results/latest/metrics.json)" in block
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    # The committed README table is exactly what the committed results produce.
    newest = max(d for d in (ROOT / "eval/results").glob("20??-??-??") if (d / "metrics.json").exists())
    committed_block = report.readme_block(newest)
    assert committed_block in readme
