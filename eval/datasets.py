"""Fixed dataset splits. Anything tuned is tuned on DEV only; TEST is touched
once per reported number. Changing these seeds after looking at TEST results
would invalidate the CIs, so they are constants.
"""

from __future__ import annotations

from functools import cache, lru_cache

import numpy as np

from faults import sim
from faults import topology as topo

DEV_SEEDS = tuple(range(0, 200))
TEST_SEEDS = tuple(range(10_000, 10_300))
DEV_WEEK_SEED = 500
TEST_WEEK_SEED = 501

SERIES: list[tuple[str, str]] = [(s, m) for s in topo.SERVICES for m in sim.METRICS]


@cache
def incident(seed: int) -> sim.Incident:
    return sim.generate(seed)


def incidents(seeds: tuple[int, ...]) -> list[sim.Incident]:
    return [incident(s) for s in seeds]


def stack(inc: sim.Incident) -> tuple[np.ndarray, np.ndarray]:
    """Return (today (S, n), history (S, H, n)) in SERIES order."""
    today = np.stack([inc.metrics[s][m][-1] for s, m in SERIES])
    hist = np.stack([inc.metrics[s][m][:-1] for s, m in SERIES])
    return today, hist


@lru_cache(maxsize=4)
def week(seed: int) -> np.ndarray:
    """Fault-free metrics, (S, days+H, DAY) in SERIES order."""
    w = sim.fault_free_week(seed)
    return np.stack([w[s][m] for s, m in SERIES])
