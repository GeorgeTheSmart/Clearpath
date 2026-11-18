"""Online Boutique service topology (caller -> callees).

Source: GoogleCloudPlatform/microservices-demo architecture diagram. The
loadgenerator is excluded because it is the traffic source, not a service
under test. Call fractions are rough per-request fan-out weights used only by
the simulator to scale propagated latency; the localizer never sees them.
"""

from __future__ import annotations

SERVICES: tuple[str, ...] = (
    "frontend",
    "cartservice",
    "productcatalogservice",
    "currencyservice",
    "paymentservice",
    "shippingservice",
    "emailservice",
    "checkoutservice",
    "recommendationservice",
    "adservice",
    "redis-cart",
)

# caller -> {callee: call fraction per caller request}
CALLS: dict[str, dict[str, float]] = {
    "frontend": {
        "productcatalogservice": 0.9,
        "currencyservice": 0.8,
        "cartservice": 0.5,
        "recommendationservice": 0.5,
        "shippingservice": 0.2,
        "checkoutservice": 0.1,
        "adservice": 0.4,
    },
    "checkoutservice": {
        "productcatalogservice": 1.0,
        "currencyservice": 1.0,
        "cartservice": 1.0,
        "shippingservice": 1.0,
        "emailservice": 1.0,
        "paymentservice": 1.0,
    },
    "recommendationservice": {"productcatalogservice": 1.0},
    "cartservice": {"redis-cart": 1.0},
}


def callees(svc: str) -> dict[str, float]:
    return CALLS.get(svc, {})


def callers(svc: str) -> list[str]:
    return [c for c, ds in CALLS.items() if svc in ds]


def edges() -> list[tuple[str, str]]:
    return [(c, d) for c, ds in CALLS.items() for d in ds]


def neighbors(svc: str) -> set[str]:
    """Undirected neighbourhood, used by the correlator for grouping."""
    return set(callees(svc)) | set(callers(svc))


def reverse_topological() -> list[str]:
    """Services ordered leaves-first, so propagation can flow callee -> caller."""
    order: list[str] = []
    seen: set[str] = set()

    def visit(s: str) -> None:
        if s in seen:
            return
        seen.add(s)
        for d in callees(s):
            visit(d)
        order.append(s)

    for s in SERVICES:
        visit(s)
    return order
