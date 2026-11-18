"""Typed contracts between nodes. The LLM must return a `Diagnosis`."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

FaultType = Literal[
    "cpu_hog",
    "memory_leak",
    "crash_loop",
    "latency_injection",
    "packet_loss",
    "bad_config",
    "bad_deploy",
    "dns_failure",
    "dependency_down",
    "unknown",
]
ActionKind = Literal["rollout_restart", "scale", "rollback"]


class Evidence(BaseModel):
    ref: str = Field(description="ID of an item in the gathered context, e.g. log:log-00042, metric:cartservice:error_rate, loc:1, rb:rb-crash_loop#symptoms")
    claim: str = Field(max_length=300)


class Action(BaseModel):
    kind: ActionKind
    target: str
    replicas: int | None = None


class Diagnosis(BaseModel):
    root_cause_service: str
    fault_type: FaultType
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(max_length=600)
    evidence: list[Evidence] = Field(min_length=1)
    fix_steps: list[str] = Field(min_length=1)
    risk_level: Literal["low", "medium", "high"]
    proposed_actions: list[Action] = Field(default_factory=list)
    degraded: bool = False  # True when produced without the LLM


class ContextItem(BaseModel):
    id: str
    kind: Literal["alert", "metric", "log", "event", "loc", "rb"]
    service: str | None = None
    text: str


class Context(BaseModel):
    incident_id: str
    window: tuple[int, int]
    items: list[ContextItem]
    redactions: dict[str, int] = Field(default_factory=dict)  # kind -> count
    quarantined: list[str] = Field(default_factory=list)  # log IDs blocked as injection

    def ids(self) -> set[str]:
        return {i.id for i in self.items}

    def by_kind(self, kind: str) -> list[ContextItem]:
        return [i for i in self.items if i.kind == kind]
