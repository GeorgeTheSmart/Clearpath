"""Pluggable LLM providers with caching, retries and token/cost accounting.

Select with CLEARPATH_LLM = anthropic | openai | ollama | none and
CLEARPATH_MODEL. Prices are NOT hard-coded (they change): set
CLEARPATH_PRICE_IN / CLEARPATH_PRICE_OUT in USD per million tokens to get $
cost; otherwise cost is reported as tokens only.

Standard library HTTP only, so the agent has no SDK dependency.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    wall_s: float = 0.0
    calls: int = 0
    cache_hits: int = 0

    def cost_usd(self) -> float | None:
        pin, pout = os.environ.get("CLEARPATH_PRICE_IN"), os.environ.get("CLEARPATH_PRICE_OUT")
        if pin is None or pout is None:
            return None
        return self.input_tokens / 1e6 * float(pin) + self.output_tokens / 1e6 * float(pout)


class LLM(Protocol):
    name: str
    usage: Usage

    def complete(self, system: str, user: str, max_tokens: int = 1200) -> str: ...


class LLMUnavailable(RuntimeError):
    pass


def _post(url: str, body: dict[str, Any], headers: dict[str, str], timeout: float) -> dict[str, Any]:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"content-type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        out: dict[str, Any] = json.load(r)
        return out


@dataclass
class HTTPProvider:
    name: str
    model: str
    timeout: float = 60.0
    retries: int = 3
    cache_dir: Path | None = Path(".cache/llm")
    usage: Usage = field(default_factory=Usage)

    def _key(self, system: str, user: str, max_tokens: int) -> str:
        return hashlib.sha256(json.dumps([self.name, self.model, system, user, max_tokens]).encode()).hexdigest()

    def complete(self, system: str, user: str, max_tokens: int = 1200) -> str:
        key = self._key(system, user, max_tokens)
        if self.cache_dir is not None:
            p = self.cache_dir / f"{key}.json"
            if p.exists():
                self.usage.cache_hits += 1
                return str(json.loads(p.read_text(encoding="utf-8"))["text"])
        t0 = time.time()
        last: Exception | None = None
        for attempt in range(self.retries):
            try:
                text, tin, tout = self._call(system, user, max_tokens)
                break
            except (urllib.error.URLError, TimeoutError, KeyError, json.JSONDecodeError) as e:
                last = e
                time.sleep(min(8.0, 0.5 * 2**attempt))
        else:
            raise LLMUnavailable(f"{self.name} failed after {self.retries} attempts: {last}")
        self.usage.calls += 1
        self.usage.input_tokens += tin
        self.usage.output_tokens += tout
        self.usage.wall_s += time.time() - t0
        if self.cache_dir is not None:
            try:
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                (self.cache_dir / f"{key}.json").write_text(json.dumps({"text": text}), encoding="utf-8", newline="\n")
            except OSError:
                pass  # best-effort (e.g. read-only root FS): never fail a paid completion over its cache
        return text

    def _call(self, system: str, user: str, max_tokens: int) -> tuple[str, int, int]:
        if self.name == "anthropic":
            r = _post(
                "https://api.anthropic.com/v1/messages",
                {"model": self.model, "max_tokens": max_tokens, "system": system, "messages": [{"role": "user", "content": user}]},
                {"x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01"},
                self.timeout,
            )
            text = "".join(b.get("text", "") for b in r["content"])
            return text, int(r["usage"]["input_tokens"]), int(r["usage"]["output_tokens"])
        if self.name == "openai":
            r = _post(
                "https://api.openai.com/v1/chat/completions",
                {
                    "model": self.model,
                    "max_tokens": max_tokens,
                    "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                    "response_format": {"type": "json_object"},
                },
                {"authorization": f"Bearer {os.environ['OPENAI_API_KEY']}"},
                self.timeout,
            )
            return r["choices"][0]["message"]["content"], int(r["usage"]["prompt_tokens"]), int(r["usage"]["completion_tokens"])
        if self.name == "ollama":
            host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
            r = _post(
                f"{host}/api/chat",
                {
                    "model": self.model,
                    "stream": False,
                    "format": "json",
                    "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                    # Without an explicit num_ctx Ollama uses a small default window and
                    # silently drops the START of a long prompt - the system prompt
                    # with the safety rules goes first. temperature/seed: reproducible evals.
                    "options": {"num_ctx": int(os.environ.get("CLEARPATH_NUM_CTX", "8192")), "temperature": 0, "seed": 0, "num_predict": max_tokens},
                },
                {},
                self.timeout,
            )
            return r["message"]["content"], int(r.get("prompt_eval_count", 0)), int(r.get("eval_count", 0))
        raise ValueError(self.name)


def from_env() -> LLM | None:
    name = os.environ.get("CLEARPATH_LLM", "none").lower()
    if name == "none":
        return None
    # ollama default: Qwen2.5-7B-Instruct - Apache-2.0 (OSI open source), reliable JSON, fits 8 GB VRAM at Q4
    defaults = {"anthropic": "claude-sonnet-5-5", "openai": "gpt-4o-mini", "ollama": "qwen2.5:7b-instruct"}
    if name not in defaults:
        raise ValueError(f"CLEARPATH_LLM={name!r}: expected one of none, {', '.join(defaults)}")
    # CLEARPATH_LLM_CACHE: response cache dir (keeps evals reproducible); "off" disables it.
    cache = os.environ.get("CLEARPATH_LLM_CACHE", ".cache/llm")
    return HTTPProvider(
        name=name,
        model=os.environ.get("CLEARPATH_MODEL", defaults[name]),
        cache_dir=None if cache == "off" else Path(cache),
        timeout=float(os.environ.get("CLEARPATH_LLM_TIMEOUT", "120")),  # a local model's first call also loads it
    )
