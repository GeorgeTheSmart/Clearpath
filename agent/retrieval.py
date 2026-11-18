"""Hybrid runbook retrieval: BM25 + dense vectors, fused with reciprocal rank fusion.

* BM25 (Robertson & Zaragoza) is implemented here (k1=1.5, b=0.75): exact
  term matching is what finds "OOMKilled" or "no such host".
* Dense: LSA (TF-IDF -> truncated SVD, cosine). It is a stand-in for a neural
  sentence embedding (e.g. bge-small) that could not be downloaded in the
  build environment; `Embedder` is the swap point.
* RRF (Cormack et al., 2009): score(d) = sum_r 1 / (k + rank_r(d)), k = 60. It
  needs no score calibration between retrievers, which is why it is used.
* A cross-encoder rerank is supported through `Reranker` but off by default
  (no model available offline); its absence is reported, not hidden.

Chunks have stable IDs (`rb-crash_loop#symptoms`) so the diagnosis can cite them.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import numpy as np

_TOKEN = re.compile(r"[a-z0-9_]+")
_STOP = frozenset("a an the and or of to in on for is are be with by at as it its this that from".split())


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOP]


@dataclass(frozen=True)
class Chunk:
    id: str
    doc_id: str
    fault_type: str
    text: str


def load_runbooks(root: Path) -> list[Chunk]:
    chunks: list[Chunk] = []
    for p in sorted(root.glob("*.md")):
        raw = p.read_text()
        meta = dict(re.findall(r"^(\w+): (.*)$", raw.split("---")[1], re.M)) if raw.startswith("---") else {}
        body = raw.split("---", 2)[2] if raw.startswith("---") else raw
        doc = meta.get("id", p.stem)
        title = body.strip().splitlines()[0].lstrip("# ")
        for sec in re.split(r"^## ", body, flags=re.M)[1:]:
            name, _, text = sec.partition("\n")
            cid = f"{doc}#{name.strip().lower().split()[0]}"
            chunks.append(Chunk(cid, doc, meta.get("fault_type", "none"), f"{title}. {meta.get('alerts', '')}. {text.strip()}"))
        if "## " not in body:
            chunks.append(Chunk(f"{doc}#body", doc, meta.get("fault_type", "none"), body.strip()))
    return chunks


class BM25:
    def __init__(self, docs: list[list[str]], k1: float = 1.5, b: float = 0.75) -> None:
        self.k1, self.b = k1, b
        self.tf = [Counter(d) for d in docs]
        self.len = np.array([len(d) for d in docs], float)
        self.avg = float(self.len.mean()) if docs else 0.0
        df = Counter(t for d in docs for t in set(d))
        n = len(docs)
        self.idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}

    def scores(self, q: list[str]) -> np.ndarray:
        out = np.zeros(len(self.tf))
        for i, tf in enumerate(self.tf):
            s = 0.0
            for t in q:
                f = tf.get(t, 0)
                if f:
                    s += self.idf[t] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * self.len[i] / self.avg))
            out[i] = s
        return out


class Embedder(Protocol):
    def fit(self, texts: list[str]) -> None: ...
    def encode(self, texts: list[str]) -> np.ndarray: ...


class LSAEmbedder:
    def __init__(self, dim: int = 24, seed: int = 0) -> None:
        from sklearn.decomposition import TruncatedSVD
        from sklearn.feature_extraction.text import TfidfVectorizer

        self.vec = TfidfVectorizer(tokenizer=tokenize, token_pattern=None, ngram_range=(1, 2), sublinear_tf=True)
        self.svd = TruncatedSVD(n_components=dim, random_state=seed)

    def fit(self, texts: list[str]) -> None:
        X = self.vec.fit_transform(texts)
        self.svd.n_components = min(self.svd.n_components, X.shape[1] - 1, X.shape[0] - 1)
        self.svd.fit(X)

    def encode(self, texts: list[str]) -> np.ndarray:
        E = self.svd.transform(self.vec.transform(texts))
        return np.asarray(E / np.maximum(np.linalg.norm(E, axis=1, keepdims=True), 1e-12))


class Reranker(Protocol):
    def score(self, query: str, texts: list[str]) -> np.ndarray: ...


def rrf(rankings: list[list[int]], k: int = 60) -> dict[int, float]:
    out: dict[int, float] = {}
    for r in rankings:
        for pos, idx in enumerate(r):
            out[idx] = out.get(idx, 0.0) + 1.0 / (k + pos + 1)
    return out


@dataclass(frozen=True)
class Hit:
    chunk: Chunk
    score: float


class Retriever:
    def __init__(self, chunks: list[Chunk], embedder: Embedder | None = None, reranker: Reranker | None = None) -> None:
        self.chunks = chunks
        self.bm25 = BM25([tokenize(c.text) for c in chunks])
        self.emb = embedder or LSAEmbedder()
        self.emb.fit([c.text for c in chunks])
        self.E = self.emb.encode([c.text for c in chunks])
        self.reranker = reranker

    def search(self, query: str, k: int = 5, mode: str = "hybrid") -> list[Hit]:
        q = tokenize(query)
        bm = self.bm25.scores(q)
        dense = self.E @ self.emb.encode([query])[0]
        if mode == "bm25":
            fused = {i: float(bm[i]) for i in range(len(self.chunks))}
        elif mode == "dense":
            fused = {i: float(dense[i]) for i in range(len(self.chunks))}
        else:
            fused = rrf([list(np.argsort(-bm, kind="stable")), list(np.argsort(-dense, kind="stable"))])
        order = sorted(fused, key=lambda i: -fused[i])[: max(k * 3, k)]
        if self.reranker is not None:
            rs = self.reranker.score(query, [self.chunks[i].text for i in order])
            order = [order[j] for j in np.argsort(-rs)]
        return [Hit(self.chunks[i], fused[i]) for i in order[:k]]

    def search_docs(self, query: str, k: int = 3, mode: str = "hybrid") -> list[Hit]:
        """Best chunk per runbook, deduplicated to documents (for recall@k)."""
        seen: dict[str, Hit] = {}
        for h in self.search(query, k=len(self.chunks), mode=mode):
            seen.setdefault(h.chunk.doc_id, h)
        return list(seen.values())[:k]
