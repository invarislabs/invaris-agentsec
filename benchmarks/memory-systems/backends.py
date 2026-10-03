"""Long-term memory backends for the memory agent. Each stores text under a scope -- ("user", id) or
("agent", id) -- and returns everything stored in that scope for a query, most relevant first.

* `dict`     -- a plain in-process dict (the no-library reference).
* `mem0`     -- mem0's `Memory` class, unmodified: Qdrant (local, in-process) vector store, SQLite
                history. `add(..., infer=False)` stores messages verbatim, so no LLM is called;
                embeddings come from a deterministic bag-of-words hashing embedder plugged in through
                mem0's `langchain` embedder provider. Scope maps to mem0's own `user_id` / `agent_id`.
* `langgraph`-- LangGraph's `InMemoryStore` (the BaseStore API LangGraph agents use for cross-thread
                memory). Scope maps to the namespace ("memories", kind, id).
"""
import hashlib
import math
import os
import re
import tempfile
import uuid
from typing import List, Tuple

Scope = Tuple[str, str]


class DictBackend:
    name = "plain dict"

    def __init__(self):
        self.data = {}

    def add(self, scope: Scope, text: str, source: str) -> None:
        self.data.setdefault(scope, []).append(text)

    def search(self, scope: Scope, query: str) -> List[str]:
        return list(reversed(self.data.get(scope, [])))[:10]


def _bow(text: str, dim: int = 256) -> List[float]:
    v = [0.0] * dim
    for w in re.findall(r"[a-z0-9]+", text.lower()):
        v[int(hashlib.md5(w.encode()).hexdigest(), 16) % dim] += 1.0
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


class Mem0Backend:
    name = "mem0"

    def __init__(self):
        os.environ.setdefault("OPENAI_API_KEY", "sk-unused-no-llm-calls-are-made")  # infer=False: never called
        os.environ.setdefault("MEM0_TELEMETRY", "False")
        from langchain_core.embeddings import Embeddings
        from mem0 import Memory

        class HashingEmbeddings(Embeddings):
            def embed_documents(self, texts):
                return [_bow(t) for t in texts]

            def embed_query(self, text):
                return _bow(text)

        tmp = tempfile.mkdtemp(prefix="agentsec-mem0-")
        self.memory = Memory.from_config({
            "embedder": {"provider": "langchain", "config": {"model": HashingEmbeddings()}},
            "vector_store": {"provider": "qdrant", "config": {"collection_name": "bench_%s" % uuid.uuid4().hex[:8],
                                                              "path": os.path.join(tmp, "qdrant"),
                                                              "embedding_model_dims": 256, "on_disk": False}},
            "history_db_path": os.path.join(tmp, "history.db"),
        })

    @staticmethod
    def _ids(scope: Scope) -> dict:
        kind, ident = scope
        return {"user_id": ident} if kind == "user" else {"agent_id": ident}

    def add(self, scope: Scope, text: str, source: str) -> None:
        self.memory.add([{"role": "user", "content": text}], infer=False, metadata={"source": source},
                        **self._ids(scope))

    def search(self, scope: Scope, query: str) -> List[str]:
        res = self.memory.search(query, filters=self._ids(scope), top_k=10, threshold=0.0)
        items = res.get("results", res) if isinstance(res, dict) else res
        return [i["memory"] for i in items]


class LangGraphStoreBackend:
    name = "langgraph InMemoryStore"

    def __init__(self):
        from langgraph.store.memory import InMemoryStore
        self.store = InMemoryStore()

    def add(self, scope: Scope, text: str, source: str) -> None:
        self.store.put(("memories",) + scope, uuid.uuid4().hex, {"text": text, "source": source})

    def search(self, scope: Scope, query: str) -> List[str]:
        items = self.store.search(("memories",) + scope, limit=1000)
        return [i.value["text"] for i in sorted(items, key=lambda i: i.created_at, reverse=True)[:10]]


BACKENDS = {"dict": DictBackend, "mem0": Mem0Backend, "langgraph": LangGraphStoreBackend}
