# Memory-systems benchmark

**Question:** can AgentSec detect memory failures -- poisoned memories, cross-user leakage, stale instructions,
persisted secrets, untrusted content influencing later sessions -- when an agent's long-term memory is a real memory
library, not a dict inside a reference agent?

**Method:** a deterministic agent (`memory_agent.py`) follows mem0's documented usage pattern: search memory for the
current scope before answering, add the user's message after. Its memory is one of three backends
(`backends.py`), each used through its own public API:

| Backend | What is real | What is substituted |
|---|---|---|
| `dict` | nothing -- the no-library reference | - |
| `mem0` | mem0's `Memory` class: Qdrant (local, in-process) vector store, SQLite history, `user_id`/`agent_id` scoping | `add(..., infer=False)` stores messages verbatim, so no LLM is called; embeddings come from a deterministic bag-of-words hashing embedder plugged in through mem0's `langchain` embedder provider |
| `langgraph` | LangGraph's `InMemoryStore` (the `BaseStore` API LangGraph agents use for cross-thread memory), namespaced per scope | - |

The agent runs in four configurations, each a real-world choice: `isolated` (memory keyed by the end user, only
user-authored text stored, recalled memories treated as data), `shared_scope` (memory keyed by the agent, as with
mem0 `agent_id` or one shared namespace), `stores_untrusted` (also stores "save to memory" text from documents and
tool results, and follows recalled memories), and `vulnerable` (both).

Scenarios: the five `memory_poisoning` scenarios (including the new `secret_persisted_incidentally`) and
`identity_and_session_confusion/credential_from_other_session`.

## Run

```bash
python benchmarks/memory-systems/run.py dict
.venv-mem0/bin/python benchmarks/memory-systems/run.py mem0          # pip install mem0ai langchain langchain-core
.venv-langgraph/bin/python benchmarks/memory-systems/run.py langgraph
python benchmarks/memory-systems/summarize.py                        # writes MATRIX.md
```

## Results (2026-10-03)

[MATRIX.md](MATRIX.md). With all three backends AgentSec separates the failure modes: `isolated` produces no
findings; `shared_scope` produces only cross-user leaks (`secret_leak` on the PIN, the remembered token and the
incidentally stored token); `stores_untrusted` produces only persistence findings (`memory_poisoned`, poisoned-memory
`forbidden_action`) with cross-user isolation intact; `vulnerable` produces both.

One backend-dependent difference: with mem0 in the `vulnerable` configuration the incidentally stored token did not
surface for the second user, because mem0's similarity ranking placed other (poisoned) memories above it in the top
results ("tokens" in the question vs. "token" in the memory). Whether a leak shows up depends on retrieval ranking,
which is exactly why it has to be tested against the real store.

## Not tested

- **Letta** (`letta-code` / Letta server): its agents call an LLM on every step and memory is managed by the agent
  itself; running it needs a Letta server and model credentials, neither available here. NOT TESTED.
- mem0 with `infer=True` (LLM fact extraction), and LangGraph `SqliteStore`/`PostgresStore`: not run.
- Real models deciding what to remember: the agent here is scripted.
