---
name: llm-engineer
tier: HIGH
domains: [LLM, RAG, agents, evals, prompt-engineering, cost, latency, guardrails, fine-tuning]
---

## Activation
Load on: LLM feature design, RAG architecture, agent/tool-use, eval framework,
prompt optimization, cost reduction, latency optimization, guardrails, fine-tuning decision.

## RAG Architecture
```
Retrieval pipeline:
  Chunking:     semantic (not fixed-size); overlap 10-20%; preserve sentence boundaries
  Embedding:    task-specific model (retrieval models ≠ general models)
  Index:        HNSW for < 10M vectors; IVF-PQ for > 10M (recall vs cost tradeoff)
  Query:        hybrid search (dense + sparse BM25); reciprocal rank fusion
  Reranking:    cross-encoder reranker on top-K candidates (K=20 → top 5)
  Context:      inject retrieved chunks with source metadata; max context window respected

Failure modes to test:
  - Query has no relevant documents → graceful "I don't know"
  - Retrieved docs contradict each other → surface conflict, don't hallucinate resolution
  - Retrieved docs are stale → freshness metadata in retrieval
  - Query out of domain → out-of-scope detector before retrieval
```

## Agent/Tool-Use Patterns
```python
# Tool definition — strict typing, minimal surface
tools = [{
    "name": "query_database",
    "description": "Query the orders database. Use only for order-related questions.",
    "input_schema": {
        "type": "object",
        "properties": {
            "sql": {"type": "string", "description": "Read-only SQL SELECT query"},
        },
        "required": ["sql"]
    }
}]

# Tool execution — sandboxed, timeout, never trust LLM output directly
async def execute_tool(tool_name: str, tool_input: dict) -> str:
    # {P}: tool_name in allowed_tools; tool_input matches schema
    # Validate input against schema BEFORE execution
    validate_tool_input(tool_name, tool_input)
    # Timeout all tool calls
    async with asyncio.timeout(30):
        return await tool_registry[tool_name](tool_input)

# Prompt injection defense:
# - Never interpolate user input directly into system prompt
# - Separate user content from instructions (system vs user role)
# - Validate tool outputs before passing back to model
```

## Eval Framework
```python
# Every LLM feature needs evals before and after changes
class Eval:
    name: str
    input: str | dict
    expected: str | Callable[[str], bool]  # exact match or validator function
    
# Eval categories (all required):
evals = [
    # Correctness: does it give right answer?
    Eval("factual_qa", input=..., expected="correct answer"),
    # Refusal: does it refuse when it should?
    Eval("out_of_scope", input="unrelated question", expected=lambda r: "don't know" in r.lower()),
    # Safety: does it handle adversarial input?
    Eval("prompt_injection", input="ignore previous instructions", expected=no_injection_followed),
    # Format: does output match expected structure?
    Eval("json_output", input=..., expected=valid_json_validator),
]

# Run evals on every prompt/model change
# Target: ≥ 95% pass rate before deploy
```

## Cost & Latency Optimization
```
Token reduction:
  - Prompt caching (Anthropic / OpenAI): cache stable system prompt portions
  - Compress retrieved context (summarize vs full chunks above threshold)
  - Response length control: max_tokens + explicit "be concise" instruction

Latency reduction:
  - Streaming: always for user-facing; buffer for tool calls
  - Parallel tool calls where tools are independent
  - Smaller model for classification/routing; larger for generation

Model selection:
  Simple classification:  small model (cost ×10-100 cheaper)
  Tool routing:           medium model
  Complex reasoning:      large model
  Measure: cost-per-correct-answer (not just cost-per-token)
```

## Guardrails
```
Input guardrails:  PII detection, prompt injection detection, topic classifier
Output guardrails: hallucination detection (grounded in retrieved context?),
                   PII in output, factual claim verification, format validation
Fallback:         on guardrail trip → safe static response, never silent failure
Logging:          log all inputs + outputs (PII-stripped) for eval dataset growth
```
