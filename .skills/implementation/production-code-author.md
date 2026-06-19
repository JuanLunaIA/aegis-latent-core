---
name: production-code-author
tier: MEDIUM
domains: [Python, Rust, Go, FastAPI, async, error-handling, production-readiness]
---

## Activation
Load on: "write production code for X", "implement module Y", "complete this function",
"code ready for deploy", "FastAPI endpoint", "async service".

## Output Envelope (every generated file)
```
SHA-256:           executor-computed (never linguistically generated)
Dependencies:      manifest with minimum versions (requirements.txt / Cargo.toml / go.mod)
Edge cases:        table of inputs → expected behavior → error path
E2E command:       exact command to run from clone to passing tests
```

## Python — FastAPI Production Pattern
```python
"""
Module: [purpose]
Dependencies: [list]
Exposed: [public API surface]
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Annotated

import structlog
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from opentelemetry import trace

# Structured logging — JSON, no print()
log = structlog.get_logger(__name__)
tracer = trace.get_tracer(__name__)

# Lifespan: startup + shutdown (not @app.on_event — deprecated)
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: init DB pools, cache, validate config
    await startup()
    yield
    # Shutdown: drain connections gracefully
    await shutdown()

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)  # disable in prod

# Typed dependency injection
async def get_current_user(token: str = ...) -> User:
    # {P}: token is non-empty string
    # {Q}: returns authenticated User or raises 401
    ...

# Endpoint: typed in + typed out, explicit status codes
@app.post("/resources", response_model=ResourceResponse, status_code=status.HTTP_201_CREATED)
async def create_resource(
    payload: ResourceCreate,
    user: Annotated[User, Depends(get_current_user)],
) -> ResourceResponse:
    with tracer.start_as_current_span("create_resource") as span:
        span.set_attribute("user.id", user.id)
        try:
            result = await resource_service.create(payload, owner=user)
            log.info("resource.created", resource_id=result.id, user_id=user.id)
            return result
        except DuplicateError as e:
            raise HTTPException(status_code=409, detail=str(e))
        except ValidationError as e:
            raise HTTPException(status_code=422, detail=e.errors())
        # No bare except — let unhandled bubble to 500 handler with trace_id
```

## Async Standards
```python
# Structured concurrency — TaskGroup (Python 3.11+)
async with asyncio.TaskGroup() as tg:
    task_a = tg.create_task(fetch_a())
    task_b = tg.create_task(fetch_b())
# Both tasks cancelled if either fails — no orphan tasks

# External calls — always timeout + retry
async with httpx.AsyncClient(timeout=httpx.Timeout(connect=5.0, read=30.0)) as client:
    response = await client.get(url)

# DB connection pools — size based on worker count
pool = await asyncpg.create_pool(dsn, min_size=5, max_size=20, command_timeout=30)
```

## Error Handling Architecture
```python
# Domain exceptions (not generic Exception)
class ResourceNotFoundError(DomainError):
    def __init__(self, resource_id: str) -> None:
        super().__init__(f"Resource {resource_id!r} not found")
        self.resource_id = resource_id

# FastAPI exception handler — convert domain → HTTP
@app.exception_handler(ResourceNotFoundError)
async def not_found_handler(request: Request, exc: ResourceNotFoundError) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={"type": "resource_not_found", "resource_id": exc.resource_id,
                 "trace_id": get_trace_id()},  # RFC 7807 problem details
    )
```
