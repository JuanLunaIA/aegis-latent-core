# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Streaming request-body limits, installed by both HTTP surfaces.

`RequestBodyLimitMiddleware` lives here rather than in `aegis.proxy.app` so that
`aegis_server` can install it without importing the gateway module: that import
pulls the gateway's whole dependency graph (795 modules, ~0.8 s locally) and its
import-time egress-guard probe into the enterprise process, which is a separate
surface with its own start-up path and its own configuration. `aegis.proxy.app`
re-exports the name, so `from aegis.proxy.app import RequestBodyLimitMiddleware`
still resolves.

The limit is enforced twice on purpose (AUD-09): a declared `Content-Length`
over the cap is refused before any byte is read, and the receive stream is
counted chunk by chunk so a chunked or understating client cannot exceed it
either.

The second path raises from inside the receive callable, which Starlette runs in
an anyio task group: the exception therefore reaches `dispatch` wrapped in a
`BaseExceptionGroup` and an `except HTTPException` would miss it, turning the
refusal into an unhandled server error. `RequestBodyTooLargeError` exists so the
middleware can recognise its own refusal through that wrapping and re-raise
anything else untouched.
"""

from __future__ import annotations

from typing import Any, cast

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class RequestBodyTooLargeError(HTTPException):
    """The 413 raised from inside the receive callable.

    Raised as a distinct type rather than a plain HTTPException so that the
    unwrapping below can tell this middleware's own refusal apart from any other
    exception travelling in the same group.
    """

    def __init__(self) -> None:
        super().__init__(status_code=413, detail="Request body too large")


def _is_body_too_large(exc: BaseException) -> bool:
    """True when `exc` is, or groups, this middleware's own 413 refusal."""
    if isinstance(exc, RequestBodyTooLargeError):
        return True
    if isinstance(exc, BaseExceptionGroup):
        return any(_is_body_too_large(inner) for inner in exc.exceptions)
    return False


class RequestBodyLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized bodies before JSON parsing or provider forwarding."""

    def __init__(self, app: Any, max_body_bytes: int) -> None:
        super().__init__(app)
        self._max_body_bytes = max_body_bytes

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                declared = int(content_length)
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
            if declared < 0 or declared > self._max_body_bytes:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        received = 0
        original_receive = request.receive

        async def bounded_receive() -> dict[str, Any]:
            nonlocal received
            message = await original_receive()
            if message.get("type") == "http.request":
                chunk = message.get("body", b"")
                received += len(chunk)
                if received > self._max_body_bytes:
                    raise RequestBodyTooLargeError
            return dict(message)

        request._receive = bounded_receive
        try:
            return cast("Response", await call_next(request))
        except RequestBodyTooLargeError:
            return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        except BaseExceptionGroup as group:
            # Starlette runs the receive callable in an anyio task group, so the
            # refusal can arrive grouped. Anything that is not our own 413 is
            # re-raised untouched.
            if not _is_body_too_large(group):
                raise
            return JSONResponse(status_code=413, content={"detail": "Request body too large"})
