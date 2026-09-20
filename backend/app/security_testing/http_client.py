"""HTTP client that cannot send traffic without ScopeGuard + SafetyController."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

import httpx

from app.domain.http import HttpBodyMeta, HttpExchange, HttpHeader
from app.security_testing.errors import AuthorizationDeniedError, SafetyLimitExceededError
from app.security_testing.failures import ToolExecutionResult, ToolExecutionState
from app.security_testing.secrets import redact_exchange

if TYPE_CHECKING:
    from app.security_testing.engine import SecurityTestEngine


class GatedHttpClient:
    """The only HTTP sender used by fuzzing, API tests, and PoC requests."""

    def __init__(self, engine: SecurityTestEngine, *, tool: str) -> None:
        self._engine = engine
        self._tool = tool

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        content: str | bytes | None = None,
        timeout: float | None = None,
        destructive: bool = False,
        active: bool = True,
    ) -> HttpExchange | ToolExecutionResult:
        payload = content if content is not None else b""
        payload_bytes = len(payload.encode("utf-8") if isinstance(payload, str) else payload)
        decision = self._engine.authorize(
            url,
            method=method,
            tool=self._tool,
            active=active,
            payload_bytes=payload_bytes,
            destructive=destructive,
        )
        if not decision.allowed:
            self._engine.audit.record(
                project=self._engine.project_id,
                target=url,
                scope_decision=decision.reason,
                tool=self._tool,
                action=f"{method.upper()} denied",
                result="denied",
                human_approval=decision.approval_state,
            )
            raise AuthorizationDeniedError(decision.reason, target=url, tool=self._tool)

        if self._engine.safety.dry_run or decision.dry_run:
            self._engine.audit.record(
                project=self._engine.project_id,
                target=url,
                scope_decision=decision.reason,
                tool=self._tool,
                action=f"{method.upper()} dry-run",
                result="dry_run",
            )
            return ToolExecutionResult(
                tool=self._tool,
                state=ToolExecutionState.DRY_RUN,
                detail=f"Would send {method.upper()} {url}",
            )

        try:
            self._engine.rate_limiter.require()
        except SafetyLimitExceededError as exc:
            self._engine.audit.record(
                project=self._engine.project_id,
                target=url,
                scope_decision=decision.reason,
                tool=self._tool,
                action=f"{method.upper()} rate-limited",
                rate_limit_decision=str(exc),
                result="rate_limited",
            )
            raise

        limits = self._engine.safety.limits
        self._engine.safety.acquire(url)
        try:
            timeout_s = timeout if timeout is not None else limits.timeout_seconds
            async with httpx.AsyncClient(
                timeout=timeout_s,
                follow_redirects=True,
                max_redirects=limits.max_redirects,
            ) as client:
                response = await client.request(
                    method.upper(),
                    url,
                    headers=dict(headers or {}),
                    content=payload if payload else None,
                )
        except httpx.TimeoutException as exc:
            return ToolExecutionResult(
                tool=self._tool, state=ToolExecutionState.TIMEOUT, detail=str(exc)
            )
        except httpx.HTTPError as exc:
            return ToolExecutionResult(
                tool=self._tool, state=ToolExecutionState.NETWORK_FAILURE, detail=str(exc)
            )
        finally:
            self._engine.safety.release()

        body = response.content[: limits.max_response_bytes]
        truncated = len(response.content) > limits.max_response_bytes
        exchange = HttpExchange(
            method=method.upper(),
            url=str(response.url),
            request_headers=tuple(HttpHeader(name=k, value=v) for k, v in (headers or {}).items()),
            request_body=payload.decode("utf-8", "replace")
            if isinstance(payload, bytes)
            else payload or None,
            response_status=response.status_code,
            response_headers=tuple(
                HttpHeader(name=k, value=v) for k, v in response.headers.items()
            ),
            response_body=body.decode("utf-8", "replace"),
            response_body_meta=HttpBodyMeta(
                content_type=response.headers.get("content-type"),
                byte_length=len(response.content),
                truncated=truncated,
            ),
            elapsed_ms=(response.elapsed.total_seconds() * 1000 if response.elapsed else None),
            source_tool=self._tool,
            scope_decision=decision.reason,
        )
        redacted = redact_exchange(exchange)
        self._engine.audit.record(
            project=self._engine.project_id,
            target=url,
            scope_decision=decision.reason,
            tool=self._tool,
            action=f"{method.upper()} {url}",
            request_id=redacted.request_id,
            result=f"status={redacted.response_status}",
        )
        return redacted
