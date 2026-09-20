"""HTTP client that cannot send traffic without ScopeGuard + SafetyController.

Redirects are disabled by default. Each Location is normalized and
re-authorized (ScopeGuard + SafetyController) before it is followed.
The first authorized URL never covers the rest of a redirect chain.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING
from urllib.parse import urljoin

import httpx

from app.domain.http import HttpBodyMeta, HttpExchange, HttpHeader
from app.security_testing.errors import AuthorizationDeniedError, SafetyLimitExceededError
from app.security_testing.failures import ToolExecutionResult, ToolExecutionState
from app.security_testing.secrets import redact_exchange, redact_text
from app.security_testing.target import TargetNormalizer

if TYPE_CHECKING:
    from app.security_testing.engine import SecurityTestEngine


class GatedHttpClient:
    """The only HTTP sender used by fuzzing, API tests, and PoC requests."""

    def __init__(self, engine: SecurityTestEngine, *, tool: str) -> None:
        self._engine = engine
        self._tool = tool
        self._normalizer = TargetNormalizer()

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
        follow_redirects: bool = False,
    ) -> HttpExchange | ToolExecutionResult:
        payload = content if content is not None else b""
        payload_bytes = len(payload.encode("utf-8") if isinstance(payload, str) else payload)
        limits = self._engine.safety.limits
        timeout_s = timeout if timeout is not None else limits.timeout_seconds
        current = url
        remaining = limits.max_redirects if follow_redirects else 0
        seen: set[str] = set()
        response: httpx.Response | None = None
        last_decision_reason = ""
        hops = 0

        while True:
            decision = self._engine.authorize(
                current,
                method=method if hops == 0 else "GET",
                tool=self._tool if hops == 0 else f"{self._tool}_redirect",
                active=active,
                payload_bytes=payload_bytes if hops == 0 else 0,
                destructive=destructive,
            )
            last_decision_reason = decision.reason
            if not decision.allowed:
                self._engine.audit.record(
                    project=self._engine.project_id,
                    target=current,
                    scope_decision=decision.reason,
                    tool=self._tool,
                    action=f"{method.upper()} denied" if hops == 0 else "redirect denied",
                    result="denied",
                    human_approval=decision.approval_state,
                )
                raise AuthorizationDeniedError(decision.reason, target=current, tool=self._tool)

            if self._engine.safety.dry_run or decision.dry_run:
                self._engine.audit.record(
                    project=self._engine.project_id,
                    target=current,
                    scope_decision=decision.reason,
                    tool=self._tool,
                    action=f"{method.upper()} dry-run",
                    result="dry_run",
                )
                return ToolExecutionResult(
                    tool=self._tool,
                    state=ToolExecutionState.DRY_RUN,
                    detail=f"Would send {method.upper()} {current}",
                )

            try:
                self._engine.rate_limiter.require()
            except SafetyLimitExceededError as exc:
                self._engine.audit.record(
                    project=self._engine.project_id,
                    target=current,
                    scope_decision=decision.reason,
                    tool=self._tool,
                    action=f"{method.upper()} rate-limited",
                    rate_limit_decision=str(exc),
                    result="rate_limited",
                )
                raise

            self._engine.safety.acquire(current)
            try:
                async with httpx.AsyncClient(
                    timeout=timeout_s,
                    follow_redirects=False,
                    max_redirects=0,
                ) as client:
                    response = await client.request(
                        method.upper() if hops == 0 else "GET",
                        current,
                        headers=dict(headers or {}),
                        content=payload if payload and hops == 0 else None,
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

            assert response is not None
            if not _is_redirect(response):
                break
            location = response.headers.get("location")
            if not location:
                break
            nxt = self._normalize_redirect(current, location)
            if nxt in seen or current in seen:
                return ToolExecutionResult(
                    tool=self._tool,
                    state=ToolExecutionState.EXECUTION_ERROR,
                    detail=f"Redirect loop involving {current}",
                )
            seen.add(current)
            if remaining <= 0:
                if follow_redirects:
                    return ToolExecutionResult(
                        tool=self._tool,
                        state=ToolExecutionState.EXECUTION_ERROR,
                        detail="Maximum redirects exceeded",
                    )
                # Redirects disabled: return the 3xx as the observation.
                break
            remaining -= 1
            hops += 1
            current = nxt

        assert response is not None
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
            scope_decision=last_decision_reason,
        )
        redacted = redact_exchange(exchange)
        self._engine.audit.record(
            project=self._engine.project_id,
            target=url,
            scope_decision=last_decision_reason,
            tool=self._tool,
            action=f"{method.upper()} {url}",
            request_id=redacted.request_id,
            result=f"status={redacted.response_status}",
        )
        return redacted

    def _normalize_redirect(self, current: str, location: str) -> str:
        joined = urljoin(current, location.strip())
        try:
            normalized = self._normalizer.normalize(joined, default_scheme=_scheme_of(current))
            return normalized.url
        except ValueError as exc:
            raise AuthorizationDeniedError(
                f"Malformed redirect target {redact_text(location)} ({exc})",
                target=joined,
                tool=self._tool,
            ) from exc


def _is_redirect(response: httpx.Response) -> bool:
    return response.status_code in {301, 302, 303, 307, 308}


def _scheme_of(url: str) -> str:
    if url.startswith("http://"):
        return "http"
    return "https"
