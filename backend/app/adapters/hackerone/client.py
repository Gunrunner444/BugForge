"""HackerOne Hacker API HTTP client.

Isolated JSON:API + Basic auth. Rate-limited independently of target scanning.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.adapters.hackerone.credentials import HackerOneCredentials
from app.adapters.hackerone.errors import (
    HackerOneAuthError,
    HackerOneError,
    HackerOneIdentityVerificationError,
    HackerOneRateLimitError,
)
from app.security_testing.secrets import redact_text

_IDENTITY_HINTS = (
    "identity verification",
    "verify your identity",
    "id verification",
    "kyc",
)


class HackerOneApiClient:
    def __init__(
        self,
        credentials: HackerOneCredentials,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 20.0,
        min_interval_seconds: float = 0.25,
        max_retries: int = 3,
    ) -> None:
        self._credentials = credentials
        self._base = credentials.base_url.rstrip("/") + "/"
        self._timeout = timeout
        self._min_interval = min_interval_seconds
        self._max_retries = max_retries
        self._last_call = 0.0
        self._transport = transport
        self.calls: list[tuple[str, str]] = []

    def _client(self) -> httpx.Client:
        kwargs: dict[str, Any] = {
            "base_url": self._base,
            "auth": self._credentials.auth_tuple(),
            "timeout": self._timeout,
            "headers": {"Accept": "application/json", "Content-Type": "application/json"},
        }
        if self._transport is not None:
            kwargs["transport"] = self._transport
        return httpx.Client(**kwargs)

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, Any] | None = None,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = path if path.startswith("http") else path.lstrip("/")
        self.calls.append((method.upper(), _path_only(urljoin(self._base, url))))
        attempt = 0
        while True:
            self._wait()
            attempt += 1
            try:
                with self._client() as client:
                    response = client.request(method.upper(), url, json=json_body, params=params)
            except httpx.TimeoutException as exc:
                raise HackerOneError("HackerOne API timed out", code="timeout") from exc
            except httpx.HTTPError as exc:
                raise HackerOneError("HackerOne API network failure", code="network") from exc
            if response.status_code == 429 and attempt <= self._max_retries:
                retry_after = _retry_after(response)
                time.sleep(retry_after)
                continue
            return self._handle(response)

    def get(self, path: str, *, params: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return self.request("GET", path, params=params)

    def post(self, path: str, *, json_body: Mapping[str, Any]) -> dict[str, Any]:
        return self.request("POST", path, json_body=json_body)

    def patch(self, path: str, *, json_body: Mapping[str, Any]) -> dict[str, Any]:
        return self.request("PATCH", path, json_body=json_body)

    def paginate(self, path: str, *, params: Mapping[str, Any] | None = None) -> list[Any]:
        items: list[Any] = []
        next_path: str | None = path
        query = dict(params or {})
        while next_path:
            payload = self.get(next_path, params=query or None)
            data = payload.get("data")
            if isinstance(data, list):
                items.extend(data)
            elif data is not None:
                items.append(data)
            links = payload.get("links") if isinstance(payload.get("links"), dict) else {}
            nxt = links.get("next") if isinstance(links, dict) else None
            if not nxt:
                break
            next_path = str(nxt)
            query = {}
        return items

    def _wait(self) -> None:
        now = time.monotonic()
        wait = self._min_interval - (now - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.monotonic()

    def _handle(self, response: httpx.Response) -> dict[str, Any]:
        status = response.status_code
        text = redact_text(response.text or "")
        body: dict[str, Any]
        try:
            parsed = response.json()
            body = parsed if isinstance(parsed, dict) else {"data": parsed}
        except ValueError:
            body = {"raw": text[:500]}
        errors = body.get("errors")
        message = _error_message(errors) or text[:300] or f"HTTP {status}"
        lowered = message.lower()
        if status in {401}:
            raise HackerOneAuthError(
                "Invalid HackerOne API credentials", status_code=401, code="invalid_credentials"
            )
        if status == 403 and any(hint in lowered for hint in _IDENTITY_HINTS):
            raise HackerOneIdentityVerificationError()
        if status == 403:
            raise HackerOneAuthError(
                "HackerOne API forbidden. The account may lack permission for this action.",
                status_code=403,
                code="forbidden",
            )
        if status == 404:
            raise HackerOneError("HackerOne resource not found", status_code=404, code="not_found")
        if status == 409:
            raise HackerOneError(
                "HackerOne reported a conflict (possible duplicate)",
                status_code=409,
                code="conflict",
            )
        if status == 422:
            code = _classify_unprocessable(message)
            raise HackerOneError(
                f"HackerOne rejected the payload: {message}", status_code=422, code=code
            )
        if status == 400:
            raise HackerOneError(
                f"HackerOne request was invalid: {message}", status_code=400, code="bad_request"
            )
        if status == 429:
            raise HackerOneRateLimitError(
                "HackerOne API rate limited", retry_after=_retry_after(response)
            )
        if status >= 500:
            raise HackerOneError(
                "HackerOne API server error", status_code=status, code="server_error"
            )
        if status >= 400:
            raise HackerOneError(message, status_code=status, code="error")
        return body


def _retry_after(response: httpx.Response) -> float:
    raw = response.headers.get("Retry-After") or response.headers.get("retry-after") or "1"
    try:
        return max(0.5, float(raw))
    except ValueError:
        return 1.0


def _error_message(errors: object) -> str:
    if isinstance(errors, list) and errors:
        first = errors[0]
        if isinstance(first, dict):
            detail = first.get("detail") or first.get("title") or first.get("code")
            return str(detail or "")
        return str(first)
    if isinstance(errors, dict):
        return str(errors.get("detail") or errors.get("title") or "")
    return ""


def _classify_unprocessable(message: str) -> str:
    lowered = message.lower()
    if "severity" in lowered:
        return "severity_required"
    if "weakness" in lowered:
        return "weakness_invalid"
    if "structured_scope" in lowered or "structured scope" in lowered:
        return "structured_scope_invalid"
    if "identity" in lowered:
        return "identity_verification_required"
    return "unprocessable"


def _path_only(url: str) -> str:
    parsed = urlparse(url)
    return parsed.path or url
