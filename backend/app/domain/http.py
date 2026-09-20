"""Vendor-neutral HTTP evidence types for proxy and browser adapters."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HttpHeader:
    name: str
    value: str


@dataclass(frozen=True)
class HttpExchange:
    """One captured request/response pair.

    Bodies may be truncated by collectors. This type is evidence, not an
    invitation to replay requests against live targets.
    """

    method: str
    url: str
    request_headers: tuple[HttpHeader, ...] = ()
    request_body: str | None = None
    query: str | None = None
    cookies: tuple[str, ...] = ()
    response_status: int | None = None
    response_headers: tuple[HttpHeader, ...] = ()
    response_body: str | None = None
    elapsed_ms: float | None = None
    metadata: tuple[tuple[str, str], ...] = ()
