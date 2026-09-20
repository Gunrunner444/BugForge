"""HackerOne API errors. Messages never include credentials."""

from __future__ import annotations

from app.security_testing.errors import SecurityTestingError


class HackerOneError(SecurityTestingError):
    def __init__(self, message: str, *, status_code: int | None = None, code: str = "") -> None:
        self.status_code = status_code
        self.code = code
        super().__init__(message)


class HackerOneAuthError(HackerOneError):
    pass


class HackerOneRateLimitError(HackerOneError):
    def __init__(self, message: str, *, retry_after: float | None = None) -> None:
        self.retry_after = retry_after
        super().__init__(message, status_code=429, code="rate_limited")


class HackerOneIdentityVerificationError(HackerOneError):
    def __init__(self, message: str = "HackerOne identity verification is required") -> None:
        super().__init__(message, status_code=403, code="identity_verification_required")
