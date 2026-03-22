"""Cagent SDK exceptions."""

from __future__ import annotations

from typing import Any


class CagentError(Exception):
    """Base exception for all cagent SDK errors."""


class ApiError(CagentError):
    """HTTP error from the CP API."""

    def __init__(self, status_code: int, detail: str, response: Any = None):
        self.status_code = status_code
        self.detail = detail
        self.response = response
        super().__init__(f"HTTP {status_code}: {detail}")


class NotFoundError(ApiError):
    """404 from the API."""


class AuthenticationError(ApiError):
    """401/403 from the API."""


class ValidationError(CagentError):
    """Client-side validation error."""
