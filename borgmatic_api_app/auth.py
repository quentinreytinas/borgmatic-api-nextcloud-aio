"""Authentication helpers for the Borgmatic API."""

from __future__ import annotations

from dataclasses import dataclass
from functools import wraps
from typing import Callable

from flask import Request, request

from .config import Settings


class AuthError(PermissionError):
    """Raised when the request fails authentication."""


@dataclass(slots=True)
class AuthManager:
    settings: Settings

    def verify(self, request: Request, read_only: bool = False) -> None:
        header = request.headers.get("X-From-NodeRed")
        if header != self.settings.from_header:
            raise AuthError("X-From-NodeRed header invalid")

        auth_header = request.headers.get("Authorization", "")
        progress_token = request.headers.get("X-Progress-Token", "")

        if read_only:
            if auth_header.startswith("Bearer "):
                token = auth_header[7:].strip()
                if token not in (self.settings.read_token, self.settings.write_token):
                    raise AuthError("Invalid token")
            elif progress_token == self.settings.read_token:
                return
            else:
                raise AuthError("Missing read token")
        else:
            if not auth_header.startswith("Bearer "):
                raise AuthError("Missing write token")
            token = auth_header[7:].strip()
            if token != self.settings.write_token:
                raise AuthError("Missing/invalid write token")


def require_auth(manager: AuthManager, read_only: bool = False) -> Callable:
    """Decorator enforcing authentication on a view function."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            manager.verify(request, read_only=read_only)
            return func(*args, **kwargs)

        return wrapper

    return decorator
