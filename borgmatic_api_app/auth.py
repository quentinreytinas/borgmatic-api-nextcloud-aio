"""Authentication helpers for the Borgmatic API."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from functools import wraps
from typing import Callable, List, Optional

from flask import Request, request

from .config import Settings


class TokenRole(Enum):
    """Token roles for fine-grained access control."""

    ADMIN = "admin"
    ACTION = "action"
    READ = "read"


class AuthError(PermissionError):
    """Raised when the request fails authentication."""


@dataclass(slots=True)
class AuthResult:
    """Result of a successful authentication."""

    role: TokenRole


@dataclass(slots=True)
class AuthManager:
    settings: Settings

    def verify(self, req: Request, read_only: bool = False) -> None:
        """Legacy verify (kept for backwards compatibility during migration).

        In legacy mode (SECURE_MODE=false), write_token = admin_token = legacy_token,
        so this path still works.
        """
        header = req.headers.get("X-From-NodeRed")
        if header != self.settings.from_header:
            raise AuthError("X-From-NodeRed header invalid")

        auth_header = req.headers.get("Authorization", "")
        progress_token = req.headers.get("X-Progress-Token", "")

        if read_only:
            if auth_header.startswith("Bearer "):
                token = auth_header[7:].strip()
                if token not in (self.settings.read_token, self.settings.admin_token):
                    raise AuthError("Invalid token")
            elif progress_token == self.settings.read_token:
                return
            else:
                raise AuthError("Missing read token")
        else:
            if not auth_header.startswith("Bearer "):
                raise AuthError("Missing write token")
            token = auth_header[7:].strip()
            if token != self.settings.admin_token:
                raise AuthError("Missing/invalid write token")

    def authenticate(self, req: Request) -> Optional[TokenRole]:
        """Authenticate request and return the TokenRole, or None if unauthenticated."""
        # 1) Check X-From-NodeRed header
        header = req.headers.get("X-From-NodeRed")
        if header != self.settings.from_header:
            return None

        # 2) Extract token
        auth_header = req.headers.get("Authorization", "")
        progress_token = req.headers.get("X-Progress-Token", "")

        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        elif progress_token:
            token = progress_token

        if not token:
            return None

        # 3) Match token to role (order matters: check specific roles first)
        if token == self.settings.admin_token:
            return TokenRole.ADMIN
        if token == self.settings.action_token:
            return TokenRole.ACTION
        if token == self.settings.read_token:
            return TokenRole.READ

        return None

    def require(self, req: Request, roles: List[TokenRole]) -> AuthResult:
        """Require one of the given roles; raise AuthError if not satisfied."""
        role = self.authenticate(req)
        if role is None or role not in roles:
            raise AuthError(f"Token role required: {[r.value for r in roles]}")
        return AuthResult(role=role)


def require_role(*roles: TokenRole) -> Callable:
    """Decorator enforcing at least one of the given TokenRoles.

    Usage:
        @require_role(TokenRole.ADMIN)
        @require_role(TokenRole.ADMIN, TokenRole.ACTION)
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            from flask import current_app, jsonify as flask_jsonify

            try:
                services = current_app.config["SERVICES"]
                auth: AuthManager = services.auth
                auth.require(request, list(roles))
            except AuthError:
                return (
                    flask_jsonify(
                        {
                            "error": "unauthorized",
                            "message": "Invalid or insufficient token role",
                        }
                    ),
                    401,
                )
            return func(*args, **kwargs)

        return wrapper

    return decorator


def require_read() -> Callable:
    """Shortcut for @require_role(TokenRole.READ, TokenRole.ADMIN)."""
    return require_role(TokenRole.READ, TokenRole.ADMIN)


def require_admin() -> Callable:
    """Shortcut for @require_role(TokenRole.ADMIN)."""
    return require_role(TokenRole.ADMIN)


def require_action() -> Callable:
    """Shortcut for @require_role(TokenRole.ACTION, TokenRole.ADMIN)."""
    return require_role(TokenRole.ACTION, TokenRole.ADMIN)


# ---------------------------------------------------------------------------
# Legacy decorator (kept for migration — wraps require_auth)
# ---------------------------------------------------------------------------
def require_auth(manager: AuthManager, read_only: bool = False) -> Callable:
    """Decorator enforcing authentication on a view function (legacy)."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            manager.verify(request, read_only=read_only)
            return func(*args, **kwargs)

        return wrapper

    return decorator
