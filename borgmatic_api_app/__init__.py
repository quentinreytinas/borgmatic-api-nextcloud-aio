"""Borgmatic API application package."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - imported for type checking only
    from flask import Flask


def create_app() -> "Flask":
    from .app import create_app as factory

    return factory()


__all__ = ["create_app"]
