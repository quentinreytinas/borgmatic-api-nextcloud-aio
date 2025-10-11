"""Application factory for the Borgmatic API."""

from __future__ import annotations

from flask import Flask

from .auth import AuthManager
from .buffers import BufferStore
from .config import load_settings
from .metrics import Metrics
from .rate_limit import RateLimiter
from .services import Services
from .routes import create_blueprint


def create_app() -> Flask:
    settings = load_settings()
    auth = AuthManager(settings)
    buffers = BufferStore()
    rate_limiter = RateLimiter()
    metrics = Metrics()
    services = Services(
        settings=settings,
        auth=auth,
        rate_limiter=rate_limiter,
        buffers=buffers,
        metrics=metrics,
    )

    app = Flask(__name__)
    app.config["JSON_AS_ASCII"] = False
    app.config["SERVICES"] = services

    app.register_blueprint(create_blueprint(services))
    return app
