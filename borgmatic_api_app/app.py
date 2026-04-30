"""Application factory for the Borgmatic API."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from flask import Flask, Response

from .actions import ActionStore
from .audit import AuditLogger
from .auth import AuthManager
from .buffers import BufferStore
from .config import load_settings
from .metrics import Metrics
from .rate_limit import RateLimiter
from .routes import create_blueprint
from .routes.actions import bp as actions_blueprint
from .services import Services


def create_app() -> Flask:
    settings = load_settings()
    auth = AuthManager(settings)
    buffers = BufferStore()
    rate_limiter = RateLimiter()
    metrics = Metrics()

    # Initialize action store
    actions_store = ActionStore(policy_path=settings.actions_policy_path)
    actions_store.load_from_file()

    # Initialize audit logger
    audit_logger = AuditLogger(
        log_path=settings.audit_log_path,
        stdout=settings.audit_stdout,
    )

    # Thread pool for async action execution
    executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="action")

    services = Services(
        settings=settings,
        auth=auth,
        rate_limiter=rate_limiter,
        buffers=buffers,
        metrics=metrics,
        actions_store=actions_store,
        audit_logger=audit_logger,
        executor=executor,
    )

    app = Flask(__name__)
    app.config["JSON_AS_ASCII"] = False
    app.config["SERVICES"] = services

    @app.after_request
    def _set_security_headers(response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response

    # Register blueprints
    app.register_blueprint(create_blueprint(services))
    app.register_blueprint(actions_blueprint)
    return app
