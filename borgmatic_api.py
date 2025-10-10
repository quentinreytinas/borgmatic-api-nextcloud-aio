"""WSGI entry point for the Borgmatic API."""

from borgmatic_api_app import create_app

app = create_app()
