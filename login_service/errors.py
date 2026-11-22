"""Errors: API errors are JSON ``{"error": code}`` (the page translates the code);
anything unexpected is logged with a reference and shown generically."""

from __future__ import annotations

import logging
import secrets

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

log = logging.getLogger("login_service")


class APIError(Exception):
    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code = code
        self.status = status


def log_error(message: str, *args: object) -> str:
    ref = secrets.token_hex(5)
    log.error("[ref %s] " + message, ref, *args, exc_info=True)
    return ref


def register(app: Flask) -> None:
    @app.errorhandler(APIError)
    def _api(exc: APIError):
        return jsonify(error=exc.code), exc.status

    @app.errorhandler(HTTPException)
    def _http(exc: HTTPException):
        status = exc.code or 500
        if request.path.startswith("/api/"):
            code = {400: "bad_request", 403: "forbidden", 404: "not_found", 405: "method_not_allowed",
                    413: "too_large", 429: "too_many"}.get(status, "error")
            return jsonify(error=code), status
        return render_template("error.html", status=status), status

    @app.errorhandler(Exception)
    def _unexpected(exc: Exception):
        ref = log_error("unexpected error on %s %s", request.method, request.path)
        if request.path.startswith("/api/"):
            return jsonify(error="internal_error", ref=ref), 500
        return render_template("error.html", status=500, ref=ref), 500
