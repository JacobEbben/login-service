"""Security headers, CSRF, client keys and rate limits."""

from __future__ import annotations

import ipaddress
import secrets
import threading
import time
from collections import deque

from flask import Flask, request, session

from .compare import same_secret
from .errors import APIError

# ---- headers -------------------------------------------------------------------------------

def build_csp(form_targets: str = "") -> str:
    """The Content-Security-Policy. ``form_targets``: the registered apps' origins.
    After the login form is posted the browser is redirected on to the app, and
    browsers apply form-action to that whole redirect chain, so the apps that
    may receive a sign-in must be listed (and nothing else)."""
    return "; ".join([
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "font-src 'self'",
        "manifest-src 'self'",
        "base-uri 'none'",
        f"form-action 'self' {form_targets}".strip(),
        "frame-ancestors 'none'",
        "require-trusted-types-for 'script'",
    ])

PERMISSIONS_POLICY = ", ".join(f"{f}=()" for f in (
    "accelerometer", "autoplay", "camera", "display-capture", "encrypted-media", "fullscreen",
    "geolocation", "gyroscope", "magnetometer", "microphone", "midi", "payment",
    "picture-in-picture", "publickey-credentials-get", "screen-wake-lock", "usb",
    "xr-spatial-tracking",
))


def register_headers(app: Flask, *, hsts: bool, form_targets) -> None:
    """``form_targets()``: the space-separated origins of the registered apps."""
    @app.after_request
    def _headers(resp):
        h = resp.headers
        h.setdefault("Content-Security-Policy", build_csp(form_targets()))
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Permissions-Policy", PERMISSIONS_POLICY)
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        h.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        h.setdefault("Cross-Origin-Embedder-Policy", "require-corp")
        h.setdefault("X-Permitted-Cross-Domain-Policies", "none")
        if hsts:
            h.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        if not request.path.startswith("/static/") and request.path != "/.well-known/openid-configuration" \
                and request.path != "/jwks.json":
            # Pages carry the CSRF token, token answers carry tokens: never cache them.
            h["Cache-Control"] = "no-store"
            h["Pragma"] = "no-cache"
        h.pop("Server", None)
        h.pop("X-Powered-By", None)
        return resp


# ---- CSRF ----------------------------------------------------------------------------------

CSRF_KEY = "csrf"


def csrf_token() -> str:
    token = session.get(CSRF_KEY)
    if not isinstance(token, str) or not token:
        token = session[CSRF_KEY] = secrets.token_urlsafe(32)
    return token


def csrf_ok(sent: object) -> bool:
    return same_secret(sent, session.get(CSRF_KEY, ""))


def check_csrf_header() -> None:
    if not csrf_ok(request.headers.get("X-CSRF-Token", "")):
        raise APIError("csrf_invalid", 403)


# ---- client key and rate limits ------------------------------------------------------------

def client_key() -> str:
    """The caller's address for limits: IPv4, or the IPv6 /64 (one home or phone
    gets a whole /64, so a single address would be trivial to rotate)."""
    raw = request.remote_addr or ""
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return raw or "?"
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


class RateLimiter:
    """Sliding-window counters in memory (one process). ``limit <= 0`` means unlimited."""

    MAX_KEYS = 50_000

    def __init__(self, clock=time.monotonic):
        self._hits: dict[tuple[str, str], deque[float]] = {}
        self._lock = threading.Lock()
        self._clock = clock

    def allow(self, bucket: str, key: str, limit: int, window: float) -> bool:
        if limit <= 0:
            return True
        now = self._clock()
        with self._lock:
            if len(self._hits) > self.MAX_KEYS:
                self._prune(now, window)
            q = self._hits.setdefault((bucket, key), deque())
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def _prune(self, now: float, window: float) -> None:
        for k in [k for k, q in self._hits.items() if not q or q[-1] <= now - window]:
            del self._hits[k]


# ---- password guessing (admin password) ------------------------------------------------------

class LoginLimiter:
    """Failed admin-password attempts per key (a client key, or the account
    ``*admin-password*``). A locked key is never forgotten to save memory
    (that would lift the lock); expired and unlocked keys go first."""

    def __init__(self, max_keys: int = 10_000, clock=time.monotonic):
        self._lock = threading.Lock()
        self._max_keys = max_keys
        self._clock = clock
        self._failures: dict[str, tuple[list[float], int, float]] = {}

    def locked(self, key: str, max_failures: int, window: float) -> bool:
        now = self._clock()
        with self._lock:
            entry = self._failures.get(key)
            return entry is not None and len([t for t in entry[0] if now - t < window]) >= max_failures

    def fail(self, key: str, max_failures: int, window: float) -> None:
        now = self._clock()
        with self._lock:
            old = self._failures.pop(key, None)
            times = [t for t in (old[0] if old else []) if now - t < window] + [now]
            self._failures[key] = (times, max_failures, window)
            if len(self._failures) > self._max_keys:
                for k, (ts, mx, win) in list(self._failures.items()):
                    if len(self._failures) <= self._max_keys:
                        break
                    if len([t for t in ts if now - t < win]) < mx:
                        del self._failures[k]

    def recent(self, key: str, window: float) -> int:
        now = self._clock()
        with self._lock:
            entry = self._failures.get(key)
            return len([t for t in entry[0] if now - t < window]) if entry else 0

    def attempt(self, key: str, max_failures: int, window: float) -> bool:
        """Atomically: False if ``key`` is locked, else count this attempt as a failure
        NOW (``reset`` on success). Counting before the slow check means parallel
        requests can't all pass the lock check before any failure is recorded."""
        with self._lock:
            now = self._clock()
            old = self._failures.pop(key, None)
            times = [t for t in (old[0] if old else []) if now - t < window]
            if len(times) >= max_failures:
                self._failures[key] = (times, max_failures, window)
                return False
            self._failures[key] = ([*times, now], max_failures, window)
            return True

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


# scrypt needs ~32 MiB and real CPU per check: at most two at once.
_PASSWORD_CHECKS = threading.BoundedSemaphore(2)


def password_check_slot():
    return _PASSWORD_CHECKS
