"""Authenticator-app codes (TOTP, RFC 6238): HMAC-SHA1, 6 digits, 30-second steps.

These are the settings every authenticator app supports (Google Authenticator,
Microsoft Authenticator, 1Password, Aegis, ...). A code is accepted for the
current step and one step either side (clock drift), and each step only once:
the caller stores the step it accepted and passes it as ``last_step``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

DIGITS = 6
PERIOD = 30
DRIFT_STEPS = 1


def new_secret() -> str:
    """A random 160-bit secret, base32 without padding (what apps expect)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _key(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def code_at(secret: str, step: int) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10**DIGITS).zfill(DIGITS)


def verify(secret: str, code: object, last_step: int = 0, now: float | None = None) -> int | None:
    """The time step ``code`` belongs to, or None. Steps at or before ``last_step``
    are refused (a code works only once)."""
    if not isinstance(code, str):
        return None
    code = code.strip().replace(" ", "")
    if len(code) != DIGITS or not code.isascii() or not code.isdigit():
        return None
    current = int((time.time() if now is None else now) // PERIOD)
    for step in range(current - DRIFT_STEPS, current + DRIFT_STEPS + 1):
        if step > last_step and hmac.compare_digest(code_at(secret, step), code):
            return step
    return None


def provisioning_uri(secret: str, account: str, issuer: str) -> str:
    """The otpauth:// link inside the QR code."""
    label = quote(f"{issuer}:{account}", safe="")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer, safe='')}"
            f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}")


def qr_svg_data_uri(uri: str) -> str:
    """The QR code as an SVG data: URI (allowed by the CSP's img-src 'self' data:)."""
    import segno
    return segno.make(uri, error="m").svg_data_uri(scale=5, border=2, dark="#0e1422", light="#ffffff")
