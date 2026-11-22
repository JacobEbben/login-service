"""Comparing secrets (CSRF tokens, OAuth state and nonce, fingerprints).

``hmac.compare_digest`` takes constant time, but given two ``str`` values it
only accepts ASCII and raises TypeError otherwise: a client sending "é" as a
token turned the request into a 500 (and an error-log entry). Comparing the
UTF-8 bytes avoids that; anything that is not text simply doesn't match.
"""

from __future__ import annotations

import hmac


def same_secret(sent: object, expected: object) -> bool:
    """Constant-time equality of two non-empty strings; False for anything else."""
    if not isinstance(sent, str) or not isinstance(expected, str) or not expected:
        return False
    return hmac.compare_digest(sent.encode("utf-8"), expected.encode("utf-8"))
