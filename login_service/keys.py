"""Keys: the ID-token signing key (RS256, published as JWKS) and the box that
encrypts 2FA secrets at rest.

Signing keys live in ``<data_dir>/keys/``: ``signing-key.pem`` signs new tokens;
older ``*.pem`` files there are still published (JWKS) so tokens they signed keep
verifying while apps refresh. Rotate: move signing-key.pem to e.g.
``2026-11.pem`` and restart (a new key is generated); delete the old file a
day later.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _int_b64(n: int) -> str:
    return b64url(n.to_bytes((n.bit_length() + 7) // 8, "big"))


@dataclass(frozen=True)
class SigningKey:
    kid: str
    private: rsa.RSAPrivateKey

    @property
    def jwk(self) -> dict[str, str]:
        pub = self.private.public_key().public_numbers()
        return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid, "n": _int_b64(pub.n), "e": _int_b64(pub.e)}


def _kid(key: rsa.RSAPrivateKey) -> str:
    """RFC 7638 thumbprint of the public key."""
    pub = key.public_key().public_numbers()
    canon = json.dumps({"e": _int_b64(pub.e), "kty": "RSA", "n": _int_b64(pub.n)}, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canon.encode()).digest())


class KeyRing:
    def __init__(self, directory: str):
        self.dir = directory
        os.makedirs(directory, mode=0o700, exist_ok=True)
        current = os.path.join(directory, "signing-key.pem")
        if not os.path.exists(current):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
            fd = os.open(current, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(pem)
        self.current = self._load(current)
        self.published = [self.current] + [
            self._load(os.path.join(directory, n)) for n in sorted(os.listdir(directory))
            if n.endswith(".pem") and n != "signing-key.pem"]

    @staticmethod
    def _load(path: str) -> SigningKey:
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError(f"{path}: not an RSA key")
        return SigningKey(_kid(key), key)

    def jwks(self) -> dict[str, Any]:
        return {"keys": [k.jwk for k in self.published]}

    def sign(self, claims: dict[str, Any], typ: str = "JWT") -> str:
        header = {"alg": "RS256", "typ": typ, "kid": self.current.kid}
        signing_input = (b64url(json.dumps(header, separators=(",", ":")).encode()) + "."
                         + b64url(json.dumps(claims, separators=(",", ":")).encode()))
        sig = self.current.private.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        return signing_input + "." + b64url(sig)

    def verify(self, token: str, *, issuer: str, audience: str | None = None, leeway: int = 60) -> dict[str, Any]:
        """Verify a token WE signed (id_token_hint): signature, issuer, audience, expiry. Raises ValueError."""
        try:
            head_b64, body_b64, sig_b64 = token.split(".")
            header = json.loads(b64url_decode(head_b64))
            claims = json.loads(b64url_decode(body_b64))
        except (ValueError, TypeError):
            raise ValueError("malformed token") from None
        if not isinstance(header, dict) or header.get("alg") != "RS256" or not isinstance(claims, dict):
            raise ValueError("unexpected token")
        key = next((k for k in self.published if k.kid == header.get("kid")), None)
        if key is None:
            raise ValueError("unknown key")
        try:
            key.private.public_key().verify(b64url_decode(sig_b64), f"{head_b64}.{body_b64}".encode("ascii"),
                                            padding.PKCS1v15(), hashes.SHA256())
        except Exception:
            raise ValueError("bad signature") from None
        if claims.get("iss") != issuer:
            raise ValueError("wrong issuer")
        if audience is not None and claims.get("aud") != audience:
            raise ValueError("wrong audience")
        exp = claims.get("exp")
        if not isinstance(exp, int) or exp + leeway < time.time():
            raise ValueError("expired")
        return claims


class SecretBox:
    """Encrypts 2FA secrets in the database (Fernet: AES-128-CBC + HMAC-SHA256),
    with a key derived from SECRET_KEY. Set SECRET_KEY in the vault so a copy of
    the database alone doesn't reveal anyone's authenticator secret."""

    def __init__(self, secret_key: str):
        raw = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"login-service totp v1",
                   info=b"totp-secret-box").derive(secret_key.encode("utf-8"))
        self._fernet = Fernet(base64.urlsafe_b64encode(raw))

    def seal(self, text: str) -> str:
        return self._fernet.encrypt(text.encode("utf-8")).decode("ascii")

    def open(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError):
            raise ValueError("cannot decrypt 2FA secret (SECRET_KEY changed?)") from None
