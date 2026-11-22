"""OpenID Connect provider: registered apps (clients), authorization codes,
tokens and back-channel logout.

Only what the apps need, and strict:
- response_type=code only, with PKCE (S256) REQUIRED, a nonce REQUIRED and
  scope "openid" (+ "profile": preferred_username and name). Users have usernames,
  no e-mail addresses.
- redirect_uri must EXACTLY match one registered for the client.
- codes are 256-bit random, stored hashed, valid ``code_seconds`` and usable once.
- clients authenticate at the token endpoint with their secret
  (client_secret_basic or client_secret_post); only the SHA-256 is stored.
- ID tokens are RS256-signed (keys.KeyRing), published at /jwks.json.
- No refresh tokens: an app's own session lasts as long as it decides; it
  sends the user back here when it wants a fresh sign-in.
- Back-channel logout: when a sign-in ends here (sign out, blocked, reset,
  deleted), each app it was used for gets a signed logout_token.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import logging
import re
import secrets
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any

from .compare import same_secret
from .db import Database
from .keys import KeyRing

log = logging.getLogger("login_service")

SCOPES = ("openid", "profile")
MAX_URIS = 10
CLIENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]\Z")
PKCE_RE = re.compile(r"^[A-Za-z0-9_-]{43}\Z")                  # S256 challenge: base64url of 32 bytes
VERIFIER_RE = re.compile(r"^[A-Za-z0-9._~-]{43,128}\Z")
NONCE_MAX = 255
STATE_MAX = 512
BACKCHANNEL_EVENT = "http://schemas.openid.net/event/backchannel-logout"


class AuthorizeError(Exception):
    """``redirect``: the error may go back to the app (client and redirect_uri are valid);
    otherwise it is shown here (never redirect to an unchecked address)."""

    def __init__(self, error: str, description: str, redirect: str | None = None, state: str | None = None):
        super().__init__(error)
        self.error, self.description, self.redirect, self.state = error, description, redirect, state

    def redirect_url(self, issuer: str) -> str:
        assert self.redirect
        q = {"error": self.error, "error_description": self.description, "iss": issuer}
        if self.state is not None:
            q["state"] = self.state
        return _append_query(self.redirect, q)


class TokenError(Exception):
    def __init__(self, error: str, status: int = 400):
        super().__init__(error)
        self.error, self.status = error, status


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _append_query(uri: str, params: dict[str, str]) -> str:
    sep = "&" if urllib.parse.urlsplit(uri).query else "?"
    return uri + sep + urllib.parse.urlencode(params)


HOST_RE = re.compile(r"^(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\Z")


def valid_uri(uri: object, allow_http_local: bool) -> bool:
    """A redirect/logout/back-channel address an admin may register: https (or http on
    localhost outside production), a plain DNS name or IP address as host (no "*":
    the origins also go into the CSP's form-action), no fragment, no credentials."""
    if not isinstance(uri, str) or not 0 < len(uri) <= 500 or any(c in uri for c in " \t\r\n<>\"'\\;,*"):
        return False
    if any(ord(c) < 33 or ord(c) > 126 for c in uri):
        return False
    p = urllib.parse.urlsplit(uri)
    try:
        _ = p.port                               # raises on a bad port
    except ValueError:
        return False
    if p.fragment or p.username or p.password or not p.hostname or not HOST_RE.match(p.hostname):
        return False
    if p.scheme == "https":
        return True
    return allow_http_local and p.scheme == "http" and p.hostname in ("localhost", "127.0.0.1")


def origin(uri: str) -> str:
    p = urllib.parse.urlsplit(uri)
    return f"{p.scheme}://{p.netloc}"


class Provider:
    def __init__(self, db: Database, keys: KeyRing, settings_fn):
        self._deliver_lock = threading.Lock()
        self.db = db
        self.keys = keys
        self._settings = settings_fn

    @property
    def issuer(self) -> str:
        return self._settings().issuer

    # ---- clients ----
    def clients(self) -> list[dict]:
        out = []
        for r in self.db.all("SELECT client_id, name, redirect_uris, logout_uris, backchannel_uri, created FROM clients ORDER BY name"):
            d = dict(r)
            d["redirect_uris"] = json.loads(d["redirect_uris"])
            d["logout_uris"] = json.loads(d["logout_uris"])
            out.append(d)
        return out

    def client(self, client_id: object) -> dict | None:
        if not isinstance(client_id, str) or not CLIENT_ID_RE.match(client_id):
            return None
        row = self.db.one("SELECT * FROM clients WHERE client_id = ?", (client_id,))
        if row is None:
            return None
        d = dict(row)
        d["redirect_uris"] = json.loads(d["redirect_uris"])
        d["logout_uris"] = json.loads(d["logout_uris"])
        return d

    def save_client(self, client_id: str, name: str, redirect_uris: list[str], logout_uris: list[str],
                    backchannel_uri: str) -> str | None:
        """Create (returns the new secret, shown once) or update (returns None) a client."""
        args = (name[:80], json.dumps(redirect_uris), json.dumps(logout_uris), backchannel_uri)
        if self.client(client_id):
            self.db.execute("UPDATE clients SET name = ?, redirect_uris = ?, logout_uris = ?, backchannel_uri = ? "
                            "WHERE client_id = ?", (*args, client_id))
            return None
        secret = secrets.token_urlsafe(32)
        self.db.execute("INSERT INTO clients (client_id, name, redirect_uris, logout_uris, backchannel_uri, secret_hash, created) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)", (client_id, *args, _sha256(secret), int(time.time())))
        return secret

    def rotate_secret(self, client_id: str) -> str | None:
        secret = secrets.token_urlsafe(32)
        n = self.db.execute("UPDATE clients SET secret_hash = ? WHERE client_id = ?", (_sha256(secret), client_id))
        return secret if n == 1 else None

    def delete_client(self, client_id: str) -> bool:
        self.db.execute("DELETE FROM session_clients WHERE client_id = ?", (client_id,))
        self.db.execute("DELETE FROM access_tokens WHERE client_id = ?", (client_id,))
        return self.db.execute("DELETE FROM clients WHERE client_id = ?", (client_id,)) == 1

    def form_targets(self) -> str:
        """Origins of every registered redirect URI (for the CSP's form-action)."""
        origins = {origin(u) for c in self.clients() for u in c["redirect_uris"] + c["logout_uris"]}
        return " ".join(sorted(origins))

    # ---- /authorize ----
    def check_authorize(self, args: dict[str, str]) -> dict[str, Any]:
        """Validate an authorization request; the cleaned request or AuthorizeError."""
        client = self.client(args.get("client_id"))
        if client is None:
            raise AuthorizeError("invalid_client", "Unknown application.")
        redirect = args.get("redirect_uri", "")
        if not isinstance(redirect, str) or redirect not in client["redirect_uris"]:
            raise AuthorizeError("invalid_redirect_uri", "This return address is not registered for the application.")
        state = args.get("state")
        if state is not None and (not isinstance(state, str) or len(state) > STATE_MAX):
            raise AuthorizeError("invalid_request", "Bad state.")

        def fail(error: str, description: str):
            return AuthorizeError(error, description, redirect=redirect, state=state)

        if args.get("response_type") != "code":
            raise fail("unsupported_response_type", "Only response_type=code is supported.")
        scopes = (args.get("scope") or "").split()
        if "openid" not in scopes or any(s not in SCOPES for s in scopes):
            raise fail("invalid_scope", "scope must contain openid and only openid, profile.")
        if args.get("code_challenge_method") != "S256" or not PKCE_RE.match(args.get("code_challenge") or ""):
            raise fail("invalid_request", "PKCE with code_challenge_method=S256 is required.")
        nonce = args.get("nonce") or ""
        if not 0 < len(nonce) <= NONCE_MAX:
            raise fail("invalid_request", "A nonce is required.")
        if args.get("prompt") == "none":
            pass   # handled by the route (login_required when there is no session)
        return {"client": client, "redirect_uri": redirect, "state": state, "scope": " ".join(dict.fromkeys(scopes)),
                "challenge": args["code_challenge"], "nonce": nonce, "prompt": args.get("prompt", "")}

    def issue_code(self, req: dict[str, Any], user_id: str, sid: str, auth_time: int, amr: str) -> str:
        code = secrets.token_urlsafe(32)
        self.db.execute("INSERT INTO codes (code_hash, client_id, user_id, sid, redirect_uri, challenge, nonce, scope, "
                        "auth_time, amr, expires) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (_sha256(code), req["client"]["client_id"], user_id, sid, req["redirect_uri"], req["challenge"],
                         req["nonce"], req["scope"], auth_time, amr, int(time.time()) + self._settings().code_seconds))
        return _append_query(req["redirect_uri"], {k: v for k, v in
                                                   (("code", code), ("state", req["state"]), ("iss", self.issuer)) if v is not None})

    # ---- /token ----
    def authenticate_client(self, auth_header: str | None, form: dict[str, str]) -> dict:
        client_id = secret = None
        if auth_header and auth_header.startswith("Basic "):
            try:
                raw = base64.b64decode(auth_header[6:], validate=True).decode("utf-8")
                cid, _, sec = raw.partition(":")
                client_id, secret = urllib.parse.unquote(cid), urllib.parse.unquote(sec)
            except (ValueError, UnicodeDecodeError):
                raise TokenError("invalid_client", 401) from None
        else:
            client_id, secret = form.get("client_id"), form.get("client_secret")
        client = self.client(client_id)
        if client is None or not isinstance(secret, str) or not same_secret(_sha256(secret), client["secret_hash"]):
            raise TokenError("invalid_client", 401)
        return client

    def exchange(self, client: dict, form: dict[str, str], user_lookup) -> dict[str, Any]:
        if form.get("grant_type") != "authorization_code":
            raise TokenError("unsupported_grant_type")
        code, verifier = form.get("code") or "", form.get("code_verifier") or ""
        if not code or len(code) > 100 or not VERIFIER_RE.match(verifier):
            raise TokenError("invalid_grant")
        now = int(time.time())
        with self.db.transaction() as c:      # read and delete together: a code works exactly once
            row = c.execute("SELECT * FROM codes WHERE code_hash = ?", (_sha256(code),)).fetchone()
            if row is not None:
                c.execute("DELETE FROM codes WHERE code_hash = ?", (_sha256(code),))
        if row is None or row["expires"] < now or row["client_id"] != client["client_id"] \
                or row["redirect_uri"] != form.get("redirect_uri"):
            raise TokenError("invalid_grant")
        expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
        if not same_secret(expected, row["challenge"]):
            raise TokenError("invalid_grant")
        user = user_lookup(row["user_id"])
        sess = self.db.one("SELECT 1 FROM sessions WHERE sid = ?", (row["sid"],))
        if user is None or user["disabled"] or sess is None:   # signed out or blocked since the code was issued
            raise TokenError("invalid_grant")
        st = self._settings()
        scopes = row["scope"].split()
        claims: dict[str, Any] = {
            "iss": self.issuer, "sub": user["id"], "aud": client["client_id"], "azp": client["client_id"],
            "iat": now, "exp": now + st.id_token_seconds, "auth_time": row["auth_time"], "nonce": row["nonce"],
            "sid": row["sid"], "amr": row["amr"].split(),
        }
        if "profile" in scopes:
            claims.update(preferred_username=user["username"], name=user["name"])
        access = secrets.token_urlsafe(32)
        self.db.execute("INSERT INTO access_tokens (token_hash, sid, user_id, client_id, scope, expires) VALUES (?, ?, ?, ?, ?, ?)",
                        (_sha256(access), row["sid"], user["id"], client["client_id"], row["scope"], now + st.access_token_seconds))
        self.db.execute("INSERT OR IGNORE INTO session_clients (sid, client_id) VALUES (?, ?)", (row["sid"], client["client_id"]))
        return {"access_token": access, "token_type": "Bearer", "expires_in": st.access_token_seconds,
                "scope": row["scope"], "id_token": self.keys.sign(claims)}

    def userinfo(self, token: str, user_lookup) -> dict[str, Any] | None:
        row = self.db.one("SELECT * FROM access_tokens WHERE token_hash = ? AND expires > ?", (_sha256(token), int(time.time())))
        user = user_lookup(row["user_id"]) if row else None
        if row is None or user is None or user["disabled"]:
            return None
        out: dict[str, Any] = {"sub": user["id"]}
        if "profile" in row["scope"].split():
            out.update(preferred_username=user["username"], name=user["name"])
        return out

    # ---- logout ----
    def end_sessions(self, sids: list[str], user_id: str, everywhere: bool) -> None:
        """Sign-ins ended here: revoke their access tokens and queue logout notices.
        ``everywhere`` (blocked, reset, deleted, sign out everywhere): EVERY app with a
        back-channel address gets a notice by user (no sid), so the app ends all of that
        user's sign-ins - also ones whose session here already expired or was replaced."""
        now = int(time.time())
        rows: set[tuple[str, str]] = set()
        for sid in sids:
            self.db.execute("DELETE FROM access_tokens WHERE sid = ?", (sid,))
            if not everywhere:
                for r in self.db.all("SELECT client_id FROM session_clients WHERE sid = ?", (sid,)):
                    rows.add((r["client_id"], sid))
            self.db.execute("DELETE FROM session_clients WHERE sid = ?", (sid,))
        if everywhere:
            self.db.execute("DELETE FROM access_tokens WHERE user_id = ?", (user_id,))
            for app in self.clients():
                rows.add((app["client_id"], ""))
        for client_id, sid in rows:
            target = self.client(client_id)
            if target and target["backchannel_uri"]:
                self.db.execute("INSERT INTO backchannel_outbox (client_id, user_id, sid, next_try, created) "
                                "VALUES (?, ?, ?, ?, ?)", (client_id, user_id, sid, now, now))

    def logout_token(self, client: dict, user_id: str, sid: str) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {"iss": self.issuer, "aud": client["client_id"], "iat": now, "exp": now + 120,
                                  "jti": str(uuid.uuid4()), "sub": user_id, "events": {BACKCHANNEL_EVENT: {}}}
        if sid:
            claims["sid"] = sid
        return self.keys.sign(claims, typ="logout+jwt")

    MAX_ATTEMPTS = 10

    def deliver(self) -> int:
        """Send due logout notices (fresh token per attempt); failures are retried with
        back-off (30 s, 1 min, 2 min, ... at most 1 h) up to MAX_ATTEMPTS. Returns how many
        were delivered. Called right after queueing (in a thread) and by the cleanup job."""
        if not self._deliver_lock.acquire(blocking=False):
            return 0
        delivered = 0
        try:
            now = int(time.time())
            due = self.db.all("SELECT * FROM backchannel_outbox WHERE next_try <= ? AND attempts < ? ORDER BY id",
                              (now, self.MAX_ATTEMPTS))
            for row in due:
                c = self.client(row["client_id"])
                if c is None or not c["backchannel_uri"]:
                    self.db.execute("DELETE FROM backchannel_outbox WHERE id = ?", (row["id"],))
                    continue
                error = self._post(c["backchannel_uri"], self.logout_token(c, row["user_id"], row["sid"]))
                if error is None:
                    self.db.execute("DELETE FROM backchannel_outbox WHERE id = ?", (row["id"],))
                    delivered += 1
                else:
                    attempts = row["attempts"] + 1
                    self.db.execute("UPDATE backchannel_outbox SET attempts = ?, next_try = ?, last_error = ? WHERE id = ?",
                                    (attempts, now + min(3600, 30 * 2 ** (attempts - 1)), error[:200], row["id"]))
                    log.warning("back-channel logout to %s failed (attempt %d): %s", origin(c["backchannel_uri"]),
                                attempts, error)
        finally:
            self._deliver_lock.release()
        return delivered

    def notify_now(self, background: bool) -> None:
        if background:
            threading.Thread(target=self.deliver, name="backchannel", daemon=True).start()
        else:
            self.deliver()

    def outbox_status(self) -> dict[str, dict[str, Any]]:
        """Per app: notices still waiting and notices that gave up (for the admin panel)."""
        out: dict[str, dict[str, Any]] = {}
        for r in self.db.all("SELECT client_id, attempts >= ? AS failed, COUNT(*) AS n, MAX(last_error) AS err "
                             "FROM backchannel_outbox GROUP BY client_id, failed", (self.MAX_ATTEMPTS,)):
            d = out.setdefault(r["client_id"], {"pending": 0, "failed": 0, "error": ""})
            d["failed" if r["failed"] else "pending"] += r["n"]
            d["error"] = r["err"] or d["error"]
        return out

    def _post(self, uri: str, token: str) -> str | None:
        """POST a logout token; None on success, else a short reason."""
        if self._settings().app_env == "production" and not _public_host(urllib.parse.urlsplit(uri).hostname or ""):
            return "refused: internal address"
        opener = urllib.request.build_opener(_NoRedirects, urllib.request.ProxyHandler({}))
        data = urllib.parse.urlencode({"logout_token": token}).encode("ascii")
        req = urllib.request.Request(uri, data=data, method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with opener.open(req, timeout=5) as resp:
                resp.read(1024)
                return None if 200 <= resp.status < 300 else f"HTTP {resp.status}"
        except urllib.error.HTTPError as exc:
            return f"HTTP {exc.code}"
        except (urllib.error.URLError, OSError) as exc:
            return type(exc).__name__

    def prune(self) -> None:
        now = int(time.time())
        self.db.execute("DELETE FROM backchannel_outbox WHERE attempts >= ? AND created < ?", (self.MAX_ATTEMPTS, now - 7 * 86400))
        self.db.execute("DELETE FROM codes WHERE expires < ?", (now,))
        self.db.execute("DELETE FROM access_tokens WHERE expires < ?", (now,))
        self.db.execute("DELETE FROM session_clients WHERE sid NOT IN (SELECT sid FROM sessions)")


def _public_host(host: str) -> bool:
    """Production: back-channel notices only go to public addresses (no internal hosts,
    loopback, link-local or cloud metadata): checked on every resolved address."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_multicast:
            return False
    return bool(infos)


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
