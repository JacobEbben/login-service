"""Accounts, passwords, invitations, 2FA and single sign-on sessions.

- Accounts are made by an admin (or the first admin from the command line:
  ``python -m login_service.admin``). There is no self sign-up.
- A new account gets a one-time **invitation link** to choose a password; a lost
  password or authenticator is handled the same way (the admin issues a reset
  link, which also clears 2FA and ends every sign-in). Only the SHA-256 of the
  token is stored.
- Passwords: werkzeug scrypt hashes, at least 12 characters.
- 2FA: an authenticator app (TOTP), set up by the user in their account
  settings; the secret is stored encrypted (``keys.SecretBox``).
- A sign-in is a random ``sid`` in the signed session cookie AND a row in
  ``sessions`` (signing out deletes it, so a copied cookie stops working).
  Rights (admin, disabled) are re-read on every request.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from flask import g, session
from werkzeug.security import check_password_hash, generate_password_hash

from . import totp
from .db import Database
from .keys import SecretBox
from .security import csrf_token

if TYPE_CHECKING:
    from .config import Settings

# Usernames: 3-32 characters, lower case letters, digits and . _ - ; starting and ending with a letter or digit.
USERNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{1,30})[a-z0-9]\Z")
MIN_PASSWORD = 12
MAX_PASSWORD = 1024
MAX_SESSIONS_PER_USER = 20
MAX_NAME = 80
# Spends the same time as a real check when the username is unknown, so the
# answer time doesn't tell whether an account exists.
_DUMMY_HASH = generate_password_hash("not-a-real-password-just-for-timing")


def normalize_username(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    name = value.strip().lower()
    return name if USERNAME_RE.match(name) else None


def clean_name(value: object) -> str:
    return " ".join(str(value or "").split())[:MAX_NAME]


def password_problem(password: object, username: str = "") -> str | None:
    """Why a new password is refused (an i18n key), or None."""
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        return "pwTooShort"
    if len(password) > MAX_PASSWORD:
        return "pwTooLong"
    if username and username in password.strip().lower():
        return "pwHasUsername"
    if len(set(password)) < 5:
        return "pwTooSimple"
    return None


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class User:
    id: str
    username: str
    name: str
    admin: bool
    has_2fa: bool
    amr: str                 # how this session signed in: "pwd" or "pwd otp"


class Users:
    def __init__(self, db: Database, settings: Callable[[], Settings], box: SecretBox):
        self.db = db
        self._settings = settings
        self.box = box

    # ---- accounts ----
    def create(self, username: str, name: str = "", admin: bool = False) -> tuple[str, str]:
        """A new account with an invitation; returns (user id, invitation token)."""
        uid = str(uuid.uuid4())
        self.db.execute("INSERT INTO users (id, username, name, is_admin, created) VALUES (?, ?, ?, ?, ?)",
                        (uid, username, clean_name(name), int(admin), int(time.time())))
        return uid, self.new_invite(uid)

    def get(self, uid: str) -> dict | None:
        row = self.db.one("SELECT * FROM users WHERE id = ?", (uid,))
        return dict(row) if row else None

    def by_username(self, username: str) -> dict | None:
        row = self.db.one("SELECT * FROM users WHERE username = ?", (username,))
        return dict(row) if row else None

    def overview(self) -> list[dict]:
        rows = self.db.all("SELECT u.id, u.username, u.name, u.is_admin, u.disabled, u.created, u.last_login, "
                           "u.password_hash != '' AS active, u.totp_secret != '' AS has_2fa, "
                           "u.invite_expires, (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id) AS sessions "
                           "FROM users u ORDER BY u.username")
        return [dict(r) for r in rows]

    def admin_count(self) -> int:
        row = self.db.one("SELECT COUNT(*) AS n FROM users WHERE is_admin = 1 AND disabled = 0")
        return int(row["n"]) if row else 0

    def is_last_admin(self, uid: str) -> bool:
        u = self.get(uid)
        return bool(u and u["is_admin"] and not u["disabled"] and self.admin_count() <= 1)

    # The last active admin can't lose admin rights: check and change in ONE transaction,
    # so two admins demoting each other at the same moment can't leave none.
    _OTHER_ADMINS = "SELECT COUNT(*) FROM users WHERE is_admin = 1 AND disabled = 0 AND id != ?"

    def _guarded(self, uid: str, sql: str, params: tuple, removes_admin: bool) -> bool:
        with self.db.transaction() as c:
            row = c.execute("SELECT is_admin, disabled FROM users WHERE id = ?", (uid,)).fetchone()
            if row is None:
                return False
            if removes_admin and row["is_admin"] and not row["disabled"] \
                    and c.execute(self._OTHER_ADMINS, (uid,)).fetchone()[0] == 0:
                return False
            c.execute(sql, params)
        return True

    def set_admin(self, uid: str, admin: bool) -> bool:
        return self._guarded(uid, "UPDATE users SET is_admin = ? WHERE id = ?", (int(admin), uid), removes_admin=not admin)

    def set_disabled(self, uid: str, disabled: bool) -> bool:
        ok = self._guarded(uid, "UPDATE users SET disabled = ? WHERE id = ?", (int(disabled), uid), removes_admin=disabled)
        if ok and disabled:
            self.end_all(uid)
        return ok

    def delete(self, uid: str) -> bool:
        ok = self._guarded(uid, "DELETE FROM users WHERE id = ?", (uid,), removes_admin=True)
        if ok:
            self.db.execute("DELETE FROM sessions WHERE user_id = ?", (uid,))
        return ok

    def set_name(self, uid: str, name: str) -> None:
        self.db.execute("UPDATE users SET name = ? WHERE id = ?", (clean_name(name), uid))

    # ---- invitations and resets ----
    def new_invite(self, uid: str) -> str:
        token = secrets.token_urlsafe(32)
        expires = int(time.time()) + self._settings().invite_hours * 3600
        self.db.execute("UPDATE users SET invite_hash = ?, invite_expires = ? WHERE id = ?",
                        (_hash_token(token), expires, uid))
        return token

    def reset(self, uid: str) -> str:
        """Lost password or authenticator: clear both, end every sign-in, new invitation link."""
        self.db.execute("UPDATE users SET password_hash = '', totp_secret = '', totp_last_step = 0 WHERE id = ?", (uid,))
        self.end_all(uid)
        return self.new_invite(uid)

    def invited(self, token: object) -> dict | None:
        if not isinstance(token, str) or not 20 <= len(token) <= 100:
            return None
        row = self.db.one("SELECT * FROM users WHERE invite_hash = ? AND invite_expires > ? AND disabled = 0",
                          (_hash_token(token), int(time.time())))
        return dict(row) if row else None

    def accept_invite(self, token: str, password: str) -> dict | None:
        """Set the password from an invitation; the token works once."""
        with self.db.transaction() as c:
            row = c.execute("SELECT * FROM users WHERE invite_hash = ? AND invite_expires > ? AND disabled = 0",
                            (_hash_token(token), int(time.time()))).fetchone()
            if row is None:
                return None
            c.execute("UPDATE users SET password_hash = ?, invite_hash = '', invite_expires = 0 WHERE id = ?",
                      (generate_password_hash(password), row["id"]))
        return dict(row)

    # ---- passwords ----
    def check_password(self, username: str, password: str) -> dict | None:
        """The account if the password is right (and the account active), else None.
        Always spends one password-hash check."""
        user = self.by_username(username)
        stored = user["password_hash"] if user and user["password_hash"] else _DUMMY_HASH
        ok = 0 < len(password) <= MAX_PASSWORD and check_password_hash(stored, password)
        if not ok or user is None or not user["password_hash"] or user["disabled"]:
            return None
        return user

    def change_password(self, uid: str, new: str, keep_sid: str | None) -> None:
        """New password; every OTHER sign-in ends."""
        self.db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new), uid))
        self.db.execute("DELETE FROM sessions WHERE user_id = ? AND sid != ?", (uid, keep_sid or ""))

    # ---- 2FA ----
    def totp_check(self, user: dict, code: object) -> bool:
        """Check an authenticator code; each code (time step) works once."""
        if not user["totp_secret"]:
            return False
        secret = self.box.open(user["totp_secret"])
        with self.db.transaction() as c:
            row = c.execute("SELECT totp_last_step FROM users WHERE id = ?", (user["id"],)).fetchone()
            step = totp.verify(secret, code, last_step=row["totp_last_step"] if row else 0)
            if step is None:
                return False
            c.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, user["id"]))
        return True

    def enable_2fa(self, uid: str, secret: str, code: object, only_if_unset: bool = False) -> bool:
        """Turn 2FA on after the user proved their app works (a valid code for ``secret``).
        ``only_if_unset``: never replace an existing secret (two setups racing)."""
        step = totp.verify(secret, code)
        if step is None:
            return False
        extra = " AND totp_secret = ''" if only_if_unset else ""
        n = self.db.execute("UPDATE users SET totp_secret = ?, totp_last_step = ? WHERE id = ?" + extra,
                            (self.box.seal(secret), step, uid))
        return n == 1

    def disable_2fa(self, uid: str) -> None:
        self.db.execute("UPDATE users SET totp_secret = '', totp_last_step = 0 WHERE id = ?", (uid,))

    # ---- sign-ins ----
    def begin(self, uid: str, amr: str) -> str:
        """Sign in: a fresh session (new sid and CSRF token; nothing of the old one is kept)."""
        old = session.get("sid")
        if isinstance(old, str):
            self.db.execute("DELETE FROM sessions WHERE sid = ?", (old,))
        old_pw = session.get("pw_sid")
        if isinstance(old_pw, str):
            self.db.execute("DELETE FROM pw_sessions WHERE sid = ?", (old_pw,))
        lang = session.get("lang")
        session.clear()
        sid = secrets.token_urlsafe(32)
        now = int(time.time())
        with self.db.transaction() as c:
            c.execute("INSERT INTO sessions (sid, user_id, created, amr) VALUES (?, ?, ?, ?)", (sid, uid, now, amr))
            c.execute("DELETE FROM sessions WHERE user_id = ? AND sid NOT IN "
                      "(SELECT sid FROM sessions WHERE user_id = ? ORDER BY created DESC LIMIT ?)",
                      (uid, uid, MAX_SESSIONS_PER_USER))
            c.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, uid))
        session["sid"] = sid
        if lang:
            session["lang"] = lang
        session.permanent = True
        csrf_token()
        g.pop("user", None)
        return sid

    def end(self) -> str | None:
        """Sign out this browser; returns the ended sid (for back-channel logout)."""
        sid = session.get("sid")
        if isinstance(sid, str):
            self.db.execute("DELETE FROM sessions WHERE sid = ?", (sid,))
        session.clear()
        g.pop("user", None)
        return sid if isinstance(sid, str) else None

    def end_all(self, uid: str) -> list[str]:
        """End every sign-in of ``uid``; returns their sids."""
        sids = [r["sid"] for r in self.db.all("SELECT sid FROM sessions WHERE user_id = ?", (uid,))]
        self.db.execute("DELETE FROM sessions WHERE user_id = ?", (uid,))
        return sids

    def session_count(self, uid: str) -> int:
        row = self.db.one("SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?", (uid,))
        return int(row["n"]) if row else 0

    def current(self) -> User | None:
        if "user" in g:
            return g.user
        user = None
        sid = session.get("sid")
        if isinstance(sid, str) and sid:
            row = self.db.one("SELECT s.created, s.amr, u.* FROM sessions s JOIN users u ON u.id = s.user_id "
                              "WHERE s.sid = ?", (sid,))
            max_age = self._settings().session_hours * 3600
            if row is not None and row["created"] + max_age > time.time() and not row["disabled"]:
                user = User(id=row["id"], username=row["username"], name=row["name"], admin=bool(row["is_admin"]),
                            has_2fa=bool(row["totp_secret"]), amr=row["amr"])
            elif row is not None:
                self.db.execute("DELETE FROM sessions WHERE sid = ?", (sid,))
        g.user = user
        return user

    def session_auth_time(self) -> int:
        sid = session.get("sid")
        row = self.db.one("SELECT created FROM sessions WHERE sid = ?", (sid,)) if isinstance(sid, str) else None
        return int(row["created"]) if row else int(time.time())

    def prune(self) -> None:
        cutoff = int(time.time()) - self._settings().session_hours * 3600
        self.db.execute("DELETE FROM sessions WHERE created < ?", (cutoff,))
