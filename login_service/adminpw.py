"""The admin password (like AH Dashboard and File Share): the way in to create the
first accounts and apps, and the emergency way in.

ADMIN_PASSWORD_HASH holds only a hash (``python -m login_service.admin password``).
Signing in with it opens a session of its own: it is NOT a user, so it can't sign in
to apps and has no 2FA; it can only use the admin panel. Because it is a single
factor, its limits are tighter than a user's: ADMIN_SESSION_MINUTES idle (30),
ADMIN_SESSION_MAX_HOURS in total (4), the same lockouts as signing in, and a keyed
fingerprint of the hash in the session (changing or removing the password ends
every such session). Remove the hash once the first admin accounts exist.

The session is a random ``pw_sid`` in the cookie AND a row in ``pw_sessions``:
signing out deletes the row, so a copied cookie stops working.
"""

from __future__ import annotations

import hmac
import secrets
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

from flask import session

from .compare import same_secret
from .db import Database
from .security import csrf_token

if TYPE_CHECKING:
    from .config import Settings

MIN_LENGTH = 16
LABEL = "(admin password)"
_SID, _STARTED, _SEEN, _FP = "pw_sid", "pw_at", "pw_seen", "pw_fp"
_TOUCH_EVERY = 60


class AdminPassword:
    def __init__(self, db: Database, settings: Callable[[], Settings], key: bytes):
        self.db = db
        self._settings = settings
        self._key = key

    def configured(self) -> bool:
        return bool(self._settings().admin_password_hash)

    def _fingerprint(self) -> str:
        h = self._settings().admin_password_hash
        return hmac.new(self._key, ("admin-password:" + h).encode(), "sha256").hexdigest()[:32]

    def begin(self) -> None:
        """A fresh session (nothing of the old one is kept, also no user sign-in)."""
        old = session.get("sid")
        if isinstance(old, str):
            self.db.execute("DELETE FROM sessions WHERE sid = ?", (old,))
        self.end()
        lang = session.get("lang")
        session.clear()
        sid = secrets.token_urlsafe(32)
        self.db.execute("INSERT INTO pw_sessions (sid, created) VALUES (?, ?)", (sid, int(time.time())))
        now = time.time()
        session.update({_SID: sid, _STARTED: now, _SEEN: now, _FP: self._fingerprint()})
        if lang:
            session["lang"] = lang
        session.permanent = True
        csrf_token()

    def active(self) -> bool:
        """This request has a valid admin-password session (and touches its idle timer)."""
        sid, started, seen, fp = (session.get(k) for k in (_SID, _STARTED, _SEEN, _FP))
        if not isinstance(sid, str) or not isinstance(started, (int, float)) or not isinstance(fp, str):
            return False
        st = self._settings()
        if not isinstance(seen, (int, float)) or seen < started:
            seen = started
        now = time.time()
        ok = (self.configured() and same_secret(fp, self._fingerprint())
              and now - seen < st.admin_session_minutes * 60 and now - started < st.admin_session_max_hours * 3600
              and self.db.one("SELECT 1 FROM pw_sessions WHERE sid = ?", (sid,)) is not None)
        if not ok:
            self.end()
            return False
        if now - seen >= _TOUCH_EVERY:
            session[_SEEN] = now
        return True

    def end(self) -> None:
        sid = session.get(_SID)
        if isinstance(sid, str):
            self.db.execute("DELETE FROM pw_sessions WHERE sid = ?", (sid,))
        for k in (_SID, _STARTED, _SEEN, _FP):
            session.pop(k, None)

    def prune(self) -> None:
        cutoff = int(time.time()) - self._settings().admin_session_max_hours * 3600
        self.db.execute("DELETE FROM pw_sessions WHERE created < ?", (cutoff,))
