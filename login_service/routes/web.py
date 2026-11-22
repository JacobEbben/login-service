"""Signing in and out, invitations.

GET/POST /login           e-mail + password
GET/POST /login/2fa       the authenticator code (accounts with 2FA)
GET/POST /login/setup-2fa admins without 2FA must set it up first (REQUIRE_ADMIN_2FA)
GET/POST /invite/<token>  choose a password (new account, or after a reset)
POST     /logout          sign out here and in every app this sign-in was used for
GET      /healthz

Guessing protection (password and code alike): each attempt is counted per
client BEFORE the slow check (atomically); the per-account lock only blocks
clients that already failed recently (so nobody can lock a person out for
everyone); a server-wide cap bounds the rest. The answer never says whether an
account exists.
"""

from __future__ import annotations

import hashlib
import logging
import time
import urllib.parse

from flask import Blueprint, abort, current_app, redirect, render_template, request, session, url_for

from .. import totp
from ..app import services
from ..security import client_key, csrf_ok, password_check_slot
from ..users import normalize_username, password_problem

log = logging.getLogger("login_service")
bp = Blueprint("web", __name__)

PENDING_KEY = "pending"           # signed in with a password, the second step still to do
PENDING_SECONDS = 300
SETUP_KEY = "totp_setup"          # a 2FA secret being set up (not active until confirmed)
NEXT_PREFIXES = ("/authorize?", "/account", "/admin", "/logout?")


def safe_next(value: object) -> str:
    """Only our own pages may be the destination after signing in (no open redirect)."""
    if not isinstance(value, str) or not value.startswith(NEXT_PREFIXES) or len(value) > 4000:
        return url_for("account.index")
    p = urllib.parse.urlsplit(value)
    if p.scheme or p.netloc or "\\" in value or "\r" in value or "\n" in value:
        return url_for("account.index")
    return value


def check_form() -> None:
    if not csrf_ok(request.form.get("csrf", "")):
        abort(400)


def attempt_allowed(account: str, kind: str = "password") -> bool:
    """Count this attempt for the client (before the check) and apply the locks.

    ``kind``: "password" or "adminpw" (a slow scrypt check: a server-wide cap bounds the
    CPU) or "code" (an authenticator code after a correct password: cheap, no global cap).
    The global cap is split: clients that already failed recently share one bucket, clients
    with a clean record another (4x larger). One attacker hammering junk attempts only fills
    the first, so they can't lock out everyone else; filling the clean bucket too takes
    many fresh addresses per minute."""
    s = services()
    st = s.settings
    lim, window, client = s.login_limiter, st.lockout_seconds, client_key()
    had_failures = lim.recent(client, window) > 0
    if not lim.attempt(client, st.max_failures, window):
        return False
    if had_failures and lim.locked("acct:" + account, st.account_max_failures, window):
        return False
    if kind == "code":
        return True
    bucket = f"{kind}-checks" + ("" if had_failures else "-clean")
    cap = st.login_attempts_per_minute * (1 if had_failures else 4)
    return s.limiter.allow(bucket, "*", cap, 60)


def attempt_failed(account: str) -> None:
    s = services()
    s.login_limiter.fail("acct:" + account, s.settings.account_max_failures, s.settings.lockout_seconds)


def attempt_succeeded(account: str) -> None:
    s = services()
    s.login_limiter.reset(client_key())
    s.login_limiter.reset("acct:" + account)


def finish_sign_in(uid: str, amr: str, nxt: str):
    services().users.begin(uid, amr)
    return redirect(safe_next(nxt))


@bp.get("/favicon.ico")
def favicon():
    """For browsers and tools that ask for /favicon.ico directly (the pages link the SVG/PNG)."""
    return current_app.send_static_file("icons/favicon-32.png")


@bp.get("/healthz")
def healthz():
    return {"ok": True}


@bp.get("/")
def index():
    return redirect(url_for("account.index"))


@bp.get("/login")
def login():
    nxt = safe_next(request.args.get("next"))
    if services().users.current() is not None:
        return redirect(nxt)
    return render_template("login.html", next=nxt, error=request.args.get("error", ""))


@bp.post("/login")
def login_post():
    check_form()
    s = services()
    nxt = safe_next(request.form.get("next"))
    username = normalize_username(request.form.get("username")) or ""
    password = request.form.get("password", "")
    if not attempt_allowed(username or "?"):
        log.warning("sign-in locked out for %s", client_key())
        return render_template("login.html", next=nxt, error="locked", username=username), 429
    with password_check_slot():
        user = s.users.check_password(username, password) if username else None
    if user is None:
        attempt_failed(username or "?")
        log.info("failed sign-in for %s from %s", username or "(no username)", client_key())
        return render_template("login.html", next=nxt, error="badLogin", username=username), 401
    if user["totp_secret"]:
        session[PENDING_KEY] = {"uid": user["id"], "at": time.time(), "next": nxt, "step": "2fa", "v": _version(user)}
        return redirect(url_for("web.second_factor"))
    if user["is_admin"] and s.settings.require_admin_2fa:
        session[PENDING_KEY] = {"uid": user["id"], "at": time.time(), "next": nxt, "step": "setup", "v": _version(user)}
        return redirect(url_for("web.setup_second_factor"))
    attempt_succeeded(username)
    log.info("%s signed in from %s", username, client_key())
    return finish_sign_in(user["id"], "pwd", nxt)


def _version(user: dict) -> str:
    """Changes when the password or 2FA changes (reset, password change, 2FA set up):
    a half-finished sign-in started before that can't be completed afterwards."""
    return hashlib.sha256((user["password_hash"] + "|" + user["totp_secret"]).encode()).hexdigest()[:24]


def _pending(step: str) -> dict | None:
    p = session.get(PENDING_KEY)
    if not isinstance(p, dict) or p.get("step") != step or not isinstance(p.get("at"), (int, float)) \
            or time.time() - p["at"] > PENDING_SECONDS:
        return None
    user = services().users.get(str(p.get("uid", "")))
    if not user or user["disabled"] or not user["password_hash"] or p.get("v") != _version(user):
        session.pop(PENDING_KEY, None)
        return None
    if step == "setup" and user["totp_secret"]:       # someone else set it up meanwhile
        session.pop(PENDING_KEY, None)
        return None
    return p


@bp.get("/login/2fa")
def second_factor():
    if _pending("2fa") is None:
        return redirect(url_for("web.login", error="expired"))
    return render_template("login_2fa.html")


@bp.post("/login/2fa")
def second_factor_post():
    check_form()
    s = services()
    p = _pending("2fa")
    if p is None:
        return redirect(url_for("web.login", error="expired"))
    user = s.users.get(p["uid"])
    assert user is not None
    if not attempt_allowed(user["username"], "code"):
        session.pop(PENDING_KEY, None)
        return redirect(url_for("web.login", error="locked"))
    if not s.users.totp_check(user, request.form.get("code", "")):
        attempt_failed(user["username"])
        log.info("wrong authenticator code for %s from %s", user["username"], client_key())
        return render_template("login_2fa.html", error="badCode"), 401
    attempt_succeeded(user["username"])
    log.info("%s signed in with 2FA from %s", user["username"], client_key())
    return finish_sign_in(user["id"], "pwd otp", p["next"])


@bp.get("/login/setup-2fa")
def setup_second_factor():
    p = _pending("setup")
    if p is None:
        return redirect(url_for("web.login", error="expired"))
    user = services().users.get(p["uid"])
    assert user is not None
    secret = session.get(SETUP_KEY) if isinstance(session.get(SETUP_KEY), str) else None
    if not secret:
        secret = session[SETUP_KEY] = totp.new_secret()
    return render_template("setup_2fa.html", forced=True, **_setup_context(secret, user["username"]))


@bp.post("/login/setup-2fa")
def setup_second_factor_post():
    check_form()
    s = services()
    p = _pending("setup")
    secret = session.get(SETUP_KEY)
    if p is None or not isinstance(secret, str):
        return redirect(url_for("web.login", error="expired"))
    user = s.users.get(p["uid"])
    assert user is not None
    if not attempt_allowed(user["username"], "code"):
        session.pop(PENDING_KEY, None)
        return redirect(url_for("web.login", error="locked"))
    if not s.users.enable_2fa(user["id"], secret, request.form.get("code", ""), only_if_unset=True):
        attempt_failed(user["username"])
        return render_template("setup_2fa.html", forced=True, error="badCode",
                               **_setup_context(secret, user["username"])), 400
    attempt_succeeded(user["username"])
    session.pop(SETUP_KEY, None)
    log.info("%s set up 2FA (required for admins)", user["username"])
    return finish_sign_in(user["id"], "pwd otp", p["next"])


def _setup_context(secret: str, username: str) -> dict:
    issuer_name = urllib.parse.urlsplit(services().settings.issuer).hostname or "Login"
    uri = totp.provisioning_uri(secret, username, issuer_name)
    grouped = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    return {"qr": totp.qr_svg_data_uri(uri), "secret_text": grouped}


@bp.post("/logout")
def logout():
    check_form()
    s = services()
    user = s.users.current()
    s.adminpw.end()
    sid = s.users.end()
    if user is not None and sid:
        s.sign_out_sessions([sid], user.id)
    return redirect(url_for("web.login", error="signedOut"))


@bp.get("/invite/<token>")
def invite(token: str):
    user = services().users.invited(token)
    if user is None:
        return render_template("message.html", key="inviteInvalid"), 404
    return render_template("invite.html", token=token, username=user["username"])


@bp.post("/invite/<token>")
def invite_post(token: str):
    check_form()
    s = services()
    if not s.limiter.allow("invite", client_key(), 20, 600):
        abort(429)
    user = s.users.invited(token)
    if user is None:
        return render_template("message.html", key="inviteInvalid"), 404
    password = request.form.get("password", "")
    problem = password_problem(password, user["username"])
    if problem is None and password != request.form.get("password2", ""):
        problem = "pwMismatch"
    if problem:
        return render_template("invite.html", token=token, username=user["username"], error=problem), 400
    if s.users.accept_invite(token, password) is None:
        return render_template("message.html", key="inviteInvalid"), 404
    log.info("%s chose a password (invitation)", user["username"])
    return redirect(url_for("web.login", error="passwordSet"))
