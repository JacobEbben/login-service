"""Command line for the server operator (run inside the container, with the same settings):

    python -m login_service.admin secret-key                    # a SECRET_KEY for the secret store
    python -m login_service.admin password                      # ADMIN_PASSWORD_HASH for /admin/login
    python -m login_service.admin create-admin yourname "Your Name"
    python -m login_service.admin reset yourname

Prints a one-time link (valid INVITE_HOURS) to choose a password. This is how the
first admin is made: there is no default password and no setup page on the internet.
With REQUIRE_ADMIN_2FA the admin sets up an authenticator app at the first sign-in.
"""

from __future__ import annotations

import sqlite3
import sys

from flask import url_for

USAGE = "usage: python -m login_service.admin secret-key | password | create-admin <username> [name] | reset <username>"


def make_hash() -> int:
    import getpass

    from werkzeug.security import generate_password_hash

    from .adminpw import MIN_LENGTH
    password = getpass.getpass("New admin password: ")
    if len(password) < MIN_LENGTH:
        print(f"Use at least {MIN_LENGTH} characters (it is a single factor: make it long).", file=sys.stderr)
        return 1
    if getpass.getpass("Repeat password: ") != password:
        print("Passwords do not match.", file=sys.stderr)
        return 1
    # Single quotes: the hash contains "$", which Docker Compose would otherwise expand.
    print("\nAdd this line to .env (or the secret store) and restart; /admin/login then accepts it:\n")
    print("ADMIN_PASSWORD_HASH='" + generate_password_hash(password) + "'")
    return 0


def main(argv: list[str]) -> int:
    from .app import create_app, services
    from .users import normalize_username

    if argv[:1] == ["password"]:
        return make_hash()
    if argv[:1] == ["secret-key"]:
        import secrets
        print("SECRET_KEY: " + secrets.token_urlsafe(48) + "    # put this in the secret store; never change it afterwards")
        return 0
    if len(argv) < 2 or argv[0] not in ("create-admin", "reset"):
        print(USAGE, file=sys.stderr)
        return 2
    username = normalize_username(argv[1])
    if username is None:
        print("Not a valid username (3-32 characters: a-z, 0-9, . _ -).", file=sys.stderr)
        return 1
    app = create_app()
    s = services(app)
    with app.test_request_context(base_url=s.settings.issuer or "http://localhost"):
        if argv[0] == "create-admin":
            try:
                _, token = s.users.create(username, " ".join(argv[2:]), admin=True)
            except sqlite3.IntegrityError:
                print("That username already exists: use 'reset'.", file=sys.stderr)
                return 1
            what = "Admin account created."
        else:
            user = s.users.by_username(username)
            if user is None:
                print("No account with that username.", file=sys.stderr)
                return 1
            s.end_user(user["id"])
            token = s.users.reset(user["id"])
            what = "Password and 2FA reset; every sign-in ended."
        link = s.settings.issuer + url_for("web.invite", token=token)
    print(f"{what}\nOne-time link (valid {s.settings.invite_hours} hours):\n\n  {link}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
