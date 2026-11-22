"""Run the app with Waitress (the container's entry point: ``python serve.py``).

Behind vps-platform's Caddy set TRUSTED_PROXY=* (only Caddy shares the app's
network, and Caddy replaces X-Forwarded-For), so rate limits apply per visitor.
"""

import os

from waitress import serve

from login_service import create_app
from login_service.config import unquote


def waitress_options(env=os.environ) -> dict:
    def get(key: str, default: str) -> str:
        return unquote(env.get(key, default).strip())

    options = {
        "host": get("HOST", "127.0.0.1"),
        "port": int(get("PORT", "8080")),
        "threads": int(get("THREADS", "8")),
        "ident": "",                                            # no "Server: waitress" header
        "max_request_body_size": 64 * 1024,                     # forms and token requests only
    }
    proxy = get("TRUSTED_PROXY", "")
    if proxy:
        options.update(
            trusted_proxy=proxy,
            trusted_proxy_count=int(get("TRUSTED_PROXY_COUNT", "1")),
            trusted_proxy_headers={"x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"},
            clear_untrusted_proxy_headers=True,
        )
    return options


def main() -> None:
    options = waitress_options()
    app = create_app()
    print(f"Login Service running at http://{options['host']}:{options['port']}")
    serve(app, **options)


if __name__ == "__main__":
    main()
