"""Login Service: the central sign-in (OpenID Connect provider) for the AH Dashboard and File Share."""

from .app import create_app

__all__ = ["create_app"]
