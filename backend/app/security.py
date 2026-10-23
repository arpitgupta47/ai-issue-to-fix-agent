"""Signed patch tokens: a patch can only be authorized if the server validated it first."""
import hashlib
import hmac
import os

SECRET = os.environ.get("SECRET_KEY", "dev-only-change-me").encode()


def patch_token(path: str, patched: str) -> str:
    return hmac.new(SECRET, f"{path}\n{patched}".encode(), hashlib.sha256).hexdigest()


def verify_token(path: str, patched: str, token: str) -> bool:
    return hmac.compare_digest(patch_token(path, patched), token)
