"""Signed patch tokens: a patch can only be authorized if the server validated it first."""
import hashlib
import hmac
import os
import secrets

SECRET = os.environ.get("SECRET_KEY", "").encode() or secrets.token_bytes(32)


def patch_token(path: str, original: str, patched: str) -> str:
    payload = f"{path}\n{hashlib.sha256(original.encode()).hexdigest()}\n{patched}"
    return hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()


def verify_token(path: str, original: str, patched: str, token: str) -> bool:
    return hmac.compare_digest(patch_token(path, original, patched), token)
