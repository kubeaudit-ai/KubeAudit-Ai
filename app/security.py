"""Random tokens and their hashes. Only hashes are stored; a database leak exposes no usable tokens."""
import hashlib
import secrets


def new_token(prefix: str = "", nbytes: int = 32) -> str:
    return prefix + secrets.token_urlsafe(nbytes)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_api_key() -> str:
    return new_token("ka_live_", 32)
