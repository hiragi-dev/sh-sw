"""認証。

- 管理 API: `shsw-token` CLI で発行したアクセストークン (Authorization: Bearer)。DB にはハッシュのみ保存。
- 内部 API: プロキシ addon と共有する SHSW_INTERNAL_TOKEN (X-Internal-Token)。
"""
import hashlib
import hmac
import os
import secrets
import time

from fastapi import Header, HTTPException, Request

from . import db

INTERNAL_TOKEN = os.environ.get("SHSW_INTERNAL_TOKEN", "")
TOKEN_PREFIX = "shsw_"

# last_used_at の書き込みを間引く (token_id -> monotonic)
_last_touch: dict[int, float] = {}


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_token(name: str) -> tuple[int, str]:
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    from .policy import now

    tid = db.execute(
        "INSERT INTO api_tokens(name, token_hash, hint, created_at) VALUES (?, ?, ?, ?)",
        (name, hash_token(token), token[:10] + "…" + token[-4:], now().isoformat()),
    )
    return tid, token


def lookup(token: str) -> dict | None:
    if not token.startswith(TOKEN_PREFIX):
        return None
    return db.query_one(
        "SELECT * FROM api_tokens WHERE token_hash = ? AND revoked_at IS NULL", (hash_token(token),)
    )


def _bearer(authorization: str | None) -> str:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def require_admin(request: Request, authorization: str | None = Header(default=None)) -> dict:
    row = lookup(_bearer(authorization))
    if not row:
        raise HTTPException(status_code=401, detail="invalid or missing API token")
    last = _last_touch.get(row["id"], 0.0)
    if time.monotonic() - last > 60:
        _last_touch[row["id"]] = time.monotonic()
        from .policy import now

        client = request.headers.get("x-forwarded-for", request.client.host if request.client else "")
        db.execute(
            "UPDATE api_tokens SET last_used_at = ?, last_used_from = ? WHERE id = ?",
            (now().isoformat(), client.split(",")[0].strip(), row["id"]),
        )
    return row


def require_internal(x_internal_token: str | None = Header(default=None)) -> None:
    if not INTERNAL_TOKEN or not x_internal_token or not hmac.compare_digest(x_internal_token, INTERNAL_TOKEN):
        raise HTTPException(status_code=401, detail="unauthorized")
