import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Literal
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, field_validator

from . import auth, certs, db, passes, policy
from .policy import now

log = logging.getLogger("shsw")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

# 外部(トリガー呼び出し元・端末)から見たバックエンドの URL。UI の表示に使う
PUBLIC_URL = os.environ.get("SHSW_PUBLIC_URL", "").rstrip("/")

DEFAULT_SETTINGS = {"intercept_all": False, "event_max_rows": 50000}

class _ChangeNotifier:
    """変更系 API が呼ばれたことをロングポーリング中の同期リクエストに知らせる。"""

    def __init__(self) -> None:
        self.generation = 0
        self._event: asyncio.Event | None = None

    def notify(self) -> None:
        self.generation += 1
        if self._event:
            self._event.set()
            self._event = None

    async def wait(self, gen: int, timeout: float) -> None:
        if self.generation != gen:
            return
        if self._event is None:
            self._event = asyncio.Event()
        try:
            await asyncio.wait_for(self._event.wait(), timeout)
        except asyncio.TimeoutError:
            pass


_change = _ChangeNotifier()

# プロキシ(addon)の最新状態。メモリ上のみ。
proxy_state: dict = {"last_sync": None, "last_sync_mono": 0.0, "stats": {}}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init()
    certs.ensure_ca()
    if not db.query_one("SELECT id FROM api_tokens WHERE revoked_at IS NULL"):
        log.warning("有効な API トークンがありません。`docker compose exec api shsw-token create web` で発行してください")
    if not auth.INTERNAL_TOKEN:
        log.warning("SHSW_INTERNAL_TOKEN が未設定のためプロキシと同期できません")
    yield


app = FastAPI(
    title="shsw API", version="1.0.0", docs_url="/api/docs", openapi_url="/api/openapi.json", lifespan=lifespan
)


@app.middleware("http")
async def _notify_on_change(request: Request, call_next):
    """変更系リクエスト (POST/PUT/DELETE) が成功したらプロキシへの即時同期を促す。"""
    response = await call_next(request)
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.url.path.startswith("/api/") \
            and response.status_code < 400:
        _change.notify()
    return response


def get_settings() -> dict:
    return {k: db.get_setting(k, v) for k, v in DEFAULT_SETTINGS.items()}


# ---------------------------------------------------------------- schemas

class PatternIn(BaseModel):
    host: str
    include_subdomains: bool = True
    path: str = ""

    @field_validator("host", mode="before")
    @classmethod
    def _host(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if "://" in v:
            v = urlsplit(v).hostname or ""
        v = v.split("/")[0].split(":")[0] if not v.startswith("[") else v
        if not v:
            raise ValueError("host is required")
        return v

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        v = (v or "").strip()
        if v and not v.startswith("/") and not v.startswith("*"):
            v = "/" + v
        return v


class WindowIn(BaseModel):
    days: list[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4])
    start: str = "09:00"
    end: str = "18:00"

    @field_validator("days")
    @classmethod
    def _days(cls, v: list[int]) -> list[int]:
        if any(d < 0 or d > 6 for d in v):
            raise ValueError("days must be 0(Mon)..6(Sun)")
        return sorted(set(v))

    @field_validator("start", "end")
    @classmethod
    def _hm(cls, v: str) -> str:
        try:
            h, m = (int(x) for x in v.split(":"))
            assert 0 <= h <= 23 and 0 <= m <= 59
        except Exception:
            raise ValueError("time must be HH:MM")
        return f"{h:02d}:{m:02d}"


class PolicyIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = ""
    enabled: bool = True
    action: Literal["block", "allow"] = "block"
    patterns: list[PatternIn] = Field(default_factory=list)
    schedule_mode: Literal["always", "during", "outside"] = "always"
    windows: list[WindowIn] = Field(default_factory=list)


class OverrideIn(BaseModel):
    state: Literal["on", "off", "clear"]
    duration_minutes: int | None = Field(default=None, ge=1, le=60 * 24 * 365)


TriggerAction = Literal["activate", "deactivate", "toggle", "reset"]


class TriggerIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    action: TriggerAction = "activate"
    policy_ids: list[int] = Field(default_factory=list)
    duration_minutes: int | None = Field(default=None, ge=1, le=60 * 24 * 365)
    enabled: bool = True


class HookIn(BaseModel):
    action: TriggerAction | None = None
    duration_minutes: int | None = Field(default=None, ge=1, le=60 * 24 * 365)
    token: str | None = None


class CARegenIn(BaseModel):
    common_name: str = Field(default="shsw Proxy CA", min_length=1, max_length=64)
    organization: str = Field(default="shsw", min_length=1, max_length=64)
    days: int = Field(default=3650, ge=30, le=7300)
    key_size: Literal[2048, 3072, 4096] = 2048


class IssueIn(BaseModel):
    common_name: str = Field(min_length=1, max_length=253)
    sans: list[str] = Field(default_factory=list)
    days: int = Field(default=397, ge=1, le=825)


class SettingsIn(BaseModel):
    intercept_all: bool | None = None
    event_max_rows: int | None = Field(default=None, ge=100, le=5_000_000)


class PassIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = ""
    enabled: bool = True
    patterns: list[PatternIn] = Field(min_length=1)
    default_seconds: int = Field(default=300, ge=1, le=86400)
    max_seconds: int = Field(default=3600, ge=1, le=86400)
    daily_limit_seconds: int | None = Field(default=None, ge=1, le=86400)

    @field_validator("max_seconds")
    @classmethod
    def _max(cls, v: int, info) -> int:
        d = info.data.get("default_seconds")
        if d is not None and v < d:
            raise ValueError("max_seconds must be >= default_seconds")
        return v


class UnlockIn(BaseModel):
    seconds: int | None = Field(default=None, ge=1, le=86400)
    extend: bool = False
    token: str | None = None


class SyncIn(BaseModel):
    events: list[dict] = Field(default_factory=list)
    stats: dict = Field(default_factory=dict)
    ca_fingerprint: str | None = None


# ---------------------------------------------------------------- public

@app.get("/api/health")
def health():
    return {"ok": True, "time": now().isoformat()}


@app.get("/api/public/ca.{fmt}")
def download_ca(fmt: Literal["pem", "crt", "cer", "der", "p12"]):
    kind = {"pem": "pem", "crt": "der", "cer": "pem", "der": "der", "p12": "p12"}[fmt]
    media = {"pem": "application/x-pem-file", "der": "application/x-x509-ca-cert", "p12": "application/x-pkcs12"}[kind]
    return Response(
        certs.ca_cert_bytes(kind),
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="shsw-ca.{fmt}"'},
    )


# ---------------------------------------------------------------- admin

admin = [Depends(auth.require_admin)]


@app.get("/api/auth/me")
def me(token: dict = Depends(auth.require_admin)):
    return {"token_name": token["name"], "public_url": PUBLIC_URL, "version": app.version}


@app.get("/api/status", dependencies=admin)
def status():
    pols = policy.list_policies()
    last = proxy_state["last_sync_mono"]
    since = db.query_one(
        "SELECT COUNT(*) AS c FROM block_events WHERE ts >= ?", ((now() - timedelta(hours=24)).isoformat(),)
    )["c"]
    ca = certs.ca_info()
    return {
        "time": now().isoformat(),
        "public_url": PUBLIC_URL,
        "timezone": str(policy.TZ),
        "proxy": {
            "online": bool(last) and time.monotonic() - last < 15,
            "last_sync": proxy_state["last_sync"],
            "stats": proxy_state["stats"],
            "ca_in_sync": proxy_state["stats"].get("ca_fingerprint") in (None, ca["fingerprint_raw"]),
        },
        "policies": {
            "total": len(pols),
            "active": sum(1 for p in pols if p["active"]),
        },
        "blocked_24h": since,
        "settings": get_settings(),
        "ca": ca,
    }


# policies

@app.get("/api/policies", dependencies=admin)
def list_policies():
    return policy.list_policies()


def _policy_values(body: PolicyIn) -> tuple:
    return (
        body.name, body.description, int(body.enabled), body.action,
        json.dumps([p.model_dump() for p in body.patterns]),
        body.schedule_mode, json.dumps([w.model_dump() for w in body.windows]),
    )


@app.post("/api/policies", dependencies=admin, status_code=201)
def create_policy(body: PolicyIn):
    ts = now().isoformat()
    pid = db.execute(
        "INSERT INTO policies(name, description, enabled, action, patterns, schedule_mode, windows, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (*_policy_values(body), ts, ts),
    )
    return policy.get_policy(pid)


def _must_policy(pid: int) -> dict:
    p = policy.get_policy(pid)
    if not p:
        raise HTTPException(404, "policy not found")
    return p


@app.get("/api/policies/{pid}", dependencies=admin)
def get_policy(pid: int):
    return _must_policy(pid)


@app.put("/api/policies/{pid}", dependencies=admin)
def update_policy(pid: int, body: PolicyIn):
    _must_policy(pid)
    db.execute(
        "UPDATE policies SET name=?, description=?, enabled=?, action=?, patterns=?, schedule_mode=?, windows=?, updated_at=? "
        "WHERE id=?",
        (*_policy_values(body), now().isoformat(), pid),
    )
    return policy.get_policy(pid)


@app.delete("/api/policies/{pid}", dependencies=admin, status_code=204)
def delete_policy(pid: int):
    _must_policy(pid)
    db.execute("DELETE FROM policies WHERE id = ?", (pid,))
    return Response(status_code=204)


@app.post("/api/policies/{pid}/override", dependencies=admin)
def override_policy(pid: int, body: OverrideIn):
    _must_policy(pid)
    policy.set_override(pid, None if body.state == "clear" else body.state, body.duration_minutes)
    return policy.get_policy(pid)


# triggers

def _trigger_out(row: dict) -> dict:
    t = dict(row)
    t["enabled"] = bool(t["enabled"])
    t["policy_ids"] = json.loads(t["policy_ids"])
    return t


@app.get("/api/triggers", dependencies=admin)
def list_triggers():
    return [_trigger_out(r) for r in db.query("SELECT * FROM triggers ORDER BY id")]


def _must_trigger(tid: int) -> dict:
    row = db.query_one("SELECT * FROM triggers WHERE id = ?", (tid,))
    if not row:
        raise HTTPException(404, "trigger not found")
    return _trigger_out(row)


@app.post("/api/triggers", dependencies=admin, status_code=201)
def create_trigger(body: TriggerIn):
    tid = db.execute(
        "INSERT INTO triggers(name, token, action, policy_ids, duration_minutes, enabled, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (body.name, secrets.token_urlsafe(24), body.action, json.dumps(body.policy_ids),
         body.duration_minutes, int(body.enabled), now().isoformat()),
    )
    return _must_trigger(tid)


@app.put("/api/triggers/{tid}", dependencies=admin)
def update_trigger(tid: int, body: TriggerIn):
    _must_trigger(tid)
    db.execute(
        "UPDATE triggers SET name=?, action=?, policy_ids=?, duration_minutes=?, enabled=? WHERE id=?",
        (body.name, body.action, json.dumps(body.policy_ids), body.duration_minutes, int(body.enabled), tid),
    )
    return _must_trigger(tid)


@app.post("/api/triggers/{tid}/rotate-token", dependencies=admin)
def rotate_trigger_token(tid: int):
    _must_trigger(tid)
    db.execute("UPDATE triggers SET token=? WHERE id=?", (secrets.token_urlsafe(24), tid))
    return _must_trigger(tid)


@app.delete("/api/triggers/{tid}", dependencies=admin, status_code=204)
def delete_trigger(tid: int):
    _must_trigger(tid)
    db.execute("DELETE FROM triggers WHERE id = ?", (tid,))
    return Response(status_code=204)


def _apply_trigger_action(action: str, policy_ids: list[int], duration: int | None) -> list[dict]:
    results = []
    for pid in policy_ids:
        p = policy.get_policy(pid)
        if not p:
            continue
        if action == "activate":
            policy.set_override(pid, "on", duration)
        elif action == "deactivate":
            policy.set_override(pid, "off", duration)
        elif action == "toggle":
            policy.set_override(pid, "off" if p["active"] else "on", duration)
        elif action == "reset":
            policy.set_override(pid, None, None)
        p = policy.get_policy(pid)
        results.append({"id": pid, "name": p["name"], "active": p["active"], "override_until": p["override_until"]})
    return results


@app.post("/api/hooks/{tid}")
async def fire_hook(tid: int, request: Request, token: str | None = Query(default=None)):
    """外部から POST で叩くトリガー。トークンは X-Trigger-Token / Authorization: Bearer / ?token= / body.token。"""
    body = HookIn()
    raw = await request.body()
    if raw.strip():
        try:
            body = HookIn.model_validate_json(raw)
        except Exception as e:
            raise HTTPException(422, f"invalid body: {e}")
    supplied = (
        request.headers.get("x-trigger-token")
        or auth._bearer(request.headers.get("authorization"))
        or token
        or body.token
        or ""
    )
    row = db.query_one("SELECT * FROM triggers WHERE id = ?", (tid,))
    if not row or not supplied or not hmac.compare_digest(supplied, row["token"]):
        await asyncio.sleep(0.5)
        raise HTTPException(401, "invalid trigger or token")
    trg = _trigger_out(row)
    if not trg["enabled"]:
        raise HTTPException(409, "trigger disabled")
    action = body.action or trg["action"]
    duration = body.duration_minutes if body.duration_minutes is not None else trg["duration_minutes"]
    if action == "reset":
        duration = None
    results = await asyncio.to_thread(_apply_trigger_action, action, trg["policy_ids"], duration)
    ts = now().isoformat()
    source = request.client.host if request.client else "?"
    db.execute("UPDATE triggers SET fire_count = fire_count + 1, last_fired_at = ? WHERE id = ?", (ts, tid))
    db.execute(
        "INSERT INTO trigger_logs(ts, trigger_id, trigger_name, action, source, detail) VALUES (?, ?, ?, ?, ?, ?)",
        (ts, tid, trg["name"], action, source,
         json.dumps({"duration_minutes": duration, "policies": results}, ensure_ascii=False)),
    )
    log.info("trigger %s fired: action=%s from=%s", trg["name"], action, source)
    return {"ok": True, "trigger": trg["name"], "action": action, "duration_minutes": duration, "policies": results}


# time passes (タイムパス)

def _pass_call(fn, *args):
    try:
        return fn(*args)
    except passes.PassError as e:
        raise HTTPException(e.status, e.message)


@app.get("/api/passes", dependencies=admin)
def list_passes():
    return passes.list_all()


@app.post("/api/passes", dependencies=admin, status_code=201)
def create_pass(body: PassIn):
    ts = now().isoformat()
    pid = db.execute(
        "INSERT INTO passes(name, description, enabled, patterns, default_seconds, max_seconds, daily_limit_seconds, "
        "token, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (body.name, body.description, int(body.enabled), json.dumps([p.model_dump() for p in body.patterns]),
         body.default_seconds, body.max_seconds, body.daily_limit_seconds, secrets.token_urlsafe(24), ts, ts),
    )
    return passes.to_out(passes.get(pid))


@app.get("/api/passes/{pid}", dependencies=admin)
def get_pass(pid: int):
    return passes.to_out(_pass_call(passes.get, pid))


@app.put("/api/passes/{pid}", dependencies=admin)
def update_pass(pid: int, body: PassIn):
    _pass_call(passes.get, pid)
    db.execute(
        "UPDATE passes SET name=?, description=?, enabled=?, patterns=?, default_seconds=?, max_seconds=?, "
        "daily_limit_seconds=?, updated_at=? WHERE id=?",
        (body.name, body.description, int(body.enabled), json.dumps([p.model_dump() for p in body.patterns]),
         body.default_seconds, body.max_seconds, body.daily_limit_seconds, now().isoformat(), pid),
    )
    return passes.to_out(passes.get(pid))


@app.delete("/api/passes/{pid}", dependencies=admin, status_code=204)
def delete_pass(pid: int):
    _pass_call(passes.get, pid)
    with db.tx() as c:
        c.execute("DELETE FROM passes WHERE id = ?", (pid,))
        c.execute("DELETE FROM pass_sessions WHERE pass_id = ?", (pid,))
    return Response(status_code=204)


@app.post("/api/passes/{pid}/rotate-token", dependencies=admin)
def rotate_pass_token(pid: int):
    _pass_call(passes.get, pid)
    db.execute("UPDATE passes SET token = ? WHERE id = ?", (secrets.token_urlsafe(24), pid))
    return passes.to_out(passes.get(pid))


@app.post("/api/passes/{pid}/unlock")
def admin_unlock_pass(pid: int, body: UnlockIn, token: dict = Depends(auth.require_admin)):
    return _pass_call(passes.unlock, pid, body.seconds, body.extend, f"ui:{token['name']}")


@app.post("/api/passes/{pid}/lock")
def admin_lock_pass(pid: int, token: dict = Depends(auth.require_admin)):
    return _pass_call(passes.lock, pid, f"ui:{token['name']}")


@app.get("/api/pass-logs", dependencies=admin)
def list_pass_logs(pass_id: int | None = None, limit: int = Query(default=100, ge=1, le=1000)):
    if pass_id is None:
        rows = db.query("SELECT * FROM pass_logs ORDER BY id DESC LIMIT ?", (limit,))
    else:
        rows = db.query("SELECT * FROM pass_logs WHERE pass_id = ? ORDER BY id DESC LIMIT ?", (pass_id, limit))
    for r in rows:
        r["detail"] = json.loads(r["detail"] or "{}")
    return rows


async def _pass_hook_auth(pid: int, request: Request, query_token: str | None, body_token: str | None) -> dict:
    supplied = (
        request.headers.get("x-pass-token")
        or auth._bearer(request.headers.get("authorization"))
        or query_token
        or body_token
        or ""
    )
    row = db.query_one("SELECT * FROM passes WHERE id = ?", (pid,))
    if not row or not supplied or not hmac.compare_digest(supplied, row["token"]):
        await asyncio.sleep(0.5)
        raise HTTPException(401, "invalid pass or token")
    return row


def _public_pass(p: dict) -> dict:
    keys = ("id", "name", "enabled", "unlocked", "unlocked_until", "remaining_seconds", "used_today_seconds",
            "available_today_seconds", "daily_limit_seconds", "default_seconds", "max_seconds", "server_time",
            "granted_seconds", "requested_seconds", "truncated")
    return {k: p[k] for k in keys if k in p}


@app.post("/api/pass-hooks/{pid}/unlock")
async def hook_unlock_pass(pid: int, request: Request, token: str | None = Query(default=None)):
    """外部から POST: 指定秒数だけ解除。body {"seconds": 60, "extend": false} (省略時は既定秒数)。"""
    body = UnlockIn()
    raw = await request.body()
    if raw.strip():
        try:
            body = UnlockIn.model_validate_json(raw)
        except Exception as e:
            raise HTTPException(422, f"invalid body: {e}")
    await _pass_hook_auth(pid, request, token, body.token)
    source = request.client.host if request.client else "?"
    res = await asyncio.to_thread(_pass_call, passes.unlock, pid, body.seconds, body.extend, source)
    return _public_pass(res)


@app.post("/api/pass-hooks/{pid}/lock")
async def hook_lock_pass(pid: int, request: Request, token: str | None = Query(default=None)):
    await _pass_hook_auth(pid, request, token, None)
    source = request.client.host if request.client else "?"
    return _public_pass(await asyncio.to_thread(_pass_call, passes.lock, pid, source))


@app.get("/api/pass-hooks/{pid}")
async def hook_pass_state(pid: int, request: Request, token: str | None = Query(default=None)):
    await _pass_hook_auth(pid, request, token, None)
    return _public_pass(passes.to_out(passes.get(pid)))


# logs

@app.get("/api/events", dependencies=admin)
def list_events(
    q: str = "", policy_id: int | None = None,
    limit: int = Query(default=100, ge=1, le=1000), offset: int = Query(default=0, ge=0),
):
    where, params = ["1=1"], []
    if q:
        where.append("(host LIKE ? OR path LIKE ? OR client LIKE ?)")
        params += [f"%{q}%"] * 3
    if policy_id is not None:
        where.append("policy_id = ?")
        params.append(policy_id)
    w = " AND ".join(where)
    total = db.query_one(f"SELECT COUNT(*) AS c FROM block_events WHERE {w}", tuple(params))["c"]
    items = db.query(
        f"SELECT * FROM block_events WHERE {w} ORDER BY id DESC LIMIT ? OFFSET ?", (*params, limit, offset)
    )
    return {"total": total, "items": items}


@app.get("/api/events/summary", dependencies=admin)
def events_summary(hours: int = Query(default=24, ge=1, le=24 * 30)):
    since = (now() - timedelta(hours=hours)).isoformat()
    return {
        "by_host": db.query(
            "SELECT host, COUNT(*) AS count FROM block_events WHERE ts >= ? GROUP BY host ORDER BY count DESC LIMIT 10",
            (since,),
        ),
        "by_policy": db.query(
            "SELECT policy_id, policy_name, COUNT(*) AS count FROM block_events WHERE ts >= ? "
            "GROUP BY policy_id ORDER BY count DESC LIMIT 10",
            (since,),
        ),
        "by_hour": db.query(
            "SELECT substr(ts, 1, 13) AS hour, COUNT(*) AS count FROM block_events WHERE ts >= ? "
            "GROUP BY hour ORDER BY hour",
            (since,),
        ),
    }


@app.delete("/api/events", dependencies=admin, status_code=204)
def clear_events():
    db.execute("DELETE FROM block_events")
    return Response(status_code=204)


@app.get("/api/trigger-logs", dependencies=admin)
def list_trigger_logs(limit: int = Query(default=100, ge=1, le=1000)):
    rows = db.query("SELECT * FROM trigger_logs ORDER BY id DESC LIMIT ?", (limit,))
    for r in rows:
        r["detail"] = json.loads(r["detail"] or "{}")
    return rows


# certificates

@app.get("/api/ca", dependencies=admin)
def get_ca():
    return certs.ca_info()


@app.post("/api/ca/regenerate", dependencies=admin)
def regenerate_ca(body: CARegenIn):
    key, cert = certs.generate_ca(body.common_name, body.organization, body.days, body.key_size)
    certs.write_ca_store(key, cert)
    log.warning("CA regenerated; proxy will restart to load it")
    return certs.ca_info()


@app.get("/api/certs", dependencies=admin)
def list_issued():
    rows = db.query("SELECT * FROM issued_certs ORDER BY id DESC")
    for r in rows:
        r["sans"] = json.loads(r["sans"])
    return rows


@app.post("/api/certs/issue", dependencies=admin)
def issue_cert(body: IssueIn):
    res = certs.issue_server_cert(body.common_name, body.sans, body.days)
    db.execute(
        "INSERT INTO issued_certs(serial, common_name, sans, not_after, created_at) VALUES (?, ?, ?, ?, ?)",
        (res["serial"], body.common_name, json.dumps(body.sans), res["not_after"], now().isoformat()),
    )
    return res


# settings

@app.get("/api/settings", dependencies=admin)
def read_settings():
    return get_settings()


@app.put("/api/settings", dependencies=admin)
def write_settings(body: SettingsIn):
    for k, v in body.model_dump(exclude_none=True).items():
        db.set_setting(k, v)
    return get_settings()


# ---------------------------------------------------------------- internal (proxy addon)

def _store_sync(body: SyncIn) -> None:
    settings = get_settings()
    if body.events:
        with db.tx() as cur:
            cur.executemany(
                "INSERT INTO block_events(ts, client, method, scheme, host, path, policy_id, policy_name) "
                "VALUES (:ts, :client, :method, :scheme, :host, :path, :policy_id, :policy_name)",
                [
                    {k: e.get(k) for k in ("ts", "client", "method", "scheme", "host", "path", "policy_id", "policy_name")}
                    for e in body.events[:5000]
                ],
            )
            cur.execute(
                "DELETE FROM block_events WHERE id <= (SELECT MAX(id) FROM block_events) - ?",
                (int(settings["event_max_rows"]),),
            )
    proxy_state["last_sync"] = now().isoformat()
    proxy_state["last_sync_mono"] = time.monotonic()
    proxy_state["stats"] = {**body.stats, "ca_fingerprint": body.ca_fingerprint}


def _build_ruleset() -> dict:
    rs = policy.build_ruleset()
    pass_rules, pass_hosts = passes.ruleset_entries()
    rs["passes"] = pass_rules
    rs["intercept_hosts"] += pass_hosts
    rs["intercept_all"] = bool(get_settings()["intercept_all"])
    rs["ca_fingerprint"] = certs.fingerprint(certs.load_ca_cert())
    rs["version"] = hashlib.sha256(json.dumps(rs, sort_keys=True).encode()).hexdigest()[:16]
    return rs


@app.post("/internal/sync", dependencies=[Depends(auth.require_internal)])
async def internal_sync(
    body: SyncIn,
    known_version: str = Query(default=""),
    wait: float = Query(default=0, ge=0, le=25),
):
    """プロキシ addon との同期(ロングポーリング)。

    ルールセットが known_version と同じなら、変更通知 (変更系 API 呼び出し) か時間経過による
    有効状態の変化があるまで最大 wait 秒待ってから返す。変更はほぼ即座にプロキシへ届く。
    """
    await asyncio.to_thread(_store_sync, body)
    deadline = time.monotonic() + wait
    while True:
        gen = _change.generation
        rs = await asyncio.to_thread(_build_ruleset)
        remaining = deadline - time.monotonic()
        if rs["version"] != known_version or remaining <= 0:
            return rs
        # 変更通知を待つ。スケジュールの時刻境界に備えて 1 秒ごとに再評価する
        await _change.wait(gen, min(1.0, remaining))
