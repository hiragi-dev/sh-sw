"""タイムパス: 普段は遮断し、API から指定秒数だけ一時的に解除する機能。

- 解除期限 (unlocked_until) はプロキシに渡され、プロキシがリクエスト毎に判定するため秒単位で正確に切れる
- 解除した時間はセッションとして記録し、1 日あたりの合計上限 (daily_limit_seconds) に使う
"""
import json
from datetime import datetime, timedelta

from . import db
from .policy import TZ


def now() -> datetime:
    # 秒単位の解除なので小数秒を切り捨てない(policy.now は秒で丸めている)
    return datetime.now(TZ)


class PassError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _dt(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s) if s else None


def _day_start(t: datetime) -> datetime:
    return t.replace(hour=0, minute=0, second=0, microsecond=0)


def used_seconds_today(pass_id: int, t: datetime) -> int:
    """今日 (ローカル 0 時以降) に解除されていた秒数。未経過の予約分は含まない。"""
    start = _day_start(t)
    total = 0.0
    for s in db.query(
        "SELECT started_at, ends_at FROM pass_sessions WHERE pass_id = ? AND ends_at > ?",
        (pass_id, start.isoformat()),
    ):
        a = max(_dt(s["started_at"]), start)
        b = min(_dt(s["ends_at"]), t)
        if b > a:
            total += (b - a).total_seconds()
    return int(total)


def _current_until(p: dict, t: datetime) -> datetime | None:
    until = _dt(p.get("unlocked_until"))
    return until if until and until > t else None


def to_out(row: dict, t: datetime | None = None) -> dict:
    t = t or now()
    p = dict(row)
    p["enabled"] = bool(p["enabled"])
    p["patterns"] = json.loads(p["patterns"])
    until = _current_until(p, t)
    p["unlocked"] = bool(p["enabled"] and until)
    p["unlocked_until"] = until.isoformat() if until else None
    p["remaining_seconds"] = round((until - t).total_seconds(), 1) if until else 0
    used = used_seconds_today(p["id"], t)
    p["used_today_seconds"] = used
    limit = p["daily_limit_seconds"]
    # 今日まだ解除できる秒数(進行中の解除の残り時間も差し引く)
    p["available_today_seconds"] = None if limit is None else max(0, int(limit - used - p["remaining_seconds"]))
    p["server_time"] = t.isoformat()
    return p


def get(pass_id: int) -> dict:
    row = db.query_one("SELECT * FROM passes WHERE id = ?", (pass_id,))
    if not row:
        raise PassError(404, "pass not found")
    return row


def list_all() -> list[dict]:
    t = now()
    return [to_out(r, t) for r in db.query("SELECT * FROM passes ORDER BY id")]


def _log(p: dict, action: str, seconds: int | None, source: str, detail: dict | None = None) -> None:
    db.execute(
        "INSERT INTO pass_logs(ts, pass_id, pass_name, action, seconds, source, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (now().isoformat(), p["id"], p["name"], action, seconds, source, json.dumps(detail or {}, ensure_ascii=False)),
    )


def unlock(pass_id: int, seconds: int | None, extend: bool, source: str) -> dict:
    """解除する。extend=False は「今から seconds 秒」、True は現在の残り時間に加算。"""
    p = get(pass_id)
    if not p["enabled"]:
        raise PassError(409, "pass is disabled")
    t = now()
    requested = seconds if seconds is not None else p["default_seconds"]
    if requested < 1:
        raise PassError(422, "seconds must be >= 1")
    granted = min(requested, p["max_seconds"])

    cur = _current_until(p, t)
    base = cur if (extend and cur) else t
    limit = p["daily_limit_seconds"]
    if limit is not None:
        used = used_seconds_today(pass_id, t)
        reserved = (cur - t).total_seconds() if (extend and cur) else 0
        available = limit - used - reserved
        if available <= 0:
            _log(p, "denied", requested, source, {"reason": "daily_limit", "used_today_seconds": used})
            raise PassError(429, f"本日の上限 ({limit} 秒) に達しています")
        granted = min(granted, int(available))
        if granted < 1:
            _log(p, "denied", requested, source, {"reason": "daily_limit", "used_today_seconds": used})
            raise PassError(429, f"本日の上限 ({limit} 秒) に達しています")

    until = base + timedelta(seconds=granted)
    with db.tx() as c:
        c.execute("UPDATE passes SET unlocked_until = ?, updated_at = ? WHERE id = ?", (until.isoformat(), t.isoformat(), pass_id))
        if cur:
            # 進行中のセッションの終了時刻を更新
            c.execute(
                "UPDATE pass_sessions SET ends_at = ? WHERE id = "
                "(SELECT id FROM pass_sessions WHERE pass_id = ? ORDER BY id DESC LIMIT 1)",
                (until.isoformat(), pass_id),
            )
        else:
            c.execute(
                "INSERT INTO pass_sessions(pass_id, started_at, ends_at, source) VALUES (?, ?, ?, ?)",
                (pass_id, t.isoformat(), until.isoformat(), source),
            )
    _log(p, "unlock", granted, source, {"requested": requested, "extend": extend, "until": until.isoformat()})
    out = to_out(get(pass_id))
    out["granted_seconds"] = granted
    out["requested_seconds"] = requested
    out["truncated"] = granted < requested
    return out


def lock(pass_id: int, source: str) -> dict:
    """直ちにロック(解除中なら残り時間を破棄)。"""
    p = get(pass_id)
    t = now()
    cur = _current_until(p, t)
    with db.tx() as c:
        c.execute("UPDATE passes SET unlocked_until = NULL, updated_at = ? WHERE id = ?", (t.isoformat(), pass_id))
        if cur:
            c.execute(
                "UPDATE pass_sessions SET ends_at = ? WHERE id = "
                "(SELECT id FROM pass_sessions WHERE pass_id = ? ORDER BY id DESC LIMIT 1)",
                (t.isoformat(), pass_id),
            )
    if cur:
        _log(p, "lock", int((cur - t).total_seconds()), source, {"discarded_seconds": int((cur - t).total_seconds())})
    return to_out(get(pass_id))


def ruleset_entries() -> tuple[list[dict], list[dict]]:
    """プロキシ向け: (パスのルール, 復号対象ホスト)。unlocked_until は epoch 秒で渡す。"""
    t = now()
    rules, intercept = [], []
    for row in db.query("SELECT * FROM passes WHERE enabled = 1 ORDER BY id"):
        until = _current_until(row, t)
        for pat in json.loads(row["patterns"]):
            host = pat["host"].strip().lower()
            sub = bool(pat.get("include_subdomains", True))
            intercept.append({"host": host, "include_subdomains": sub})
            rules.append({
                "host": host,
                "include_subdomains": sub,
                "path": (pat.get("path") or "").strip(),
                "user_agent": (pat.get("user_agent") or "").strip(),
                "pass_id": row["id"],
                "pass_name": row["name"],
                "unlocked_until": until.timestamp() if until else 0,
            })
    return rules, intercept
