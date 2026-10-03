"""ポリシーの有効判定(時間帯・手動/トリガー上書き)。"""
import json
import os
from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo

from . import db

TZ = ZoneInfo(os.environ.get("TZ", "Asia/Tokyo"))

DAY_NAMES = ["月", "火", "水", "木", "金", "土", "日"]


def now() -> datetime:
    return datetime.now(TZ).replace(microsecond=0)


def _parse_hm(s: str) -> time:
    h, m = s.split(":")
    return time(int(h), int(m))


def in_window(window: dict, t: datetime) -> bool:
    """window = {days: [0..6] (0=月), start: "HH:MM", end: "HH:MM"}。
    start > end は日付跨ぎ(例 22:00-06:00)、start == end は終日。"""
    days = set(window.get("days") or [])
    start, end = _parse_hm(window["start"]), _parse_hm(window["end"])
    wd, cur = t.weekday(), t.time()
    if start == end:
        return wd in days
    if start < end:
        return wd in days and start <= cur < end
    return (wd in days and cur >= start) or (((wd - 1) % 7) in days and cur < end)


def row_to_policy(row: dict) -> dict:
    p = dict(row)
    p["enabled"] = bool(p["enabled"])
    p["patterns"] = json.loads(p["patterns"])
    p["windows"] = json.loads(p["windows"])
    return p


def active_override(p: dict, t: datetime) -> str | None:
    state = p.get("override_state")
    if not state:
        return None
    until = p.get("override_until")
    if until and datetime.fromisoformat(until) <= t:
        return None
    return state


def evaluate(p: dict, t: datetime | None = None) -> tuple[bool, str]:
    """(有効か, 理由) を返す。"""
    t = t or now()
    if not p["enabled"]:
        return False, "disabled"
    ov = active_override(p, t)
    if ov == "on":
        return True, "override_on"
    if ov == "off":
        return False, "override_off"
    mode = p["schedule_mode"]
    if mode == "always":
        return True, "always"
    hit = any(in_window(w, t) for w in p["windows"])
    if mode == "during":
        return hit, "in_schedule" if hit else "out_of_schedule"
    # outside
    return (not hit), "out_of_schedule" if not hit else "in_schedule"


def next_change(p: dict, t: datetime | None = None, horizon_days: int = 8) -> str | None:
    """現在の有効状態が次に切り替わる時刻(分単位で探索)。"""
    t = t or now()
    if not p["enabled"]:
        return None
    cur, _ = evaluate(p, t)
    probe = t.replace(second=0) + timedelta(minutes=1)
    end = t + timedelta(days=horizon_days)
    ov_until = p.get("override_until")
    # 上書き中は終了時刻が最初の切り替え候補
    if active_override(p, t) and ov_until:
        probe = max(probe, datetime.fromisoformat(ov_until))
    elif active_override(p, t):
        return None
    if p["schedule_mode"] == "always" and not active_override(p, t):
        return None
    # 境界のみ走査すれば十分だが、実装の単純さを優先して 5 分刻み → 1 分刻みで詰める
    step = timedelta(minutes=5)
    prev = probe
    while probe <= end:
        if evaluate(p, probe)[0] != cur:
            fine = prev
            while fine <= probe:
                if evaluate(p, fine)[0] != cur:
                    return fine.isoformat()
                fine += timedelta(minutes=1)
            return probe.isoformat()
        prev = probe
        probe += step
    return None


def list_policies() -> list[dict]:
    t = now()
    out = []
    for row in db.query("SELECT * FROM policies ORDER BY id"):
        p = row_to_policy(row)
        p["active"], p["reason"] = evaluate(p, t)
        if not active_override(p, t):
            p["override_state"], p["override_until"] = None, None
        p["next_change"] = next_change(p, t)
        out.append(p)
    return out


def get_policy(pid: int) -> dict | None:
    row = db.query_one("SELECT * FROM policies WHERE id = ?", (pid,))
    if not row:
        return None
    p = row_to_policy(row)
    t = now()
    p["active"], p["reason"] = evaluate(p, t)
    if not active_override(p, t):
        p["override_state"], p["override_until"] = None, None
    p["next_change"] = next_change(p, t)
    return p


def set_override(pid: int, state: str | None, duration_minutes: int | None) -> None:
    """state: 'on' | 'off' | None(解除)"""
    until = None
    if state and duration_minutes:
        until = (now() + timedelta(minutes=duration_minutes)).isoformat()
    db.execute(
        "UPDATE policies SET override_state = ?, override_until = ?, updated_at = ? WHERE id = ?",
        (state, until, now().isoformat(), pid),
    )


def build_ruleset() -> dict:
    """プロキシ addon に渡すルールセット。"""
    t = now()
    rules, intercept = [], []
    for row in db.query("SELECT * FROM policies WHERE enabled = 1 ORDER BY id"):
        p = row_to_policy(row)
        active, _ = evaluate(p, t)
        for pat in p["patterns"]:
            entry = {
                "host": pat["host"].strip().lower(),
                "include_subdomains": bool(pat.get("include_subdomains", True)),
                "path": (pat.get("path") or "").strip(),
            }
            if p["action"] == "block":
                intercept.append({"host": entry["host"], "include_subdomains": entry["include_subdomains"]})
            if active:
                rules.append({**entry, "policy_id": p["id"], "policy_name": p["name"], "action": p["action"]})
    return {"rules": rules, "intercept_hosts": intercept}
