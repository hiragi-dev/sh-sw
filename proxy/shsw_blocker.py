"""shsw mitmproxy addon

- 管理 API (/internal/sync) と定期同期し、現在有効なルールを取得する
- ルールに登録されたホストのみ TLS を復号(それ以外は素通し)して高速・安定に動かす
- 一致したリクエストに 403 のブロックページを返し、ブロックイベントを API へ送る
- タイムパス: 解除期限 (epoch 秒) をルールに持ち、リクエスト毎に現在時刻と比較する(秒単位で正確に失効)
- CA が差し替えられたらプロセスを終了し、Docker の restart ポリシーで再起動させる
"""

import asyncio
import collections
import html
import json
import logging
import os
import re
import time
import urllib.request
from datetime import datetime

from mitmproxy import ctx, http, tls

API_URL = os.environ.get("SHSW_API_URL", "http://api:8000").rstrip("/")
INTERNAL_TOKEN = os.environ.get("SHSW_INTERNAL_TOKEN", "")
# ロングポーリングの最大待ち時間。変更があれば API が即座に応答する
SYNC_WAIT = float(os.environ.get("SHSW_SYNC_WAIT", "8"))
SYNC_RETRY = 2.0

log = logging.getLogger("shsw")
_CERT_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)


def _glob(pattern: str) -> str:
    """'*' のみをワイルドカードとして扱う簡易 glob → 正規表現本体。"""
    return re.escape(pattern).replace(r"\*", ".*")


def _host_regex(host: str, include_subdomains: bool) -> re.Pattern:
    body = _glob(host.lower().strip().lstrip("."))
    prefix = r"(?:.*\.)?" if include_subdomains else ""
    return re.compile(rf"^{prefix}{body}$")


class Rule:
    # mitmproxy のスクリプトローダは sys.modules に登録しないため dataclass は使わない
    __slots__ = ("policy_id", "policy_name", "action", "host_re", "path", "path_re")

    def __init__(self, policy_id, policy_name, action, host_re, path, path_re):
        self.policy_id = policy_id
        self.policy_name = policy_name
        self.action = action
        self.host_re = host_re
        self.path = path
        self.path_re = path_re

    def match(self, host: str, path: str) -> bool:
        if not self.host_re.match(host):
            return False
        if not self.path:
            return True
        if self.path_re is not None:
            return bool(self.path_re.match(path))
        return path.startswith(self.path)


def _compile_rule(r: dict) -> Rule:
    path = r.get("path") or ""
    # '*' を含めば全体一致の glob、含まなければ前方一致
    path_re = re.compile(rf"^{_glob(path)}$", re.S) if "*" in path else None
    return Rule(
        policy_id=r["policy_id"],
        policy_name=r["policy_name"],
        action=r["action"],
        host_re=_host_regex(r["host"], r.get("include_subdomains", True)),
        path=path,
        path_re=path_re,
    )


class PassRule(Rule):
    __slots__ = ("unlocked_until",)

    def __init__(self, r):
        base = _compile_rule({**r, "policy_id": r["pass_id"], "policy_name": r["pass_name"], "action": "pass"})
        super().__init__(base.policy_id, base.policy_name, "pass", base.host_re, base.path, base.path_re)
        self.unlocked_until = float(r.get("unlocked_until") or 0)


class RuleSet:
    __slots__ = ("version", "allow", "block", "passes", "intercept", "intercept_all", "ca_fingerprint")

    def __init__(self, version, allow, block, intercept, intercept_all, ca_fingerprint, passes=()):
        self.version = version
        self.allow = allow
        self.block = block
        self.passes = passes
        self.intercept = intercept
        self.intercept_all = intercept_all
        self.ca_fingerprint = ca_fingerprint

    @classmethod
    def empty(cls):
        return cls("", (), (), (), False, "")

    @classmethod
    def from_json(cls, d):
        rules = [_compile_rule(r) for r in d.get("rules", [])]
        return cls(
            version=d.get("version", ""),
            allow=tuple(r for r in rules if r.action == "allow"),
            block=tuple(r for r in rules if r.action == "block"),
            intercept=tuple(
                _host_regex(h["host"], h.get("include_subdomains", True)) for h in d.get("intercept_hosts", [])
            ),
            intercept_all=bool(d.get("intercept_all")),
            ca_fingerprint=d.get("ca_fingerprint", ""),
            passes=tuple(PassRule(r) for r in d.get("passes", [])),
        )


PASS_PAGE = """<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><title>ロック中</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{{margin:0;font-family:system-ui,-apple-system,"Hiragino Sans","Noto Sans JP",sans-serif;background:#f4f5f7;color:#1f2328;display:grid;place-items:center;min-height:100vh}}
.card{{background:#fff;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.08);padding:40px 48px;max-width:560px}}
h1{{font-size:22px;margin:0 0 12px}} p{{color:#57606a;line-height:1.7;margin:6px 0}}
code{{background:#f0f1f3;padding:2px 6px;border-radius:4px;word-break:break-all}}
</style></head><body><div class="card">
<h1>🔒 「{name}」はロック中です</h1>
<p>このコンテンツは一時解除されている間だけ利用できます。</p>
<p>URL: <code>{url}</code></p>
<p style="font-size:12px;margin-top:20px">{ts} / shsw proxy</p>
</div></body></html>"""

BLOCK_PAGE = """<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><title>アクセスがブロックされました</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{{margin:0;font-family:system-ui,-apple-system,"Hiragino Sans","Noto Sans JP",sans-serif;background:#f4f5f7;color:#1f2328;display:grid;place-items:center;min-height:100vh}}
.card{{background:#fff;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.08);padding:40px 48px;max-width:560px}}
h1{{font-size:22px;margin:0 0 12px}} p{{color:#57606a;line-height:1.7;margin:6px 0}}
code{{background:#f0f1f3;padding:2px 6px;border-radius:4px;word-break:break-all}}
</style></head><body><div class="card">
<h1>🚫 このページへのアクセスはブロックされています</h1>
<p>URL: <code>{url}</code></p>
<p>ポリシー: <b>{policy}</b></p>
<p style="font-size:12px;margin-top:20px">{ts} / shsw proxy</p>
</div></body></html>"""


class ShswBlocker:
    def __init__(self) -> None:
        self.rs = RuleSet.empty()
        self.events: collections.deque = collections.deque(maxlen=5000)
        self.stats = {"requests": 0, "blocked": 0, "passthrough": 0, "intercepted": 0, "sync_errors": 0}
        self.started_at = time.time()
        self.ca_fingerprint = ""
        self.loop: asyncio.AbstractEventLoop | None = None
        self._task: asyncio.Task | None = None
        self._host_cache: dict[str, bool] = {}
        self._last_err_log = 0.0

    # ------------------------------------------------------------ lifecycle

    def _confdir(self) -> str:
        return os.path.expanduser(ctx.options.confdir)

    def _cache_path(self) -> str:
        return os.path.join(self._confdir(), "shsw-ruleset.json")

    def _read_ca_fingerprint(self) -> str:
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes

            with open(os.path.join(self._confdir(), "mitmproxy-ca.pem"), "rb") as f:
                m = _CERT_RE.search(f.read())
            return x509.load_pem_x509_certificate(m.group(0)).fingerprint(hashes.SHA256()).hex() if m else ""
        except Exception as e:  # noqa: BLE001
            log.warning("shsw: cannot read CA fingerprint: %s", e)
            return ""

    def running(self) -> None:
        self.ca_fingerprint = self._read_ca_fingerprint()
        # API が落ちていても前回のルールで動けるようにキャッシュを読む
        try:
            with open(self._cache_path()) as f:
                self._apply(json.load(f), persist=False)
            log.info("shsw: loaded cached ruleset %s", self.rs.version)
        except FileNotFoundError:
            pass
        except Exception as e:  # noqa: BLE001
            log.warning("shsw: failed to load cached ruleset: %s", e)
        self.loop = asyncio.get_running_loop()
        self._task = self.loop.create_task(self._sync_loop())

    def done(self) -> None:
        if self._task:
            self._task.cancel()

    # ------------------------------------------------------------ sync

    async def _sync_loop(self) -> None:
        while True:
            try:
                await asyncio.to_thread(self._sync_once)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                self.stats["sync_errors"] += 1
                if time.monotonic() - self._last_err_log > 30:
                    self._last_err_log = time.monotonic()
                    log.warning("shsw: sync with %s failed: %s", API_URL, e)
                await asyncio.sleep(SYNC_RETRY)

    def _sync_once(self) -> None:
        batch = []
        while self.events and len(batch) < 5000:
            batch.append(self.events.popleft())
        payload = {
            "events": batch,
            "stats": {**self.stats, "uptime": int(time.time() - self.started_at), "ruleset": self.rs.version},
            "ca_fingerprint": self.ca_fingerprint,
        }
        # 未送信のブロックログがあるときは待たずに返してもらう
        wait = 0 if batch else SYNC_WAIT
        req = urllib.request.Request(
            f"{API_URL}/internal/sync?known_version={self.rs.version}&wait={wait}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "X-Internal-Token": INTERNAL_TOKEN},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=SYNC_WAIT + 10) as resp:
                data = json.loads(resp.read())
        except Exception:
            # 送れなかったイベントは戻す(古いものから溢れる)
            self.events.extendleft(reversed(batch))
            raise
        if data.get("version") != self.rs.version:
            self.loop.call_soon_threadsafe(self._apply, data)
        ca = data.get("ca_fingerprint")
        if ca and self.ca_fingerprint and ca != self.ca_fingerprint:
            log.warning("shsw: CA certificate changed; shutting down to reload (docker will restart)")
            self.loop.call_soon_threadsafe(ctx.master.shutdown)

    def _apply(self, data: dict, persist: bool = True) -> None:
        self.rs = RuleSet.from_json(data)
        self._host_cache = {}
        log.info(
            "shsw: ruleset %s applied (block=%d allow=%d passes=%d intercept_hosts=%d intercept_all=%s)",
            self.rs.version, len(self.rs.block), len(self.rs.allow), len(self.rs.passes), len(self.rs.intercept),
            self.rs.intercept_all,
        )
        if persist:
            try:
                tmp = self._cache_path() + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(data, f)
                os.replace(tmp, self._cache_path())
            except Exception as e:  # noqa: BLE001
                log.warning("shsw: failed to persist ruleset cache: %s", e)

    # ------------------------------------------------------------ hooks

    def _should_intercept(self, host: str) -> bool:
        rs = self.rs
        if rs.intercept_all:
            return True
        hit = self._host_cache.get(host)
        if hit is None:
            hit = any(r.match(host) for r in rs.intercept)
            if len(self._host_cache) > 10000:
                self._host_cache.clear()
            self._host_cache[host] = hit
        return hit

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        host = (data.client_hello.sni or "").lower()
        if not host and data.context.server.address:
            host = str(data.context.server.address[0]).lower()
        if host and self._should_intercept(host):
            self.stats["intercepted"] += 1
            return
        # ルール対象外は復号せず TCP のまま中継(証明書ピンニングのアプリも壊さない)
        data.ignore_connection = True
        self.stats["passthrough"] += 1

    def request(self, flow: http.HTTPFlow) -> None:
        self.stats["requests"] += 1
        rs = self.rs
        if (not rs.block and not rs.passes) or flow.response is not None:
            return
        host = flow.request.pretty_host.lower().rstrip(".")
        path = flow.request.path or "/"
        for r in rs.allow:
            if r.match(host, path):
                return
        for r in rs.block:
            if r.match(host, path):
                self._block(flow, r, host, path)
                return
        if rs.passes:
            now = time.time()
            for r in rs.passes:
                if now >= r.unlocked_until and r.match(host, path):
                    self._block(flow, r, host, path)
                    return

    def _block(self, flow: http.HTTPFlow, rule: Rule, host: str, path: str) -> None:
        self.stats["blocked"] += 1
        ts = datetime.now().astimezone()
        url = flow.request.pretty_url
        accept = flow.request.headers.get("accept", "")
        headers = {"X-Shsw-Blocked": str(rule.policy_id), "Cache-Control": "no-store"}
        is_pass = rule.action == "pass"
        if is_pass:
            headers["X-Shsw-Pass"] = str(rule.policy_id)
            del headers["X-Shsw-Blocked"]
        if "text/html" in accept:
            page = PASS_PAGE if is_pass else BLOCK_PAGE
            body = page.format(
                url=html.escape(url[:500]), policy=html.escape(rule.policy_name), name=html.escape(rule.policy_name),
                ts=ts.strftime("%Y-%m-%d %H:%M:%S"),
            )
            headers["Content-Type"] = "text/html; charset=utf-8"
        else:
            body = f"Locked by shsw time pass: {rule.policy_name}\n" if is_pass else f"Blocked by shsw policy: {rule.policy_name}\n"
            headers["Content-Type"] = "text/plain; charset=utf-8"
        flow.response = http.Response.make(403, body.encode(), headers)
        peer = flow.client_conn.peername
        self.events.append({
            "ts": ts.isoformat(timespec="seconds"),
            "client": peer[0] if peer else None,
            "method": flow.request.method,
            "scheme": flow.request.scheme,
            "host": host,
            "path": path[:1000],
            "policy_id": None if is_pass else rule.policy_id,
            "policy_name": f"[タイムパス] {rule.policy_name}" if is_pass else rule.policy_name,
        })


addons = [ShswBlocker()]
