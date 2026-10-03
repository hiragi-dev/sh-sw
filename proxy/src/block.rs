//! HTTP ミドルウェア: リクエスト毎にルールを判定し、遮断なら 403 のブロックページを返す。
//! MITM で復号した HTTPS と、平文 HTTP の両方に適用する。

use crate::rules::{RuleKind, Verdict};
use crate::state::{BlockEvent, Shared, Stats};
use rama::{
    Layer, Service,
    extensions::ExtensionsRef,
    http::{Request, Response, StatusCode, header},
    net::{client::ConnectorTarget, stream::SocketInfo},
};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct BlockLayer {
    shared: Arc<Shared>,
}

impl BlockLayer {
    pub fn new(shared: Arc<Shared>) -> Self {
        Self { shared }
    }
}

impl<S> Layer<S> for BlockLayer {
    type Service = BlockService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BlockService {
            inner,
            shared: self.shared.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BlockService<S> {
    inner: S,
    shared: Arc<Shared>,
}

/// リクエストの宛先ホスト: URI → Host ヘッダ → CONNECT の宛先 の順に探す
fn request_host<B>(req: &Request<B>) -> Option<String> {
    if let Some(h) = req.uri().host() {
        return Some(h.to_string());
    }
    if let Some(h) = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()) {
        let host = if let Some(rest) = h.strip_prefix('[') {
            rest.split(']').next().unwrap_or(rest)
        } else {
            h.rsplit_once(':').map_or(h, |(host, _)| host)
        };
        return Some(host.to_owned());
    }
    req.extensions()
        .get_ref::<ConnectorTarget>()
        .map(|t| t.0.host.to_string())
}

fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_default()
}

impl<S, B, RB> Service<Request<B>> for BlockService<S>
where
    S: Service<Request<B>, Output = Response<RB>>,
    B: Send + 'static,
    RB: From<String> + Send + 'static,
{
    type Output = Response<RB>;
    type Error = S::Error;

    async fn serve(&self, req: Request<B>) -> Result<Self::Output, Self::Error> {
        Stats::inc(&self.shared.stats.requests);
        let Some(host) = request_host(&req) else {
            return self.inner.serve(req).await;
        };
        let path = req.uri().request_target().into_owned();

        let rules = self.shared.rules.load();
        let Verdict::Block(rule) = rules.evaluate(&host, &path, now_epoch()) else {
            drop(rules);
            return self.inner.serve(req).await;
        };

        Stats::inc(&self.shared.stats.blocked);
        let is_pass = rule.kind == RuleKind::Pass;
        let scheme = req
            .uri()
            .scheme_str()
            .map(str::to_owned)
            .unwrap_or_else(|| {
                if req.extensions().get_ref::<ConnectorTarget>().is_some() {
                    "https".to_owned()
                } else {
                    "http".to_owned()
                }
            });
        let client = req
            .extensions()
            .get_ref::<SocketInfo>()
            .map(|s| s.peer_addr().ip_addr.to_string());
        self.shared.push_event(BlockEvent {
            ts: chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false),
            client,
            method: req.method().to_string(),
            scheme: scheme.clone(),
            host: host.to_ascii_lowercase(),
            path: path.chars().take(1000).collect(),
            policy_id: (!is_pass).then_some(rule.id),
            policy_name: if is_pass {
                format!("[タイムパス] {}", rule.name)
            } else {
                rule.name.clone()
            },
        });

        let wants_html = req
            .headers()
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("text/html"));
        let url = format!("{scheme}://{host}{path}");
        let (content_type, body) = if wants_html {
            ("text/html; charset=utf-8", block_page(&url, &rule.name, is_pass))
        } else if is_pass {
            ("text/plain; charset=utf-8", format!("Locked by shsw time pass: {}\n", rule.name))
        } else {
            ("text/plain; charset=utf-8", format!("Blocked by shsw policy: {}\n", rule.name))
        };
        let marker = if is_pass { "x-shsw-pass" } else { "x-shsw-blocked" };
        let resp = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CACHE_CONTROL, "no-store")
            .header(marker, rule.id.to_string())
            .body(RB::from(body))
            .unwrap_or_else(|_| Response::new(RB::from(String::from("Blocked by shsw\n"))));
        Ok(resp)
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn block_page(url: &str, name: &str, is_pass: bool) -> String {
    let url: String = url.chars().take(500).collect();
    let (title, heading, lead) = if is_pass {
        (
            "ロック中",
            format!("🔒 「{}」はロック中です", escape(name)),
            "<p>このコンテンツは一時解除されている間だけ利用できます。</p>".to_owned(),
        )
    } else {
        (
            "アクセスがブロックされました",
            "🚫 このページへのアクセスはブロックされています".to_owned(),
            format!("<p>ポリシー: <b>{}</b></p>", escape(name)),
        )
    };
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    format!(
        r#"<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><title>{title}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{{margin:0;font-family:system-ui,-apple-system,"Hiragino Sans","Noto Sans JP",sans-serif;background:#f4f5f7;color:#1f2328;display:grid;place-items:center;min-height:100vh}}
.card{{background:#fff;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.08);padding:40px 48px;max-width:560px}}
h1{{font-size:22px;margin:0 0 12px}} p{{color:#57606a;line-height:1.7;margin:6px 0}}
code{{background:#f0f1f3;padding:2px 6px;border-radius:4px;word-break:break-all}}
</style></head><body><div class="card">
<h1>{heading}</h1>
{lead}
<p>URL: <code>{url}</code></p>
<p style="font-size:12px;margin-top:20px">{ts} / shsw proxy</p>
</div></body></html>"#,
        url = escape(&url),
    )
}

/// 送信元 IP の制限 (mitmproxy の block_global 相当)。
/// 既定ではプライベート / ループバック / リンクローカル / CGNAT (Tailscale) / ULA 以外を拒否し、
/// 意図せず「インターネットに開いたプロキシ」になるのを防ぐ。
#[derive(Debug, Clone)]
pub struct ClientFilterLayer {
    allow_public: bool,
    /// 期待する Proxy-Authorization ヘッダ値 ("Basic xxx")。None なら認証なし
    proxy_auth: Option<Arc<str>>,
}

impl ClientFilterLayer {
    pub fn new(allow_public: bool, proxy_auth: Option<(String, String)>) -> Self {
        use base64::Engine as _;
        let proxy_auth = proxy_auth.map(|(user, pass)| {
            let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
            Arc::from(format!("Basic {token}"))
        });
        Self { allow_public, proxy_auth }
    }
}

impl<S> Layer<S> for ClientFilterLayer {
    type Service = ClientFilterService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ClientFilterService {
            inner,
            allow_public: self.allow_public,
            proxy_auth: self.proxy_auth.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientFilterService<S> {
    inner: S,
    allow_public: bool,
    proxy_auth: Option<Arc<str>>,
}

pub fn is_local_client(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                // 100.64.0.0/10 (CGNAT, Tailscale)
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            v6.is_loopback()
                // fc00::/7 (ULA, Tailscale の fd7a:115c:a1e0::/48 を含む)
                || (seg[0] & 0xfe00) == 0xfc00
                // fe80::/10
                || (seg[0] & 0xffc0) == 0xfe80
        }
    }
}

impl<S, B, RB> Service<Request<B>> for ClientFilterService<S>
where
    S: Service<Request<B>, Output = Response<RB>>,
    B: Send + 'static,
    RB: From<String> + Send + 'static,
{
    type Output = Response<RB>;
    type Error = S::Error;

    async fn serve(&self, req: Request<B>) -> Result<Self::Output, Self::Error> {
        if !self.allow_public
            && let Some(info) = req.extensions().get_ref::<SocketInfo>()
        {
            let ip = info.peer_addr().ip_addr;
            if !is_local_client(ip) {
                rama::telemetry::tracing::warn!(%ip, "rejected non-local client");
                let resp = Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(RB::from(String::from("shsw proxy: clients outside the local network are not allowed\n")))
                    .unwrap_or_else(|_| Response::new(RB::from(String::new())));
                return Ok(resp);
            }
        }
        if let Some(expected) = &self.proxy_auth {
            let ok = req
                .headers()
                .get(header::PROXY_AUTHORIZATION)
                .is_some_and(|v| constant_time_eq(v.as_bytes(), expected.as_bytes()));
            if !ok {
                let resp = Response::builder()
                    .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .header(header::PROXY_AUTHENTICATE, "Basic realm=\"shsw\"")
                    .body(RB::from(String::from("proxy authentication required\n")))
                    .unwrap_or_else(|_| Response::new(RB::from(String::new())));
                return Ok(resp);
            }
        }
        self.inner.serve(req).await
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::is_local_client;

    #[test]
    fn local_client_ranges() {
        for ip in ["192.168.1.5", "10.0.0.1", "172.20.0.1", "127.0.0.1", "100.93.177.65", "::1", "fd7a:115c:a1e0::1", "::ffff:192.168.1.2"] {
            assert!(is_local_client(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "100.128.0.1", "2001:4860::8888", "::ffff:8.8.8.8"] {
            assert!(!is_local_client(ip.parse().unwrap()), "{ip}");
        }
    }
}
