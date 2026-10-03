//! shsw-proxy: rama で実装した MITM アクセス制御プロキシ。
//!
//! - HTTP プロキシ (CONNECT) として待ち受け、CONNECT の宛先がルール対象のホストなら
//!   TLS を中継・復号 (TlsMitmRelay) して HTTP リクエスト毎に判定する
//! - ルール対象外のホストは復号せず、そのまま双方向に中継する (Rust 内で完結し高速)
//! - ルールは管理 API とロングポーリングで同期し、CA の差し替えもその場で反映する
//!
//! `shsw-proxy healthcheck` でコンテナのヘルスチェック用に待ち受けポートへ接続確認する。

mod block;
mod ca;
mod rules;
mod state;
mod sync;

use crate::block::{BlockLayer, ClientFilterLayer};
use crate::state::{Shared, Stats};
use arc_swap::ArcSwap;
use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsRef,
    http::{
        client::EasyHttpWebClient,
        conn::H2ClientContextParams,
        layer::{
            map_response_body::MapResponseBodyLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            upgrade::{EagerHttpProxyConnector, UpgradeLayer, mitm::HttpUpgradeMitmRelayLayer},
        },
        matcher::MethodMatcher,
        proxy::mitm::{DefaultErrorResponse, HttpMitmRelay},
        server::HttpServer,
        ws::handshake::{
            matcher::{HttpWebSocketRelayServiceRequestMatcher, WebSocketMatcher},
            mitm::{WebSocketRelayInput, WebSocketRelayOutput, WebSocketRelayService},
        },
    },
    io::{BridgeIo, Io},
    layer::{ArcLayer, ConsumeErrLayer, HijackLayer, MapOutputLayer, TimeoutLayer},
    net::{
        client::ConnectorTarget, http::server::HttpPeekRouter, proxy::IoForwardService,
    },
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::{
        KeyLogIntent,
        boring::proxy::{TlsMitmEgressServerAuth, TlsMitmRelay},
        client::ServerVerifyMode,
        server::PeekTlsClientHelloService,
    },
};
use std::{convert::Infallible, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_owned())
}

fn main() -> Result<(), BoxError> {
    let listen: SocketAddr = env_or("SHSW_LISTEN", "0.0.0.0:8080").parse().context("SHSW_LISTEN")?;
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        let addr = SocketAddr::from(([127, 0, 0, 1], listen.port()));
        return match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
            Ok(_) => Ok(()),
            Err(err) => {
                eprintln!("healthcheck failed: {err}");
                std::process::exit(1)
            }
        };
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("tokio runtime")?
        .block_on(run(listen))
}

async fn run(listen: SocketAddr) -> Result<(), BoxError> {
    use std::io::IsTerminal as _;
    tracing::subscriber::registry()
        .with(fmt::layer().with_ansi(std::io::stdout().is_terminal()))
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .with_env_var("SHSW_LOG")
                .from_env_lossy(),
        )
        .init();

    let cert_dir = PathBuf::from(env_or("SHSW_CERT_DIR", "/certs"));
    let ca_files = ca::CaFiles::from_dir(&cert_dir);
    let sync_cfg = sync::SyncConfig {
        api_url: env_or("SHSW_API_URL", "http://api:8000").trim_end_matches('/').to_owned(),
        internal_token: env_or("SHSW_INTERNAL_TOKEN", ""),
        wait: env_or("SHSW_SYNC_WAIT", "8").parse().unwrap_or(8.0),
        cache_file: cert_dir.join("shsw-ruleset.json"),
        ca_files: ca::CaFiles::from_dir(&cert_dir),
    };
    if sync_cfg.internal_token.is_empty() {
        tracing::warn!("SHSW_INTERNAL_TOKEN is not set; cannot sync with the API");
    }

    // CA は API が生成する。起動直後でまだ無ければ待つ
    let ca = loop {
        match ca::load(&ca_files) {
            Ok(ca) => break ca,
            Err(err) => {
                tracing::warn!(%err, path = %ca_files.cert.display(), "CA not available yet; retrying");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };
    tracing::info!(fingerprint = %ca.fingerprint, "loaded MITM CA");

    let shared = Shared::new(ca.fingerprint.clone());
    sync::load_cache(&shared, &sync_cfg);

    let graceful = rama::graceful::Shutdown::default();
    let exec = Executor::graceful(graceful.guard());

    let mitm = Arc::new(ArcSwap::from_pointee(new_mitm_svc(&exec, &ca, &shared)));
    let reload_ca: sync::CaReloader = {
        let (mitm, exec, shared) = (mitm.clone(), exec.clone(), shared.clone());
        Arc::new(move |ca| mitm.store(Arc::new(new_mitm_svc(&exec, &ca, &shared))))
    };

    graceful.spawn_task(sync::run(shared.clone(), sync_cfg, reload_ca));

    let proxy_auth = proxy_auth_config()?;
    let allow_public = env_or("SHSW_ALLOW_PUBLIC_CLIENTS", "false") == "true";
    if allow_public {
        tracing::warn!("SHSW_ALLOW_PUBLIC_CLIENTS=true: clients from any address are accepted");
    }
    graceful.spawn_task_fn(async move |guard| {
        let tcp_service = TcpListener::build(Executor::graceful(guard.clone()))
            .bind_address(listen)
            .await
            .expect("bind proxy listener");
        tracing::info!(%listen, "shsw proxy listening");

        let relay = ShswConnectRelay {
            shared: shared.clone(),
            mitm,
            forward: IoForwardService::new(exec.clone()),
        };
        let connect = EagerHttpProxyConnector::new(
            TimeoutLayer::new(Duration::from_secs(30)).into_layer(rama::dns::client::DnsConnector::new(
                rama::tcp::client::service::TcpConnector::new(),
            )),
            relay,
        );

        // 平文 HTTP (absolute-form) のリクエストはこのクライアントで中継する
        let web_client = EasyHttpWebClient::default_with_executor(Executor::graceful(guard.clone()));
        let web_client = HijackLayer::new(
            WebSocketMatcher::new(),
            websocket_relay_layer(exec.clone()).into_layer(web_client.clone()),
        )
        .into_layer(
            (RemoveResponseHeaderLayer::hop_by_hop(), RemoveRequestHeaderLayer::hop_by_hop())
                .into_layer(web_client),
        );

        let http_service = HttpServer::auto(exec.clone()).service(Arc::new(
            (
                ConsumeErrLayer::default(),
                ClientFilterLayer::new(allow_public, proxy_auth),
                UpgradeLayer::new(Executor::graceful(guard), MethodMatcher::CONNECT, connect),
                (
                    ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse::new()),
                    MapResponseBodyLayer::new_boxed_streaming_body(),
                    BlockLayer::new(shared),
                    ArcLayer::new(),
                ),
            )
                .into_layer(web_client),
        ));

        tcp_service.serve(http_service).await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(10))
        .await
        .context("graceful shutdown")?;
    Ok(())
}

/// SHSW_PROXY_AUTH=user:pass を指定するとプロキシ認証 (Basic) を要求する
fn proxy_auth_config() -> Result<Option<(String, String)>, BoxError> {
    let value = env_or("SHSW_PROXY_AUTH", "");
    if value.is_empty() {
        return Ok(None);
    }
    let (user, pass) = value.split_once(':').context("SHSW_PROXY_AUTH must be user:pass")?;
    if user.is_empty() || pass.is_empty() {
        return Err(BoxError::from("SHSW_PROXY_AUTH: user and password must not be empty"));
    }
    tracing::info!(user, "proxy authentication enabled");
    Ok(Some((user.to_owned(), pass.to_owned())))
}

/// 上流 HTTP/2 の受信ウィンドウ (MiB)。SHSW_H2_STREAM_WINDOW_MB / SHSW_H2_CONN_WINDOW_MB で調整可
fn h2_windows() -> (u32, u32) {
    static W: std::sync::OnceLock<(u32, u32)> = std::sync::OnceLock::new();
    *W.get_or_init(|| {
        let mib = |key: &str, default: u32| {
            env_or(key, "").parse::<u32>().unwrap_or(default).clamp(1, 1024) * 1024 * 1024
        };
        (mib("SHSW_H2_STREAM_WINDOW_MB", 32), mib("SHSW_H2_CONN_WINDOW_MB", 64))
    })
}

/// CONNECT トンネルの振り分け: ルール対象のホストは MITM、それ以外は素通し
#[derive(Clone)]
struct ShswConnectRelay<M> {
    shared: Arc<Shared>,
    mitm: Arc<ArcSwap<M>>,
    forward: IoForwardService,
}

impl<M, I, E> Service<BridgeIo<I, E>> for ShswConnectRelay<M>
where
    M: Service<BridgeIo<I, E>, Output = (), Error = Infallible>,
    I: Io + Unpin + ExtensionsRef,
    E: Io + Unpin + ExtensionsRef,
{
    type Output = ();
    type Error = Infallible;

    async fn serve(&self, bridge: BridgeIo<I, E>) -> Result<(), Infallible> {
        let host = bridge
            .0
            .extensions()
            .get_ref::<ConnectorTarget>()
            .map(|t| t.0.host.to_string());
        let rules = self.shared.rules.load();
        let intercept = match &host {
            Some(host) => rules.should_intercept(host),
            None => rules.intercept_all,
        };
        drop(rules);

        if intercept {
            Stats::inc(&self.shared.stats.intercepted);
            // 上流との HTTP/2 フロー制御ウィンドウを広げる。既定 (64KiB 程度) のままだと
            // 遠いサーバ (RTT が大きい) からのダウンロードがウィンドウ/RTT で頭打ちになる。
            // 実測: 8MiB/16MiB で約 60Mbps、32MiB/64MiB で直結と同等 (欧州のサーバ, Pi 5)。
            let (stream_window, conn_window) = h2_windows();
            bridge.1.extensions().insert(H2ClientContextParams {
                init_stream_window_size: Some(stream_window),
                init_connection_window_size: Some(conn_window),
                ..Default::default()
            });
            let mitm = self.mitm.load_full();
            mitm.serve(bridge).await
        } else {
            Stats::inc(&self.shared.stats.passthrough);
            if let Err(err) = self.forward.serve(bridge).await {
                tracing::debug!(?err, host, "passthrough relay ended with error");
            }
            Ok(())
        }
    }
}

fn new_mitm_svc<Ingress, Egress>(
    exec: &Executor,
    ca: &ca::LoadedCa,
    shared: &Arc<Shared>,
) -> impl Service<BridgeIo<Ingress, Egress>, Output = (), Error = Infallible> + Clone + use<Ingress, Egress>
where
    Ingress: Io + Unpin + ExtensionsRef,
    Egress: Io + Unpin + ExtensionsRef,
{
    let http_mitm_relay = HttpMitmRelay::new(exec.clone()).with_http_middleware((
        ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse::new()),
        MapResponseBodyLayer::new_boxed_streaming_body(),
        BlockLayer::new(shared.clone()),
        websocket_relay_layer(exec.clone()),
        ArcLayer::new(),
    ));
    // TLS 以外 (CONNECT で平文 HTTP) は HTTP として判定、それ以外のプロトコルは素通し
    let maybe_http_relay = HttpPeekRouter::new(http_mitm_relay)
        .with_known_non_http_protocol_methods()
        .with_fallback(MapOutputLayer::new(drop).into_layer(IoForwardService::new(exec.clone())));

    let tls_mitm_relay = TlsMitmRelay::new_cached_in_memory(ca.cert.clone(), ca.key.clone())
        .with_keylog_intent(KeyLogIntent::Disabled)
        // 上流サーバの証明書は必ず検証する(rama の既定は無検証)
        .with_egress_server_auth(
            TlsMitmEgressServerAuth::new()
                .with_server_verify(ServerVerifyMode::Auto)
                .with_webpki_roots(),
        );

    let app_mitm_relay =
        PeekTlsClientHelloService::new(tls_mitm_relay.into_layer(maybe_http_relay.clone()))
            .with_fallback(maybe_http_relay);

    Arc::new(ConsumeErrLayer::trace_as_debug().into_layer(app_mitm_relay))
}

/// WebSocket は中身を変更せずに中継する
fn websocket_relay_layer(
    exec: Executor,
) -> HttpUpgradeMitmRelayLayer<
    HttpWebSocketRelayServiceRequestMatcher<
        WebSocketRelayService<
            impl Service<WebSocketRelayInput, Output = WebSocketRelayOutput, Error = Infallible> + Clone,
        >,
    >,
> {
    HttpUpgradeMitmRelayLayer::new(
        exec,
        HttpWebSocketRelayServiceRequestMatcher::new(WebSocketRelayService::new(service_fn(
            async |input: WebSocketRelayInput| -> Result<WebSocketRelayOutput, Infallible> {
                Ok(WebSocketRelayOutput {
                    messages: vec![input.message],
                    extensions: input.extensions,
                })
            },
        ))),
    )
}
