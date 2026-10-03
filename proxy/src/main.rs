//! shsw-proxy: rama で実装した MITM アクセス制御プロキシ。
//!
//! - HTTP プロキシ (CONNECT) として待ち受け、CONNECT の宛先がルール対象のホストなら
//!   TLS を中継・復号 (TlsMitmRelay) して HTTP リクエスト毎に判定する
//! - ルール対象外のホストは復号せず、そのまま双方向に中継する (Rust 内で完結し高速)
//! - SHSW_TRANSPARENT_LISTEN を指定すると透過プロキシの入口も開く。nftables の REDIRECT で
//!   横取りした接続を、TLS の SNI で同じように振り分ける(ゲートウェイ構成用)
//! - ルールは管理 API とロングポーリングで同期し、CA の差し替えもその場で反映する
//!
//! `shsw-proxy healthcheck` でコンテナのヘルスチェック用に待ち受けポートへ接続確認する。

mod block;
mod ca;
mod relay;
mod rules;
mod state;
mod sync;

use crate::block::{BlockLayer, ClientFilterLayer};
use crate::relay::{HotSwap, OriginalDst, new_relay_svc, websocket_relay_layer};
use crate::state::Shared;
use arc_swap::ArcSwap;
use rama::{
    Layer,
    error::{BoxError, ErrorContext},
    http::{
        client::EasyHttpWebClient,
        layer::{
            map_response_body::MapResponseBodyLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            upgrade::{EagerHttpProxyConnector, UpgradeLayer},
        },
        matcher::MethodMatcher,
        proxy::mitm::DefaultErrorResponse,
        server::HttpServer,
        ws::handshake::matcher::WebSocketMatcher,
    },
    layer::{ArcLayer, ConsumeErrLayer, HijackLayer, TimeoutLayer},
    rt::Executor,
    tcp::{proxy::IoToProxyBridgeIoLayer, server::TcpListener},
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

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

    // 中継サービスは入口ごと (CONNECT / 透過) に型が異なるので 2 つ持ち、CA 変更時は両方作り直す
    let connect_relay = Arc::new(ArcSwap::from_pointee(new_relay_svc(&exec, &ca, &shared)));
    let transparent_relay = Arc::new(ArcSwap::from_pointee(new_relay_svc(&exec, &ca, &shared)));
    let reload_ca: sync::CaReloader = {
        let (c, t, exec, shared) = (connect_relay.clone(), transparent_relay.clone(), exec.clone(), shared.clone());
        Arc::new(move |ca| {
            c.store(Arc::new(new_relay_svc(&exec, &ca, &shared)));
            t.store(Arc::new(new_relay_svc(&exec, &ca, &shared)));
        })
    };

    graceful.spawn_task(sync::run(shared.clone(), sync_cfg, reload_ca));

    // 透過プロキシの入口 (ゲートウェイ構成)
    let transparent_listen: Option<SocketAddr> = match env_or("SHSW_TRANSPARENT_LISTEN", "") {
        v if v.is_empty() => None,
        v => Some(v.parse().context("SHSW_TRANSPARENT_LISTEN")?),
    };
    if let Some(addr) = transparent_listen {
        graceful.spawn_task_fn(async move |guard| {
            let listener = TcpListener::build(Executor::graceful(guard))
                .bind_address(addr)
                .await
                .expect("bind transparent listener");
            tracing::info!(listen = %addr, "transparent proxy listening");
            let svc = OriginalDst {
                inner: IoToProxyBridgeIoLayer::extension_connector_target()
                    .into_layer(HotSwap(transparent_relay)),
                listen: addr,
            };
            listener.serve(svc).await;
        });
    }

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

        let connect = EagerHttpProxyConnector::new(
            TimeoutLayer::new(Duration::from_secs(30)).into_layer(rama::dns::client::DnsConnector::new(
                rama::tcp::client::service::TcpConnector::new(),
            )),
            HotSwap(connect_relay),
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

