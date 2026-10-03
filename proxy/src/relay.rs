//! 接続単位の振り分けと MITM の組み立て。
//!
//! 入口は 2 つあり、どちらも同じ「中継サービス」に流れ込む:
//! - 通常プロキシ: HTTP CONNECT で宛先を受け取り、上流へ接続してから渡す
//! - 透過プロキシ: nftables の REDIRECT で横取りした接続。元の宛先を SO_ORIGINAL_DST で取得する
//!
//! 中継サービスは TLS の ClientHello を覗き、SNI (無ければ接続先ホスト) がルール対象なら
//! TLS を終端して HTTP 単位で判定し、対象外なら復号せずにそのまま中継する。
//! TLS でない通信 (平文 HTTP) は HTTP として判定し、HTTP でもなければ素通しする。

use crate::block::BlockLayer;
use crate::ca::LoadedCa;
use crate::state::{Shared, Stats};
use arc_swap::ArcSwap;
use rama::{
    Layer, Service,
    error::BoxError,
    extensions::ExtensionsRef,
    http::{
        conn::H2ClientContextParams,
        layer::{
            map_response_body::MapResponseBodyLayer, upgrade::mitm::HttpUpgradeMitmRelayLayer,
        },
        proxy::mitm::{DefaultErrorResponse, HttpMitmRelay},
        ws::handshake::{
            matcher::HttpWebSocketRelayServiceRequestMatcher,
            mitm::{WebSocketRelayInput, WebSocketRelayOutput, WebSocketRelayService},
        },
    },
    io::{BridgeIo, Io},
    layer::{ArcLayer, ConsumeErrLayer, MapOutputLayer},
    net::{
        address::HostWithPort, client::ConnectorTarget, http::server::HttpPeekRouter,
        proxy::IoForwardService,
        stream::Socket as _,
    },
    rt::Executor,
    service::service_fn,
    tcp::TcpStream,
    telemetry::tracing,
    tls::{
        KeyLogIntent,
        boring::proxy::{TlsMitmEgressServerAuth, TlsMitmRelay},
        client::ServerVerifyMode,
        server::{InputWithClientHello, PeekTlsClientHelloService},
    },
};
use std::{convert::Infallible, net::SocketAddr, sync::Arc};

/// 上流 HTTP/2 の受信ウィンドウ (バイト)。既定 32MiB / 接続 64MiB。
/// SHSW_H2_STREAM_WINDOW_MB / SHSW_H2_CONN_WINDOW_MB で調整可。
/// 実測: 8MiB/16MiB で約 60Mbps、32MiB/64MiB で直結と同等 (欧州のサーバ, Pi 5)。
fn h2_windows() -> (u32, u32) {
    static W: std::sync::OnceLock<(u32, u32)> = std::sync::OnceLock::new();
    *W.get_or_init(|| {
        let mib = |key: &str, default: u32| {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(default)
                .clamp(1, 1024)
                * 1024
                * 1024
        };
        (mib("SHSW_H2_STREAM_WINDOW_MB", 32), mib("SHSW_H2_CONN_WINDOW_MB", 64))
    })
}

/// 中継サービスを組み立てる (CA を差し替えるたびに作り直す)
pub fn new_relay_svc<Ingress, Egress>(
    exec: &Executor,
    ca: &LoadedCa,
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
    // 平文の HTTP は判定する。HTTP でもないプロトコルは素通し
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

    let decide = SniDecide {
        shared: shared.clone(),
        tls: tls_mitm_relay.into_layer(maybe_http_relay.clone()),
        forward: IoForwardService::new(exec.clone()),
    };
    let svc = PeekTlsClientHelloService::new(decide).with_fallback(maybe_http_relay);
    Arc::new(ConsumeErrLayer::trace_as_debug().into_layer(svc))
}

/// TLS 接続の振り分け: SNI (無ければ接続先) がルール対象なら MITM、それ以外は素通し
#[derive(Clone)]
struct SniDecide<T> {
    shared: Arc<Shared>,
    tls: T,
    forward: IoForwardService,
}

impl<T, I, E> Service<InputWithClientHello<BridgeIo<I, E>>> for SniDecide<T>
where
    T: Service<InputWithClientHello<BridgeIo<I, E>>, Output = (), Error: Into<BoxError>>,
    I: Io + Unpin + ExtensionsRef,
    E: Io + Unpin + ExtensionsRef,
{
    type Output = ();
    type Error = Infallible;

    async fn serve(&self, input: InputWithClientHello<BridgeIo<I, E>>) -> Result<(), Infallible> {
        let host = input
            .client_hello
            .ext_server_name()
            .map(ToString::to_string)
            .or_else(|| {
                input
                    .input
                    .0
                    .extensions()
                    .get_ref::<ConnectorTarget>()
                    .map(|t| t.0.host.to_string())
            });
        let rules = self.shared.rules.load();
        let intercept = match &host {
            Some(host) => rules.should_intercept(host),
            None => rules.intercept_all,
        };
        drop(rules);

        if intercept {
            Stats::inc(&self.shared.stats.intercepted);
            // 上流との HTTP/2 フロー制御ウィンドウを広げる。既定 (小さい) のままだと
            // 遠いサーバ (RTT が大きい) からのダウンロードがウィンドウ/RTT で頭打ちになる。
            let (stream_window, conn_window) = h2_windows();
            input.input.1.extensions().insert(H2ClientContextParams {
                init_stream_window_size: Some(stream_window),
                init_connection_window_size: Some(conn_window),
                ..Default::default()
            });
            if let Err(err) = self.tls.serve(input).await {
                tracing::debug!(error = %err.into(), host, "MITM relay ended with error");
            }
        } else {
            Stats::inc(&self.shared.stats.passthrough);
            if let Err(err) = self.forward.serve(input.input).await {
                tracing::debug!(?err, host, "passthrough relay ended with error");
            }
        }
        Ok(())
    }
}

/// CA の差し替えに対応するため、中継サービスを ArcSwap 越しに呼ぶ
pub struct HotSwap<M>(pub Arc<ArcSwap<M>>);

impl<M> Clone for HotSwap<M> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<M, I, E> Service<BridgeIo<I, E>> for HotSwap<M>
where
    M: Service<BridgeIo<I, E>, Output = (), Error = Infallible>,
    I: Send + 'static,
    E: Send + 'static,
{
    type Output = ();
    type Error = Infallible;

    async fn serve(&self, bridge: BridgeIo<I, E>) -> Result<(), Infallible> {
        let svc = self.0.load_full();
        svc.serve(bridge).await
    }
}

/// 透過プロキシの入口: REDIRECT された接続の元の宛先を ConnectorTarget として付与する
#[derive(Clone)]
pub struct OriginalDst<S> {
    pub inner: S,
    pub listen: SocketAddr,
}

/// nftables/iptables の REDIRECT で書き換えられる前の宛先 (IPv4)
fn original_dst(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    use nix::sys::socket::{getsockopt, sockopt::OriginalDst};
    let sin = getsockopt(stream, OriginalDst).map_err(std::io::Error::from)?;
    let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
    Ok(SocketAddr::from((ip, u16::from_be(sin.sin_port))))
}

impl<S> Service<TcpStream> for OriginalDst<S>
where
    S: Service<TcpStream, Error: Into<BoxError>>,
{
    type Output = ();
    type Error = Infallible;

    async fn serve(&self, stream: TcpStream) -> Result<(), Infallible> {
        let dst = match original_dst(&stream) {
            Ok(dst) => dst,
            Err(err) => {
                tracing::debug!(%err, "transparent: no original destination (not redirected?)");
                return Ok(());
            }
        };
        // 透過用ポートへの直接接続はループになるので拒否
        if dst.port() == self.listen.port()
            && stream.local_addr().is_ok_and(|l| l.ip_addr == dst.ip())
        {
            tracing::debug!(%dst, "transparent: refusing direct connection to the listener");
            return Ok(());
        }
        stream
            .extensions()
            .insert(ConnectorTarget(HostWithPort::from(dst)));
        if let Err(err) = self.inner.serve(stream).await {
            tracing::debug!(error = %err.into(), %dst, "transparent relay ended with error");
        }
        Ok(())
    }
}

/// WebSocket は中身を変更せずに中継する
pub fn websocket_relay_layer(
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
