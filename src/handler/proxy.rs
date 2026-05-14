// HTTP reverse proxy handler: forwards requests to an upstream HTTP
// server, adds X-Forwarded-For, and streams the response back.  Uses
// hyper-util's legacy client for connection pooling.
//
// When proxy-protocol is configured, each request opens a fresh
// connection (no pooling) and prepends the PROXY header before the
// HTTP traffic.  Connection reuse is incompatible with PROXY protocol
// because the header encodes the client IP at connection establishment.
// Both TCP and Unix socket upstreams are supported in this mode.

use crate::config::ProxyProtocolVersion;
use crate::error::{HttpResponse, response_502};
use crate::error::ReqBody;
use crate::listener::{LocalAddr, LocalUnixPath};
use crate::proxy_proto;
use http_body_util::{BodyExt, combinators::UnsyncBoxBody};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, Uri, Version};
use hyper_rustls::{ConfigBuilderExt, HttpsConnector};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

// Body type used for requests sent to the upstream.
// UnsyncBoxBody matches ReqBody's looser bound (Send, !Sync) so the
// streaming HTTP/3 request body can be forwarded directly to the
// hyper-util Client without a re-box.  The Client's body bound is
// `Send + 'static`, not Sync, so the relaxation is sound.
type UpstreamBody = UnsyncBoxBody<bytes::Bytes, hyper::Error>;

// Custom Tower connector for HTTP-over-Unix-domain-socket.  The URI passed
// to `call` is ignored; all connections go to the fixed socket path.
#[cfg(unix)]
#[derive(Clone)]
struct UnixConnector {
    path: std::path::PathBuf,
}

#[cfg(unix)]
impl tower_service::Service<Uri> for UnixConnector {
    type Response = hyper_util::rt::TokioIo<tokio::net::UnixStream>;
    type Error = io::Error;
    type Future = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = io::Result<Self::Response>> + Send,
        >,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let path = self.path.clone();
        Box::pin(async move {
            let stream = tokio::net::UnixStream::connect(&path).await?;
            Ok(hyper_util::rt::TokioIo::new(stream))
        })
    }
}

// Client variants: TCP (h1/h2 over http/https), Unix sockets, or
// QUIC (HTTP/3).
#[allow(clippy::large_enum_variant)]
enum ProxyClient {
    Http(Client<HttpsConnector<HttpConnector>, UpstreamBody>),
    #[cfg(unix)]
    Unix(Client<UnixConnector, UpstreamBody>),
    /// HTTP/3 over QUIC.  Holds a long-lived `quinn::Endpoint` shared
    /// across requests; each request opens a fresh QUIC connection
    /// (no pooling in v1 -- the same place to grow it later).
    H3(H3Client),
}

/// Reusable HTTP/3 client state for one upstream URL.  Built once when
/// the proxy handler is constructed; reused across every request.  The
/// `quinn::Endpoint` carries a UDP socket bound to `[::]:0` and a
/// pre-built rustls ClientConfig with `h3` ALPN.
pub(crate) struct H3Client {
    endpoint: quinn::Endpoint,
    authority: hyper::http::uri::Authority,
    /// SNI server name (host component of the upstream URL).
    server_name: String,
    /// Shared metrics handle, incremented on every fresh handshake.
    metrics: Option<Arc<crate::metrics::Metrics>>,
    /// Cached connection + h3 send-half.  Reused across requests so
    /// subsequent calls skip the 1-RTT handshake.  `None` until the
    /// first request, or after the connection is observed closed or
    /// reaped for inactivity.
    cached: Arc<tokio::sync::Mutex<Option<H3Cached>>>,
    /// Idle-timeout reaper handle.  `None` when reaping is disabled
    /// (`pool-idle-timeout 0`).  Aborted on `H3Client` drop so the
    /// background task doesn't outlive the handler.
    reaper: Option<tokio::task::JoinHandle<()>>,
    /// Optional bound on the QUIC connect handshake.  Applied via
    /// `tokio::time::timeout` around `endpoint.connect().await`.
    /// `None` keeps quinn's defaults.
    connect_timeout: Option<std::time::Duration>,
}

impl Drop for H3Client {
    fn drop(&mut self) {
        if let Some(h) = self.reaper.take() {
            h.abort();
        }
    }
}

/// Holds the live state for one cached QUIC connection.  Dropping a
/// `H3Cached` aborts its driver task, closing the QUIC connection.
struct H3Cached {
    conn: quinn::Connection,
    send: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    /// Driver task that pumps the h3 state machine until close.
    /// Aborted when the cached entry is replaced.
    drive: tokio::task::JoinHandle<()>,
    /// Last time `send_handle` returned a clone of this entry.  Read
    /// by the idle reaper to decide whether to evict.
    last_used: std::time::Instant,
}

impl Drop for H3Cached {
    fn drop(&mut self) {
        self.drive.abort();
    }
}

impl H3Client {
    /// Default idle timeout for cached upstream connections.  Matches
    /// hyper-util's `pool_idle_timeout` default so operators see
    /// consistent eviction behaviour across h1/h2 and h3.
    const DEFAULT_IDLE_TIMEOUT: std::time::Duration =
        std::time::Duration::from_secs(90);

    fn new(
        upstream: &Uri,
        pool_idle: Option<std::time::Duration>,
    ) -> anyhow::Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self::new_with_crypto(upstream, crypto, pool_idle)
    }

    /// Constructs a client whose TLS verifier accepts any certificate.
    /// Intended for internal upstreams with self-signed certs
    /// (`proxy { tls { skip-verify } }`).  Operators take
    /// responsibility for the relaxed trust by opting in explicitly.
    pub(crate) fn new_skip_verify(
        upstream: &Uri,
        pool_idle: Option<std::time::Duration>,
    ) -> anyhow::Result<Self> {
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(
                SkipServerVerification,
            ))
            .with_no_client_auth();
        Self::new_with_crypto(upstream, crypto, pool_idle)
    }

    /// Convenience wrapper for unit tests against local self-signed
    /// listeners.  Routes to the same skip-verify path as the
    /// production opt-in.
    #[cfg(test)]
    pub(crate) fn new_for_test(
        upstream: &Uri,
        pool_idle: Option<std::time::Duration>,
    ) -> anyhow::Result<Self> {
        Self::new_skip_verify(upstream, pool_idle)
    }

    fn new_with_crypto(
        upstream: &Uri,
        mut crypto: rustls::ClientConfig,
        pool_idle: Option<std::time::Duration>,
    ) -> anyhow::Result<Self> {
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let quic_cfg =
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| anyhow::anyhow!("rustls→quic: {e}"))?;
        let client_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));
        let mut endpoint = quinn::Endpoint::client(
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
        )?;
        endpoint.set_default_client_config(client_cfg);
        let authority = upstream
            .authority()
            .ok_or_else(|| anyhow::anyhow!("upstream has no authority"))?
            .clone();
        let server_name = authority.host().to_owned();
        // Validate the SNI name parses as a valid rustls ServerName so
        // we fail fast at config time, not at first request.
        let _ = <rustls::pki_types::ServerName<'_>>::try_from(
            server_name.as_str(),
        )
        .map_err(|e| anyhow::anyhow!("bad upstream host {server_name:?}: {e}"))?;
        // Idle reaper: 0 disables, None falls back to the default.
        // Cached entries are evicted when `last_used + idle < now`
        // so an upstream that goes quiet doesn't keep QUIC state
        // open indefinitely on either side.
        let cached: Arc<tokio::sync::Mutex<Option<H3Cached>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let reaper = match pool_idle {
            Some(d) if d.is_zero() => None,
            d => {
                let idle = d.unwrap_or(Self::DEFAULT_IDLE_TIMEOUT);
                // Tick at idle/4 so eviction lag is bounded at 25% of
                // the configured timeout.  Subseconds is fine: a 1 s
                // timeout ticks 4x/s.
                let tick =
                    std::cmp::max(idle / 4, std::time::Duration::from_millis(50));
                let cached = cached.clone();
                Some(tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(tick).await;
                        let mut g = cached.lock().await;
                        let evict = g
                            .as_ref()
                            .map(|c| c.last_used.elapsed() >= idle)
                            .unwrap_or(false);
                        if evict {
                            if let Some(c) = g.take() {
                                c.conn.close(
                                    quinn::VarInt::from_u32(0),
                                    b"idle",
                                );
                                tracing::debug!(
                                    "h3 outbound pool: reaped idle connection"
                                );
                            }
                        }
                    }
                }))
            }
        };
        Ok(Self {
            endpoint,
            authority,
            server_name,
            metrics: None,
            cached,
            reaper,
            connect_timeout: None,
        })
    }

    /// Resolve the upstream authority to a single SocketAddr.  A real
    /// pool would do happy-eyeballs across all results; here we take
    /// the first match per call.
    async fn resolve(&self) -> anyhow::Result<std::net::SocketAddr> {
        let port = self.authority.port_u16().unwrap_or(443);
        let addrs: Vec<std::net::SocketAddr> =
            tokio::net::lookup_host((self.server_name.as_str(), port))
                .await?
                .collect();
        addrs
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("no addresses for upstream"))
    }

    /// Build a fresh `H3Cached`: connect, h3-handshake, spawn driver.
    async fn build_cached(&self) -> anyhow::Result<H3Cached> {
        let addr = self.resolve().await?;
        let connecting = self.endpoint.connect(addr, &self.server_name)?;
        // Bound the handshake when `connect_timeout` is set; otherwise
        // let quinn's defaults stand (5 s handshake deadline + idle).
        let conn = match self.connect_timeout {
            Some(d) => tokio::time::timeout(d, connecting)
                .await
                .map_err(|_| anyhow::anyhow!("quinn connect: timed out"))?
                .map_err(|e| anyhow::anyhow!("quinn connect: {e}"))?,
            None => connecting
                .await
                .map_err(|e| anyhow::anyhow!("quinn connect: {e}"))?,
        };
        if let Some(m) = &self.metrics {
            m.quic_outbound_handshakes_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let quic = h3_quinn::Connection::new(conn.clone());
        let (mut driver, send) = h3::client::new(quic)
            .await
            .map_err(|e| anyhow::anyhow!("h3 client setup: {e}"))?;
        let drive = tokio::spawn(async move {
            let _ =
                std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        Ok(H3Cached {
            conn,
            send,
            drive,
            last_used: std::time::Instant::now(),
        })
    }

    /// Return a `SendRequest` cloned from a live cached connection,
    /// reconnecting transparently if the cache is empty or the
    /// existing connection has closed.  The cache holds at most one
    /// connection per handler -- sufficient for the current model
    /// where each `ProxyHandler` points at one upstream.
    async fn send_handle(
        &self,
    ) -> anyhow::Result<
        h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    > {
        let mut g = self.cached.lock().await;
        if let Some(c) = g.as_mut()
            && c.conn.close_reason().is_none()
        {
            // Touch last_used so the reaper sees recent activity.
            c.last_used = std::time::Instant::now();
            return Ok(c.send.clone());
        }
        // Build a new connection; replace any stale entry.
        let cached = self.build_cached().await?;
        let send = cached.send.clone();
        *g = Some(cached);
        Ok(send)
    }

    /// Drop the cached connection so the next `send_handle` call
    /// reconnects.  Called when a connection-level error is observed
    /// during a request.
    async fn evict_cached(&self) {
        let mut g = self.cached.lock().await;
        *g = None;
    }

    pub(crate) async fn request(
        &self,
        req: Request<UpstreamBody>,
    ) -> anyhow::Result<HttpResponse> {
        // Run the request and, on *any* failure past the point where
        // a cached connection has been observed, evict the cache so
        // the next call to `request` reconnects.  The current request
        // body isn't replayable (UnsyncBoxBody is !Clone) so we
        // don't retry in-flight -- but a subsequent caller's request
        // sees a fresh connection.
        match self.request_inner(req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                self.evict_cached().await;
                Err(e)
            }
        }
    }

    async fn request_inner(
        &self,
        req: Request<UpstreamBody>,
    ) -> anyhow::Result<HttpResponse> {
        use bytes::Buf;
        use http_body_util::BodyExt;

        let mut send_request = self.send_handle().await?;

        let (parts, body) = req.into_parts();
        let head = Request::from_parts(parts, ());
        // If the cached connection died between the cache check and
        // the actual send_request, `send_request` returns an error.
        // Evict and retry once with a fresh connection.  This race
        // is common right after the server sends CONNECTION_CLOSE:
        // close_reason() lags by a few hundred microseconds, so the
        // first send on the next request can land on a dying conn.
        let mut stream = match send_request.send_request(head.clone()).await
        {
            Ok(s) => s,
            Err(_) => {
                self.evict_cached().await;
                send_request = self.send_handle().await?;
                send_request
                    .send_request(head)
                    .await
                    .map_err(|e| anyhow::anyhow!("h3 send_request: {e}"))?
            }
        };

        // Forward the request body frame-by-frame so large uploads
        // don't materialise in memory.  Mirrors the response-side
        // pattern used by `send_h3_response` in listener.rs.
        let mut body = body;
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| {
                anyhow::anyhow!("read request body: {e}")
            })?;
            if frame.is_data() {
                let data = frame.into_data().map_err(|_| {
                    anyhow::anyhow!("frame::into_data race")
                })?;
                stream
                    .send_data(data)
                    .await
                    .map_err(|e| anyhow::anyhow!("h3 send_data: {e}"))?;
            } else if frame.is_trailers() {
                let map = frame.into_trailers().map_err(|_| {
                    anyhow::anyhow!("frame::into_trailers race")
                })?;
                stream
                    .send_trailers(map)
                    .await
                    .map_err(|e| anyhow::anyhow!("h3 send_trailers: {e}"))?;
                // Trailers terminate the request stream; no further
                // data is permitted by h3.
                break;
            }
        }
        stream
            .finish()
            .await
            .map_err(|e| anyhow::anyhow!("h3 finish: {e}"))?;

        // Receive the response head + body.
        let resp = stream
            .recv_response()
            .await
            .map_err(|e| anyhow::anyhow!("h3 recv_response: {e}"))?;
        let (mut resp_parts, ()) = resp.into_parts();
        // The upstream response arrives with version=HTTP_3 set by h3.
        // We forward it over h1/h2 to the downstream client; hyper's
        // h1 codec specifically panics if asked to serialise HTTP/3
        // on the wire.  Reset to the protocol-agnostic default so the
        // listener-side codec picks the right wire format based on
        // the *inbound* connection, not the upstream's.
        resp_parts.version = hyper::Version::default();

        // Stream the upstream response body via an mpsc channel.
        // The pump task confines the !Sync h3 RecvStream; the
        // downstream-facing `BoxBody` only sees a Send+Sync
        // ReceiverStream so it satisfies BoxBody's bounds.  Note
        // that `send_request` and the driver task stay in the pool
        // -- only the per-request `stream` moves into the pump.
        let (tx, rx) = tokio::sync::mpsc::channel::<
            Result<hyper::body::Frame<bytes::Bytes>, std::io::Error>,
        >(4);
        tokio::spawn(async move {
            loop {
                match stream.recv_data().await {
                    Ok(Some(mut chunk)) => {
                        let n = chunk.remaining();
                        let b = chunk.copy_to_bytes(n);
                        if tx
                            .send(Ok(hyper::body::Frame::data(b)))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        let _ = tx
                            .send(Err(std::io::Error::other(
                                format!("h3 recv_data: {e}"),
                            )))
                            .await;
                        break;
                    }
                }
            }
        });
        let body_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        let body = http_body_util::StreamBody::new(body_stream).boxed();
        Ok(Response::from_parts(resp_parts, body))
    }
}

// Hop-by-hop headers that must not be forwarded (RFC 7230 s.6.1).
// These are connection-specific and meaningless to the next hop.
static HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

pub struct ProxyHandler {
    // The client maintains a connection pool keyed by authority.
    // Stored in Arc<Handler> by the router, so it is shared across
    // all requests to this location.
    client: ProxyClient,
    upstream: Uri,
    strip_prefix: bool,
    proxy_protocol: Option<ProxyProtocolVersion>,
    // Filesystem path for unix: upstreams; used by serve_with_proxy_protocol
    // to open a fresh UnixStream (the pooled client handles normal requests).
    #[cfg(unix)]
    unix_path: Option<std::path::PathBuf>,
    // Auto-discovered HTTP/3 upgrade hint, parsed from upstream
    // `Alt-Svc` response headers when the handler is in `scheme=auto`.
    // Lazily populated `H3Client` keyed by the alt-port from the hint
    // so subsequent requests can upgrade transparently.
    h3_hint: Arc<tokio::sync::Mutex<Option<H3Hint>>>,
    /// Lazy H3Client built on first auto-upgrade.  Wrapped in `Arc`
    /// so `try_upgrade_to_h3` can hand a clone back to the caller
    /// without releasing the slot.
    h3_lazy: Arc<tokio::sync::Mutex<Option<Arc<H3Client>>>>,
    // Captured construction parameters used to build the lazy
    // `H3Client` on first upgrade.  Avoid re-parsing config at
    // request time.
    h3_params: H3LazyParams,
    // `true` when this handler was configured with the default
    // `scheme=auto`; `false` for explicit `scheme=h3` (already h3)
    // or for non-https upstreams that can't upgrade.
    auto_h3_enabled: bool,
}

/// Captured `H3Client` builder parameters for lazy construction on
/// Alt-Svc upgrade.  Cloneable because `Mutex<Option<H3Client>>`
/// holds the actual client; this struct just records how to build it.
#[derive(Clone)]
struct H3LazyParams {
    upstream: Uri,
    skip_verify: bool,
    pool_idle: Option<std::time::Duration>,
    connect_timeout: Option<std::time::Duration>,
}

/// One Alt-Svc cache entry.  The port may differ from the upstream
/// URL's port (e.g. an https upstream on 443 advertising h3 on 8443).
struct H3Hint {
    port: u16,
    expires_at: std::time::Instant,
}

/// Cap on the advertised max-age so a misconfigured upstream can't
/// pin us to h3 for an unreasonably long time.  24 hours matches
/// what browsers like Chrome use for similar Alt-Svc caches.
const MAX_ALT_SVC_MA_SECS: u64 = 24 * 3600;

/// Extract the first `h3=":<port>"; ma=<seconds>` entry from an
/// `Alt-Svc` header value, ignoring other ALPNs and `clear`.  Returns
/// `None` if the header doesn't advertise h3 or `ma` is zero.
///
/// We accept the most common shapes:
///
///   h3=":443"; ma=86400
///   h3=":8443"; ma=86400; persist=1
///   h3-29=":443"; ma=3600, h3=":443"; ma=3600
///
/// and ignore anything we don't recognise.  Hand-rolled rather than
/// pulling in a full RFC-7838 parser because we only care about one
/// protocol identifier (`h3`) and one parameter (`ma`).
fn parse_alt_svc_h3(value: &str) -> Option<(u16, u64)> {
    // The header value is comma-separated alt-services; pick the
    // first that matches h3=":port" and has ma>0.
    for entry in value.split(',') {
        let mut parts = entry.split(';').map(str::trim);
        let head = parts.next()?;
        let (proto, rest) = head.split_once('=')?;
        if proto.trim() != "h3" {
            continue;
        }
        // rest is `":port"` or `"port"` (we accept both; the spec
        // requires the leading colon but be lenient).
        let port_str = rest.trim().trim_matches('"');
        let port_str = port_str.strip_prefix(':').unwrap_or(port_str);
        let port: u16 = port_str.parse().ok()?;
        let mut ma: Option<u64> = None;
        for param in parts {
            if let Some(rest) = param.strip_prefix("ma=") {
                ma = rest.trim().parse().ok();
            }
        }
        let ma = ma?;
        if ma == 0 {
            continue;
        }
        return Some((port, ma));
    }
    None
}

impl ProxyHandler {
    pub fn new(
        upstream_str: &str,
        strip_prefix: bool,
        proxy_protocol: Option<ProxyProtocolVersion>,
        scheme: crate::config::ProxyUpstreamScheme,
        pool_idle_timeout_secs: Option<u64>,
        pool_max_idle: Option<u32>,
        skip_verify: bool,
        connect_timeout_secs: Option<u64>,
    ) -> anyhow::Result<Self> {
        let connect_timeout =
            connect_timeout_secs.map(std::time::Duration::from_secs);
        // Hyper-util's default pool_idle_timeout is 90 s; honour the
        // operator's override or keep the default.  Used for both the
        // h1/h2 hyper-util Client below and the h3 reaper.
        let pool_idle =
            pool_idle_timeout_secs.map(std::time::Duration::from_secs);
        let mut http_builder = Client::builder(TokioExecutor::new());
        if let Some(d) = pool_idle {
            http_builder.pool_idle_timeout(d);
        }
        if let Some(n) = pool_max_idle {
            http_builder.pool_max_idle_per_host(n as usize);
        }

        // Unix domain socket upstream: "unix:/path/to/socket"
        #[cfg(unix)]
        if let Some(path) = upstream_str.strip_prefix("unix:") {
            let connector = UnixConnector { path: path.into() };
            let client = http_builder.build(connector);
            // The URI authority is irrelevant; the connector ignores it.
            // Use "http://localhost" so that Host: localhost is sent, which
            // is the conventional value for Unix-socket HTTP backends.
            let upstream: Uri =
                "http://localhost".parse().expect("static URI is valid");
            return Ok(Self {
                client: ProxyClient::Unix(client),
                upstream,
                strip_prefix,
                proxy_protocol,
                unix_path: Some(path.into()),
                h3_hint: Arc::new(tokio::sync::Mutex::new(None)),
                h3_lazy: Arc::new(tokio::sync::Mutex::new(None)),
                // Unix upstreams can't ever upgrade to h3.
                h3_params: H3LazyParams {
                    upstream: "http://localhost"
                        .parse()
                        .expect("static URI is valid"),
                    skip_verify: false,
                    pool_idle,
                    connect_timeout,
                },
                auto_h3_enabled: false,
            });
        }
        #[cfg(not(unix))]
        if upstream_str.starts_with("unix:") {
            anyhow::bail!("unix: upstream not supported on this platform");
        }

        let upstream: Uri = upstream_str.parse().map_err(|_| {
            anyhow::anyhow!("invalid upstream URL: {upstream_str}")
        })?;
        match upstream.scheme_str() {
            Some("http") | Some("https") => {}
            _ => anyhow::bail!(
                "upstream '{upstream_str}' must use http or https scheme"
            ),
        }
        if upstream.authority().is_none() {
            anyhow::bail!("upstream '{upstream_str}' must include a host");
        }
        // H3: route through quinn instead of the h1/h2 hyper-util Client.
        if scheme == crate::config::ProxyUpstreamScheme::H3 {
            let mut h3 = if skip_verify {
                H3Client::new_skip_verify(&upstream, pool_idle)?
            } else {
                H3Client::new(&upstream, pool_idle)?
            };
            h3.connect_timeout = connect_timeout;
            return Ok(Self {
                client: ProxyClient::H3(h3),
                upstream: upstream.clone(),
                strip_prefix,
                proxy_protocol,
                #[cfg(unix)]
                unix_path: None,
                // Already h3 -- no auto-discovery needed.
                h3_hint: Arc::new(tokio::sync::Mutex::new(None)),
                h3_lazy: Arc::new(tokio::sync::Mutex::new(None)),
                h3_params: H3LazyParams {
                    upstream,
                    skip_verify,
                    pool_idle,
                    connect_timeout,
                },
                auto_h3_enabled: false,
            });
        }

        // HttpsConnector handles both http:// and https:// upstreams.
        // Mozilla WebPKI roots are bundled; no OS cert store dependency.
        // Both ALPN protocols are enabled so https:// upstreams that
        // advertise h2 get HTTP/2 (with multiplexing + header
        // compression), and h1-only backends fall back transparently.
        // When the operator opted into skip-verify (internal upstream
        // with a self-signed cert), build a rustls ClientConfig with
        // the permissive verifier instead of webpki roots.
        let mut http_conn = HttpConnector::new();
        http_conn.enforce_http(false); // allow https URIs
        if let Some(d) = connect_timeout {
            http_conn.set_connect_timeout(Some(d));
        }
        let https_builder = if skip_verify {
            // Don't set alpn_protocols here: hyper-rustls 0.27's
            // `with_tls_config` panics if ALPN is pre-populated.
            // The builder injects the right ALPN list based on the
            // subsequent `enable_http1()` / `enable_http2()` calls.
            let crypto = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(
                    SkipServerVerification,
                ))
                .with_no_client_auth();
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(crypto)
        } else {
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_webpki_roots()
        };
        let connector = https_builder
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http_conn);
        let client = http_builder.build(connector);
        // Auto-discovery only makes sense for https upstreams that
        // could plausibly advertise h3 over QUIC.  Plaintext http://
        // upstreams keep the cache disabled so we never try to
        // upgrade them.
        let auto_h3_enabled = upstream_str.starts_with("https://");
        Ok(Self {
            client: ProxyClient::Http(client),
            upstream: upstream.clone(),
            strip_prefix,
            proxy_protocol,
            #[cfg(unix)]
            unix_path: None,
            h3_hint: Arc::new(tokio::sync::Mutex::new(None)),
            h3_lazy: Arc::new(tokio::sync::Mutex::new(None)),
            h3_params: H3LazyParams {
                upstream,
                skip_verify,
                pool_idle,
                connect_timeout,
            },
            auto_h3_enabled,
        })
    }

    /// Inject the shared Metrics handle so the H3 client variant can
    /// increment the outbound handshake counter.  A no-op for h1/h2 +
    /// Unix variants; metrics for those flow through the request
    /// pipeline elsewhere.
    pub fn set_metrics(&mut self, metrics: Arc<crate::metrics::Metrics>) {
        if let ProxyClient::H3(h) = &mut self.client {
            h.metrics = Some(metrics);
        }
    }

    pub async fn serve(
        &self,
        req: Request<ReqBody>,
        matched_prefix: &str,
    ) -> HttpResponse {
        if let Some(version) = self.proxy_protocol {
            return self
                .serve_with_proxy_protocol(req, matched_prefix, version)
                .await;
        }
        let backend_req =
            match self.prepare_backend_request(req, matched_prefix) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("proxy: failed to build backend URI: {e}");
                    return response_502();
                }
            };

        // HTTP/3 takes a separate path because the response body is
        // produced by h3, not hyper's Incoming, so we can't share
        // `convert_response`.
        if let ProxyClient::H3(h3) = &self.client {
            return match h3.request(backend_req).await {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::error!("proxy h3: backend request failed: {e:#}");
                    response_502()
                }
            };
        }

        // Auto-h3 upgrade: if the upstream has previously advertised
        // `Alt-Svc: h3=...` within the cached `ma` window, build (or
        // reuse) a lazy H3Client and route through it.  Falls back to
        // h1/h2 on h3 failure, evicting the hint so the next request
        // doesn't re-attempt the bad upgrade.
        if self.auto_h3_enabled
            && let Some(h3) = self.try_upgrade_to_h3().await
        {
            match h3.request(backend_req).await {
                Ok(resp) => return resp,
                Err(e) => {
                    tracing::debug!(
                        "h3 upgrade failed, falling back to h1/h2: {e:#}"
                    );
                    // Evict the hint so we don't loop on a bad cache
                    // entry; the next response's Alt-Svc may re-arm it.
                    *self.h3_hint.lock().await = None;
                    // Rebuild the backend request: the previous body
                    // was consumed by the failed h3 path.  We can't
                    // safely retry mid-flight without replayable
                    // bodies, so return 502 -- matches the existing
                    // shape for any other backend failure.
                    return response_502();
                }
            }
        }

        let result = match &self.client {
            ProxyClient::Http(c) => c.request(backend_req).await,
            #[cfg(unix)]
            ProxyClient::Unix(c) => c.request(backend_req).await,
            ProxyClient::H3(_) => unreachable!("H3 handled above"),
        };
        match result {
            Ok(resp) => {
                // Inspect Alt-Svc on the upstream response before
                // converting -- a non-zero `h3=...; ma=...` arms the
                // auto-upgrade cache for subsequent requests.
                if self.auto_h3_enabled {
                    self.absorb_alt_svc(resp.headers()).await;
                }
                convert_response(resp)
            }
            Err(e) => {
                tracing::error!("proxy: backend request failed: {e}");
                response_502()
            }
        }
    }

    /// Parse `Alt-Svc` response headers; if an `h3=":<port>"; ma=N`
    /// entry is present (with N>0), arm the auto-upgrade cache.
    /// Best-effort: malformed headers are silently ignored.
    ///
    /// Refuses to redirect h3 traffic to a *privileged* port
    /// (< 1024) unless that port happens to match the original
    /// upstream URL's port -- this blocks a compromised upstream
    /// from advertising e.g. `h3=":22"` and tricking the proxy
    /// into sending QUIC datagrams at a local SSH/SMTP listener.
    /// Cert verification would still apply, but no need to even
    /// open the socket.
    async fn absorb_alt_svc(&self, headers: &hyper::HeaderMap) {
        let original_port = self
            .h3_params
            .upstream
            .port_u16()
            .unwrap_or(443);
        for v in headers.get_all(hyper::header::ALT_SVC).iter() {
            let Ok(s) = v.to_str() else { continue };
            if let Some((port, ma)) = parse_alt_svc_h3(s) {
                if port < 1024 && port != original_port {
                    tracing::warn!(
                        port,
                        "ignoring Alt-Svc h3 redirect to privileged \
                         port that doesn't match the upstream URL"
                    );
                    continue;
                }
                let expires_at = std::time::Instant::now()
                    + std::time::Duration::from_secs(
                        ma.min(MAX_ALT_SVC_MA_SECS),
                    );
                *self.h3_hint.lock().await =
                    Some(H3Hint { port, expires_at });
                tracing::debug!(
                    port,
                    ma,
                    "armed h3 auto-upgrade hint from upstream Alt-Svc"
                );
                return;
            }
        }
    }

    /// If a fresh h3 hint exists, ensure the lazy `H3Client` is built
    /// and return a reference to it.  Returns None when no upgrade
    /// is currently warranted (no hint, expired, or build failure).
    async fn try_upgrade_to_h3(&self) -> Option<Arc<H3Client>> {
        let port = {
            let mut g = self.h3_hint.lock().await;
            let entry = g.as_ref()?;
            if entry.expires_at <= std::time::Instant::now() {
                *g = None;
                return None;
            }
            entry.port
        };
        let mut lazy = self.h3_lazy.lock().await;
        if lazy.is_none() {
            // Rebuild the upstream URL with the alt-svc port so the
            // h3 client connects to the advertised endpoint, not the
            // original h1/h2 port.
            let host = self.h3_params.upstream.host()?;
            let alt_url = format!("https://{host}:{port}/")
                .parse::<Uri>()
                .ok()?;
            let mut h3 = if self.h3_params.skip_verify {
                H3Client::new_skip_verify(
                    &alt_url,
                    self.h3_params.pool_idle,
                )
                .ok()?
            } else {
                H3Client::new(&alt_url, self.h3_params.pool_idle).ok()?
            };
            h3.connect_timeout = self.h3_params.connect_timeout;
            *lazy = Some(Arc::new(h3));
        }
        lazy.clone()
    }

    fn prepare_backend_request(
        &self,
        req: Request<ReqBody>,
        matched_prefix: &str,
    ) -> anyhow::Result<Request<UpstreamBody>> {
        let peer_ip = req
            .extensions()
            .get::<SocketAddr>()
            .map(|a| a.ip().to_string());

        let backend_uri = build_backend_uri(
            &self.upstream,
            req.uri(),
            matched_prefix,
            self.strip_prefix,
        )?;

        let (mut parts, body) = req.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        set_forwarding_headers(&mut parts.headers, peer_ip.as_deref());
        parts.uri = backend_uri;
        // Don't pin the request version: hyper-util's Client picks
        // h1 or h2 based on the ALPN negotiated with the upstream.
        // For h1 (the prior behaviour for everything), this is
        // equivalent; for h2-capable upstreams we now get
        // multiplexing + HPACK on the wire.
        parts.version = Version::default();
        if let Some(authority) = self.upstream.authority()
            && let Ok(v) = HeaderValue::from_str(authority.as_str())
        {
            parts.headers.insert(hyper::header::HOST, v);
        }
        Ok(Request::from_parts(parts, body.boxed_unsync()))
    }

    // Open a fresh connection per request, write the PROXY header,
    // then send HTTP/1.1 over the raw socket.  No connection pooling.
    // Supports both TCP and Unix socket upstreams.
    async fn serve_with_proxy_protocol(
        &self,
        req: Request<ReqBody>,
        matched_prefix: &str,
        version: ProxyProtocolVersion,
    ) -> HttpResponse {
        // SocketAddr extension is absent for Unix-socket peers; treat
        // its absence as "no real address info" rather than 0.0.0.0:0.
        let src = req.extensions().get::<SocketAddr>().copied();
        let dst_tcp = req.extensions().get::<LocalAddr>().map(|a| a.0);
        let dst_unix =
            req.extensions().get::<LocalUnixPath>().map(|p| p.0.clone());

        let backend_req =
            match self.prepare_backend_request(req, matched_prefix) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("proxy: failed to build backend URI: {e}");
                    return response_502();
                }
            };

        let header = match src {
            Some(src_addr) => {
                // TCP peer: use real addresses.
                let dst = dst_tcp
                    .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
                proxy_proto::build_header(version, src_addr, dst)
            }
            None => match version {
                // Unix-socket peer: emit correct non-TCP encoding.
                ProxyProtocolVersion::V1 => proxy_proto::build_v1_unknown(),
                ProxyProtocolVersion::V2 => match dst_unix.as_deref() {
                    // AF_UNIX with listener path as dst when known.
                    Some(p) => proxy_proto::build_v2_unix(None, Some(p)),
                    // UNSPEC when no path is available.
                    None => proxy_proto::build_v2_unspec(),
                },
            },
        };

        // Unix socket upstream: connect, write PROXY header, send HTTP/1.1.
        #[cfg(unix)]
        if let Some(path) = &self.unix_path {
            let mut stream = match tokio::net::UnixStream::connect(path).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("proxy: unix upstream connect failed: {e}");
                    return response_502();
                }
            };
            if let Err(e) = stream.write_all(&header).await {
                tracing::error!("proxy: writing PROXY header failed: {e}");
                return response_502();
            }
            return match send_http1_request(TokioIo::new(stream), backend_req)
                .await
            {
                Ok(r) => convert_response(r),
                Err(e) => {
                    tracing::error!("proxy: backend request failed: {e}");
                    response_502()
                }
            };
        }

        let authority = self
            .upstream
            .authority()
            .expect("upstream authority validated in new()")
            .as_str();
        let mut stream = match tokio::net::TcpStream::connect(authority).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("proxy: upstream connect failed: {e}");
                return response_502();
            }
        };

        if let Err(e) = stream.write_all(&header).await {
            tracing::error!("proxy: writing PROXY header failed: {e}");
            return response_502();
        }

        let resp = if self.upstream.scheme_str() == Some("https") {
            let host = self.upstream.host().unwrap_or("");
            let server_name = match rustls::pki_types::ServerName::try_from(
                host.to_owned(),
            ) {
                Ok(n) => n,
                Err(e) => {
                    tracing::error!(
                        "proxy: invalid upstream hostname '{host}': {e}"
                    );
                    return response_502();
                }
            };
            let tls_cfg = Arc::new(
                rustls::ClientConfig::builder()
                    .with_webpki_roots()
                    .with_no_client_auth(),
            );
            let tls_stream = match tokio_rustls::TlsConnector::from(tls_cfg)
                .connect(server_name, stream)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("proxy: TLS handshake failed: {e}");
                    return response_502();
                }
            };
            send_http1_request(TokioIo::new(tls_stream), backend_req).await
        } else {
            send_http1_request(TokioIo::new(stream), backend_req).await
        };

        match resp {
            Ok(r) => convert_response(r),
            Err(e) => {
                tracing::error!("proxy: backend request failed: {e}");
                response_502()
            }
        }
    }
}

// Send one HTTP/1.1 request over an already-connected stream.
// Used by the PROXY-protocol path which bypasses connection pooling.
async fn send_http1_request<I>(
    io: I,
    req: Request<UpstreamBody>,
) -> anyhow::Result<Response<Incoming>>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);
    Ok(sender.send_request(req).await?)
}

// -- URI rewriting -------------------------------------------------

pub fn build_backend_uri(
    upstream: &Uri,
    req_uri: &Uri,
    matched_prefix: &str,
    strip_prefix: bool,
) -> anyhow::Result<Uri> {
    let req_path = req_uri.path();
    let forwarded_path = if strip_prefix {
        req_path.strip_prefix(matched_prefix).unwrap_or(req_path)
    } else {
        req_path
    };

    // Combine upstream path prefix with the forwarded request path.
    let upstream_path = upstream.path().trim_end_matches('/');
    let combined = if forwarded_path.starts_with('/') {
        format!("{upstream_path}{forwarded_path}")
    } else {
        format!("{upstream_path}/{forwarded_path}")
    };

    let path_and_query = match req_uri.query() {
        Some(q) => format!("{combined}?{q}"),
        None => combined,
    };

    let scheme = upstream
        .scheme()
        .cloned()
        .unwrap_or(hyper::http::uri::Scheme::HTTP);
    let authority = upstream
        .authority()
        .ok_or_else(|| anyhow::anyhow!("upstream has no authority"))?
        .clone();

    Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(path_and_query)
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build backend URI: {e}"))
}

// -- Header handling -----------------------------------------------

pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // Collect extra headers named in Connection before removing it.
    let connection_listed: Vec<HeaderName> = headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .map(|p| p.trim())
                .filter_map(|p| p.parse::<HeaderName>().ok())
                .collect()
        })
        .unwrap_or_default();

    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
    for name in connection_listed {
        headers.remove(name);
    }
}

fn set_forwarding_headers(headers: &mut HeaderMap, peer_ip: Option<&str>) {
    if let Some(ip) = peer_ip {
        // Append to existing X-Forwarded-For chain, or start a new one.
        let new_xff = match headers.get("x-forwarded-for") {
            Some(existing) => match existing.to_str() {
                Ok(s) => format!("{s}, {ip}"),
                Err(_) => ip.to_owned(),
            },
            None => ip.to_owned(),
        };
        if let Ok(v) = HeaderValue::from_str(&new_xff) {
            headers.insert("x-forwarded-for", v);
        }
        if let Ok(v) = HeaderValue::from_str(ip) {
            headers.insert("x-real-ip", v);
        }
    }
}

// -- Response conversion -------------------------------------------

fn convert_response(resp: Response<Incoming>) -> HttpResponse {
    let (mut parts, body) = resp.into_parts();

    // Strip hop-by-hop headers from the backend response too.
    strip_hop_by_hop(&mut parts.headers);

    let boxed = body.map_err(io::Error::other).boxed();

    Response::from_parts(parts, boxed)
}

// -- Tests ---------------------------------------------------------

/// Rustls verifier that accepts any server certificate.  Used by the
/// `proxy { tls { skip-verify } }` opt-in for internal upstreams with
/// self-signed certs, and by the test harness for the same reason
/// against in-process listeners.  Operators explicitly opt in via
/// config; this MUST NOT become the default.
#[derive(Debug)]
struct SkipServerVerification;

mod skip_verify_impl {
    use super::SkipServerVerification;
    use rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    impl ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    // -- ProxyHandler::new scheme validation ----------------------

    #[test]
    fn new_accepts_http_upstream() {
        assert!(ProxyHandler::new("http://backend:8080", false, None, crate::config::ProxyUpstreamScheme::Auto, None, None, false, None).is_ok());
    }

    #[test]
    fn new_accepts_https_upstream() {
        assert!(
            ProxyHandler::new("https://backend:8443", false, None, crate::config::ProxyUpstreamScheme::Auto, None, None, false, None).is_ok(),
            "https upstream should be accepted"
        );
    }

    #[cfg(unix)]
    #[test]
    fn new_accepts_unix_upstream() {
        let h = ProxyHandler::new("unix:/run/app.sock", false, None, crate::config::ProxyUpstreamScheme::Auto, None, None, false, None);
        assert!(h.is_ok(), "unix: upstream should be accepted on unix");
        // The internal URI collapses to localhost so that Host header
        // is a sensible value for the backend.
        let h = h.unwrap();
        assert_eq!(h.upstream.host(), Some("localhost"));
    }

    #[cfg(unix)]
    #[test]
    fn new_unix_upstream_uses_http_localhost_uri() {
        let h = ProxyHandler::new("unix:/run/app.sock", false, None, crate::config::ProxyUpstreamScheme::Auto, None, None, false, None).unwrap();
        assert_eq!(h.upstream.scheme_str(), Some("http"));
    }

    #[test]
    fn new_rejects_invalid_scheme() {
        assert!(ProxyHandler::new("ftp://backend", false, None, crate::config::ProxyUpstreamScheme::Auto, None, None, false, None).is_err());
    }

    #[test]
    fn new_rejects_missing_host() {
        assert!(ProxyHandler::new("http:///path", false, None, crate::config::ProxyUpstreamScheme::Auto, None, None, false, None).is_err());
    }

    // -- build_backend_uri -----------------------------------------

    #[test]
    fn build_backend_uri_https_scheme_preserved() {
        let u = build_backend_uri(
            &uri("https://secure-backend"),
            &uri("/api/data"),
            "/api/",
            false,
        )
        .unwrap();
        assert_eq!(u.scheme_str(), Some("https"));
        assert_eq!(u.to_string(), "https://secure-backend/api/data");
    }

    #[test]
    fn build_backend_uri_no_strip() {
        let u = build_backend_uri(
            &uri("http://backend"),
            &uri("/api/users?page=2"),
            "/api/",
            false,
        )
        .unwrap();
        assert_eq!(u.to_string(), "http://backend/api/users?page=2");
    }

    #[test]
    fn build_backend_uri_strip_prefix() {
        let u = build_backend_uri(
            &uri("http://backend"),
            &uri("/api/users?page=2"),
            "/api/",
            true,
        )
        .unwrap();
        assert_eq!(u.to_string(), "http://backend/users?page=2");
    }

    #[test]
    fn build_backend_uri_upstream_path_prefix() {
        let u = build_backend_uri(
            &uri("http://backend/v2"),
            &uri("/api/users"),
            "/api/",
            false,
        )
        .unwrap();
        assert_eq!(u.to_string(), "http://backend/v2/api/users");
    }

    #[test]
    fn build_backend_uri_strip_with_upstream_path() {
        let u = build_backend_uri(
            &uri("http://backend/v2"),
            &uri("/api/users"),
            "/api/",
            true,
        )
        .unwrap();
        assert_eq!(u.to_string(), "http://backend/v2/users");
    }

    #[test]
    fn build_backend_uri_no_query() {
        let u =
            build_backend_uri(&uri("http://backend"), &uri("/foo"), "/", false)
                .unwrap();
        assert_eq!(u.to_string(), "http://backend/foo");
        assert!(u.query().is_none());
    }

    // -- strip_hop_by_hop -----------------------------------------

    #[test]
    fn strip_hop_by_hop_removes_standard_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("keep-alive"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers
            .insert("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.insert("content-type", HeaderValue::from_static("text/html"));
        strip_hop_by_hop(&mut headers);
        assert!(headers.get("connection").is_none());
        assert!(headers.get("keep-alive").is_none());
        assert!(headers.get("transfer-encoding").is_none());
        // Non-hop-by-hop headers must survive.
        assert!(headers.get("content-type").is_some());
    }

    #[test]
    fn strip_hop_by_hop_removes_connection_listed_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "connection",
            HeaderValue::from_static("x-custom, x-other"),
        );
        headers.insert("x-custom", HeaderValue::from_static("value"));
        headers.insert("x-other", HeaderValue::from_static("value"));
        headers.insert("x-keep", HeaderValue::from_static("value"));
        strip_hop_by_hop(&mut headers);
        assert!(headers.get("connection").is_none());
        assert!(headers.get("x-custom").is_none());
        assert!(headers.get("x-other").is_none());
        assert!(headers.get("x-keep").is_some());
    }

    // -- X-Forwarded-For ------------------------------------------

    #[test]
    fn x_forwarded_for_set_when_absent() {
        let mut headers = HeaderMap::new();
        set_forwarding_headers(&mut headers, Some("1.2.3.4"));
        assert_eq!(headers.get("x-forwarded-for").unwrap(), "1.2.3.4");
        assert_eq!(headers.get("x-real-ip").unwrap(), "1.2.3.4");
    }

    #[test]
    fn x_forwarded_for_appends_to_existing() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.1"));
        set_forwarding_headers(&mut headers, Some("1.2.3.4"));
        assert_eq!(
            headers.get("x-forwarded-for").unwrap(),
            "10.0.0.1, 1.2.3.4"
        );
    }

    #[test]
    fn no_forwarding_headers_without_peer_ip() {
        let mut headers = HeaderMap::new();
        set_forwarding_headers(&mut headers, None);
        assert!(headers.get("x-forwarded-for").is_none());
        assert!(headers.get("x-real-ip").is_none());
    }

    // -- PROXY protocol tests -----------------------------------------

    #[cfg(unix)]
    #[test]
    fn proxy_protocol_accepted_for_unix_upstream() {
        use crate::config::ProxyProtocolVersion;
        // unix: + proxy-protocol is now supported; new() must succeed.
        let h = ProxyHandler::new(
            "unix:/run/app.sock",
            false,
            Some(ProxyProtocolVersion::V2), crate::config::ProxyUpstreamScheme::Auto, None, None, false, None);
        assert!(h.is_ok(), "unix + proxy-protocol should be accepted");
    }

    // Verify that the PROXY v1 header is the first bytes sent to the
    // upstream.  Uses a mock TCP server that reads up to 64 bytes and
    // echoes them back via a channel.  serve() will return 502 because
    // the mock doesn't speak HTTP, but the header arrives first.
    #[tokio::test]
    async fn proxy_protocol_v1_header_sent_to_upstream() {
        use crate::config::ProxyProtocolVersion;
        use crate::listener::LocalAddr;
        use hyper::body::Incoming;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Mock upstream: accept one connection, return its first bytes.
        let mock = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = mock.local_addr().unwrap();
        let upstream_handle = tokio::spawn(async move {
            let (mut conn, _) = mock.accept().await.unwrap();
            let mut buf = vec![0u8; 128];
            let n = conn.read(&mut buf).await.unwrap_or(0);
            // Send a minimal HTTP response so hyper doesn't error
            // (the PROXY header was already read before this).
            let _ = conn
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                .await;
            String::from_utf8_lossy(&buf[..n]).to_string()
        });

        let handler = ProxyHandler::new(
            &format!("http://{upstream_addr}"),
            false,
            Some(ProxyProtocolVersion::V1),
            crate::config::ProxyUpstreamScheme::Auto,
            None,
        None,
        false,
        None,
        )
        .unwrap();

        // Build a minimal hyper server + client pair to produce a
        // real Request<ReqBody>.
        let (client_io, server_io) = tokio::io::duplex(4096);
        let client_io = hyper_util::rt::TokioIo::new(client_io);
        let server_io = hyper_util::rt::TokioIo::new(server_io);

        let peer: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let handler = std::sync::Arc::new(handler);
        let handler_clone = handler.clone();

        // Server side: receive one request and call handler.serve().
        tokio::spawn(async move {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    server_io,
                    hyper::service::service_fn(
                        move |mut req: hyper::Request<Incoming>| {
                            req.extensions_mut().insert(peer);
                            req.extensions_mut().insert(LocalAddr(local));
                            let h = handler_clone.clone();
                            async move {
                                use http_body_util::BodyExt;
                                let req = req.map(|b| b.boxed_unsync());
                                Ok::<_, std::convert::Infallible>(
                                    h.serve(req, "/").await,
                                )
                            }
                        },
                    ),
                )
                .await
                .ok();
        });

        // Client side: send one request.
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(client_io)
                .await
                .unwrap();
        tokio::spawn(conn);
        let req = hyper::Request::builder()
            .uri("/")
            .header("host", "example.com")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let _ = sender.send_request(req).await;

        let received = upstream_handle.await.unwrap();
        assert!(
            received.starts_with("PROXY TCP4 1.2.3.4 127.0.0.1 5678 80\r\n"),
            "expected PROXY header, got: {received:?}",
        );
    }

    // Same test as above but with a Unix socket upstream.
    #[cfg(unix)]
    #[tokio::test]
    async fn proxy_protocol_v1_header_sent_to_unix_upstream() {
        use crate::config::ProxyProtocolVersion;
        use crate::listener::LocalAddr;
        use hyper::body::Incoming;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let mock = tokio::net::UnixListener::bind(&sock_path).unwrap();
        let upstream_handle = tokio::spawn(async move {
            let (mut conn, _) = mock.accept().await.unwrap();
            let mut buf = vec![0u8; 128];
            let n = conn.read(&mut buf).await.unwrap_or(0);
            let _ = conn
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                .await;
            String::from_utf8_lossy(&buf[..n]).to_string()
        });

        let handler = ProxyHandler::new(
            &format!("unix:{}", sock_path.display()),
            false,
            Some(ProxyProtocolVersion::V1),
            crate::config::ProxyUpstreamScheme::Auto,
            None,
        None,
        false,
        None,
        )
        .unwrap();

        let (client_io, server_io) = tokio::io::duplex(4096);
        let client_io = hyper_util::rt::TokioIo::new(client_io);
        let server_io = hyper_util::rt::TokioIo::new(server_io);

        let peer: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let handler = std::sync::Arc::new(handler);
        let handler_clone = handler.clone();

        tokio::spawn(async move {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    server_io,
                    hyper::service::service_fn(
                        move |mut req: hyper::Request<Incoming>| {
                            req.extensions_mut().insert(peer);
                            req.extensions_mut().insert(LocalAddr(local));
                            let h = handler_clone.clone();
                            async move {
                                use http_body_util::BodyExt;
                                let req = req.map(|b| b.boxed_unsync());
                                Ok::<_, std::convert::Infallible>(
                                    h.serve(req, "/").await,
                                )
                            }
                        },
                    ),
                )
                .await
                .ok();
        });

        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(client_io)
                .await
                .unwrap();
        tokio::spawn(conn);
        let req = hyper::Request::builder()
            .uri("/")
            .header("host", "example.com")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let _ = sender.send_request(req).await;

        let received = upstream_handle.await.unwrap();
        assert!(
            received.starts_with("PROXY TCP4 1.2.3.4 127.0.0.1 5678 80\r\n"),
            "expected PROXY header over unix socket, got: {received:?}",
        );
    }

    /// Alt-Svc parser: accepts the common `h3=":port"; ma=N` shape
    /// and ignores other alt-protocols / malformed entries.
    #[test]
    fn parse_alt_svc_h3_basic() {
        use super::parse_alt_svc_h3;
        assert_eq!(parse_alt_svc_h3("h3=\":443\"; ma=86400"), Some((443, 86400)));
        assert_eq!(parse_alt_svc_h3("h3=\":8443\"; ma=3600; persist=1"), Some((8443, 3600)));
        // First h3 entry wins when multiple are advertised.
        assert_eq!(
            parse_alt_svc_h3("h3-29=\":443\"; ma=3600, h3=\":443\"; ma=7200"),
            Some((443, 7200))
        );
        // ma=0 means "clear cache"; we treat as no upgrade hint.
        assert_eq!(parse_alt_svc_h3("h3=\":443\"; ma=0"), None);
        // No h3 entry at all.
        assert_eq!(parse_alt_svc_h3("h2=\":443\"; ma=3600"), None);
        // Missing ma.
        assert_eq!(parse_alt_svc_h3("h3=\":443\""), None);
        // Empty header.
        assert_eq!(parse_alt_svc_h3(""), None);
    }

    /// `prepare_backend_request` previously pinned the request version
    /// to HTTP/1.1, which prevented hyper-util's Client from negotiating
    /// HTTP/2 over the new `enable_http2()` ALPN.  After Phase 5 the
    /// version is left at its default so the ALPN-negotiated protocol
    /// wins.
    #[test]
    fn prepare_backend_request_does_not_pin_http11() {
        let h = ProxyHandler::new(
            "https://backend.example/",
            false,
            None,
            crate::config::ProxyUpstreamScheme::Auto,
            None,
        None,
        false,
        None,
        )
        .unwrap();
        let req = hyper::Request::builder()
            .method("GET")
            .uri("/")
            .body(
                http_body_util::Empty::<bytes::Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        let backend = h.prepare_backend_request(req, "/").unwrap();
        // The default version on a Request built with no explicit
        // .version() call is HTTP/1.1, but the proxy used to force
        // it explicitly even when the inbound request was h2.  By
        // resetting to `Version::default()` we let hyper-util decide
        // based on the upstream's ALPN.
        assert_eq!(backend.version(), hyper::Version::default());
    }
}
