use crate::acme::ChallengeMap;
use crate::auth::{AuthDecision, Authenticator};
use crate::compress;
use crate::config::{ListenerConfig, TcpProxyConfig, Timeouts};
use crate::proxy_proto;
use crate::error::{
    bytes_body, response_401, response_403, response_404, BoxBody,
};
use crate::router::Router;
use arc_swap::ArcSwap;
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::debug;

// Maximum time to wait for in-flight requests to finish after the
// shutdown signal is sent before giving up and exiting anyway.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

pub struct AppState {
    pub router: Arc<Router>,
    // ACME HTTP-01 challenge tokens served at
    // /.well-known/acme-challenge/{token}.  Populated by AcmeManager
    // during certificate issuance; empty otherwise.
    pub acme_challenges: ChallengeMap,
    pub authenticator: Arc<dyn Authenticator>,
}

// One AlohaService is cloned per accepted connection.
// It holds only Arc references so cloning is cheap.
#[derive(Clone)]
struct AlohaService {
    state: Arc<AppState>,
    // Canonical listener identifier (bind address or "fd:N");
    // used by the router to resolve the default vhost.
    bind: String,
    peer_addr: SocketAddr,
    timeouts: Timeouts,
}

impl hyper::service::Service<Request<Incoming>> for AlohaService {
    type Response = Response<BoxBody>;
    type Error = anyhow::Error;
    // Boxed future avoids naming the concrete async block type.
    type Future = Pin<
        Box<dyn Future<Output = Result<Self::Response, Self::Error>>
                + Send>,
    >;

    fn call(&self, mut req: Request<Incoming>) -> Self::Future {
        let state = self.state.clone();
        let bind = self.bind.clone();
        let peer = self.peer_addr;
        let handler_timeout = self
            .timeouts
            .handler_secs
            .map(Duration::from_secs);
        Box::pin(async move {
            let start = Instant::now();
            let method = req.method().clone();
            let path = req.uri().path().to_owned();
            // Attach the peer address as a typed extension so handlers
            // (e.g. the reverse proxy) can add X-Forwarded-For without
            // needing a separate parameter through the call stack.
            req.extensions_mut().insert(peer);

            // Read Accept-Encoding before the request is consumed by
            // the handler.  The encoding is applied to the response
            // after the handler returns, outside the handler timeout.
            let accept_encoding = req
                .headers()
                .get(hyper::header::ACCEPT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .map(ToOwned::to_owned);

            // ACME HTTP-01 challenge interception.
            // Let's Encrypt validates by fetching this path on port 80.
            if let Some(token) =
                path.strip_prefix("/.well-known/acme-challenge/")
            {
                let key_auth = state
                    .acme_challenges
                    .lock()
                    .unwrap()
                    .get(token)
                    .cloned();
                if let Some(body) = key_auth {
                    let resp = Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "text/plain")
                        .body(bytes_body(Bytes::from(body)))
                        .expect("known-valid status and header");
                    log_access(&method, &path, &resp, peer, start);
                    return Ok(resp);
                }
            }

            let serve_fut = async {
                match state.router.route(&req, &bind) {
                    Some(route) => {
                        if let Some(policy) = &route.auth_policy {
                            let principal = state
                                .authenticator
                                .authenticate(&req)
                                .await;
                            match policy.evaluate(&principal) {
                                AuthDecision::Allow => {}
                                AuthDecision::Unauthenticated => {
                                    return response_401();
                                }
                                AuthDecision::Deny => {
                                    return response_403();
                                }
                            }
                        }
                        // Routing and auth use a shared ref; the handler
                        // takes ownership so it can consume the body.
                        route
                            .handler
                            .serve(req, &route.matched_prefix)
                            .await
                    }
                    None => response_404(),
                }
            };

            // Apply per-request handler timeout when configured.
            let resp = if let Some(dur) = handler_timeout {
                match tokio::time::timeout(dur, serve_fut).await {
                    Ok(r) => r,
                    Err(_) => {
                        tracing::warn!(
                            %peer, path, "handler timed out"
                        );
                        Response::builder()
                            .status(StatusCode::REQUEST_TIMEOUT)
                            .body(bytes_body(Bytes::from_static(
                                b"<h1>408 Request Timeout</h1>",
                            )))
                            .expect("known-valid status")
                    }
                }
            } else {
                serve_fut.await
            };

            let encoding = accept_encoding
                .as_deref()
                .and_then(compress::negotiate);
            let resp =
                compress::maybe_compress(resp, encoding).await;

            log_access(&method, &path, &resp, peer, start);
            Ok(resp)
        })
    }
}

// Emit one access-log line per completed request at INFO level.
// Fields are structured so log aggregators can parse them; the
// human-readable format is also easy to read with plain `grep`.
fn log_access<B>(
    method: &hyper::Method,
    path: &str,
    resp: &Response<B>,
    peer: SocketAddr,
    start: Instant,
) {
    let status = resp.status().as_u16();
    let ms = start.elapsed().as_millis();
    tracing::info!(
        %peer,
        %method,
        path,
        status,
        ms,
        "request"
    );
}

// Build a hyper auto::Builder with the configured timeout settings.
fn make_builder(timeouts: &Timeouts) -> auto::Builder<TokioExecutor> {
    let mut builder = auto::Builder::new(TokioExecutor::new());
    {
        let mut h1 = builder.http1();
        h1.timer(TokioTimer::new());
        if let Some(secs) = timeouts.request_header_secs {
            h1.header_read_timeout(Duration::from_secs(secs));
        }
        // keepalive_secs=0 disables HTTP/1.1 keep-alive entirely.
        // Non-zero values are parsed for future idle-timeout support.
        if timeouts.keepalive_secs == Some(0) {
            h1.keep_alive(false);
        }
    }
    builder
}

// Bind a TCP socket for the listener — exported so main() can bind
// all sockets before dropping root privileges.
//
// For bind addresses this does a synchronous kernel bind; for fd-based
// listeners it takes ownership of the already-bound fd passed by
// systemd (socket activation).
pub fn bind_tcp(cfg: &ListenerConfig) -> anyhow::Result<TcpListener> {
    let std_listener = if let Some(ref addr) = cfg.bind {
        std::net::TcpListener::bind(addr.as_str())?
    } else if let Some(fd) = cfg.fd {
        // SAFETY: systemd guarantees the fd is a valid, bound, owned
        // TCP socket.  We take exclusive ownership here; the raw fd
        // must not be used again after this call.
        #[cfg(unix)]
        {
            use std::os::unix::io::FromRawFd;
            unsafe { std::net::TcpListener::from_raw_fd(fd) }
        }
        #[cfg(not(unix))]
        {
            anyhow::bail!(
                "fd-based listeners are only supported on Unix \
                 (fd={fd})"
            );
        }
    } else {
        anyhow::bail!("listener has neither bind nor fd");
    };
    std_listener.set_nonblocking(true)?;
    Ok(TcpListener::from_std(std_listener)?)
}

pub async fn run_plain(
    cfg: ListenerConfig,
    listener: TcpListener,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let name = cfg.local_name();
    tracing::info!(bind = %name, "listening (HTTP)");
    let mut connections: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, peer_addr)) => {
                        let io = TokioIo::new(stream);
                        let svc = AlohaService {
                            state: state.clone(),
                            bind: name.clone(),
                            peer_addr,
                            timeouts: cfg.timeouts.clone(),
                        };
                        let conn_shutdown = shutdown.clone();
                        connections.spawn(serve_connection(
                            io, svc, conn_shutdown, peer_addr,
                        ));
                    }
                    Err(e) => {
                        tracing::error!(bind = %name, "accept error: {e}");
                    }
                }
            }
            // Reap completed connections to prevent unbounded growth.
            Some(_) = connections.join_next(),
                if !connections.is_empty() => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }

    drain_connections(&name, connections).await;
    Ok(())
}

// Acceptor is pre-built by main (possibly via AcmeManager) and passed
// in as an ArcSwap so that live cert rotation works without restart.
pub async fn run_tls(
    cfg: ListenerConfig,
    listener: TcpListener,
    state: Arc<AppState>,
    acceptor: Arc<ArcSwap<TlsAcceptor>>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let name = cfg.local_name();
    tracing::info!(bind = %name, "listening (HTTPS)");
    let mut connections: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, peer_addr)) => {
                        // load_full() cheaply clones the inner Arc,
                        // picking up any cert hot-swapped since last accept.
                        let acc = acceptor.load_full();
                        let state = state.clone();
                        let bind = name.clone();
                        let svc_timeouts = cfg.timeouts.clone();
                        let conn_shutdown = shutdown.clone();
                        connections.spawn(async move {
                            // TLS handshake inside the task so a slow
                            // client doesn't block the accept loop.
                            let tls_stream = match acc.accept(stream).await {
                                Ok(s) => s,
                                Err(e) => {
                                    debug!(%peer_addr, "TLS handshake failed: {e}");
                                    return;
                                }
                            };
                            debug!(%peer_addr, "TLS accepted");
                            let io = TokioIo::new(tls_stream);
                            let svc = AlohaService {
                                state,
                                bind,
                                peer_addr,
                                timeouts: svc_timeouts,
                            };
                            serve_connection(io, svc, conn_shutdown, peer_addr)
                                .await;
                        });
                    }
                    Err(e) => {
                        tracing::error!(bind = %name, "accept error: {e}");
                    }
                }
            }
            Some(_) = connections.join_next(),
                if !connections.is_empty() => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }

    drain_connections(&name, connections).await;
    Ok(())
}

// Serve a single connection, initiating graceful shutdown on signal.
//
// On shutdown, hyper's graceful_shutdown() stops the connection from
// accepting new requests while allowing the current request to finish.
async fn serve_connection<I>(
    io: I,
    svc: AlohaService,
    mut shutdown: watch::Receiver<bool>,
    peer_addr: SocketAddr,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    // If shutdown was already signalled before this task started, skip
    // the connection rather than starting and immediately aborting.
    if *shutdown.borrow() {
        return;
    }
    debug!(%peer_addr, "accepted connection");
    let builder = make_builder(&svc.timeouts);
    let conn = builder.serve_connection(io, svc);
    tokio::pin!(conn);

    let mut graceful = false;
    loop {
        tokio::select! {
            result = conn.as_mut() => {
                if let Err(e) = result {
                    debug!(%peer_addr, "connection closed: {e}");
                }
                break;
            }
            // Only arm this branch until we've initiated shutdown once.
            _ = shutdown.changed(), if !graceful => {
                if *shutdown.borrow() {
                    conn.as_mut().graceful_shutdown();
                    graceful = true;
                }
            }
        }
    }
}

// ── TCP proxy listener ────────────────────────────────────────────

// `acceptor` is Some when the listener should terminate TLS before
// forwarding the decrypted stream to the upstream.
pub async fn run_tcp_proxy(
    cfg: ListenerConfig,
    proxy: TcpProxyConfig,
    listener: TcpListener,
    acceptor: Option<Arc<ArcSwap<TlsAcceptor>>>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let name = cfg.local_name();
    let local_addr = listener.local_addr().ok();
    let label = if acceptor.is_some() {
        "TCP proxy (TLS)"
    } else {
        "TCP proxy"
    };
    tracing::info!(
        bind = %name,
        upstream = %proxy.upstream,
        "listening ({label})"
    );
    let mut connections: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, peer_addr)) => {
                        let upstream = proxy.upstream.clone();
                        let proto = proxy.proxy_protocol;
                        let conn_shutdown = shutdown.clone();
                        // load_full() cheaply bumps the Arc refcount,
                        // picking up any hot-swapped cert since last accept.
                        let acc = acceptor
                            .as_ref()
                            .map(|a| a.load_full());
                        connections.spawn(async move {
                            let result = if let Some(acc) = acc {
                                match acc.accept(stream).await {
                                    Ok(tls) => tcp_proxy_connection(
                                        tls, peer_addr, local_addr,
                                        &upstream, proto, conn_shutdown,
                                    ).await,
                                    Err(e) => {
                                        debug!(%peer_addr,
                                            "TLS handshake failed: {e}");
                                        Ok(())
                                    }
                                }
                            } else {
                                tcp_proxy_connection(
                                    stream, peer_addr, local_addr,
                                    &upstream, proto, conn_shutdown,
                                ).await
                            };
                            if let Err(e) = result {
                                debug!(%peer_addr, "tcp proxy: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!(bind = %name, "accept error: {e}");
                    }
                }
            }
            Some(_) = connections.join_next(),
                if !connections.is_empty() => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }

    drain_connections(&name, connections).await;
    Ok(())
}

async fn tcp_proxy_connection<C>(
    mut client: C,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    upstream: &str,
    proxy_protocol: Option<crate::config::ProxyProtocolVersion>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    if *shutdown.borrow() {
        return Ok(());
    }

    let mut backend = tokio::net::TcpStream::connect(upstream).await?;

    if let Some(version) = proxy_protocol {
        // Use the listener's local address as the "destination" in the
        // PROXY header.  Fall back to 0.0.0.0:0 / [::]:0 if unavailable.
        let dst = local_addr.unwrap_or_else(|| {
            use std::net::{Ipv4Addr, IpAddr};
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        });
        let header = proxy_proto::build_header(version, peer_addr, dst);
        use tokio::io::AsyncWriteExt;
        backend.write_all(&header).await?;
    }

    tokio::select! {
        result = tokio::io::copy_bidirectional(&mut client, &mut backend) => {
            result?;
        }
        _ = shutdown.changed() => {
            // Shutdown signalled; let OS close the sockets.
        }
    }

    Ok(())
}

// Wait for all in-flight connections to finish, with a hard timeout.
async fn drain_connections(name: &str, mut connections: JoinSet<()>) {
    let n = connections.len();
    if n > 0 {
        tracing::info!(bind = %name, connections = n, "draining");
    }
    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(DRAIN_TIMEOUT, drain).await.is_err() {
        tracing::warn!(
            bind = %name,
            "drain timeout after {}s; {} connection(s) abandoned",
            DRAIN_TIMEOUT.as_secs(),
            connections.len(),
        );
    }
}
