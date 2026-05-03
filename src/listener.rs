// Per-connection hyper service, TCP/TLS listener loops, and access logging.
//
// AppState is shared across all connections on all listeners.  Each
// accepted connection gets a cheap clone of AlohaService (Arc refs only)
// and is driven to completion before the graceful-shutdown drain finishes.

use crate::access::{
    AccessBlock, AccessOutcome, AnonymousAuthProvider, AuthProvider,
    EvalContext,
};
use crate::acme::ChallengeMap;
use crate::auth::{Authenticator, Principal};
use crate::geoip;
use crate::headers::principal_strings;
use crate::compress;
use crate::config::{ListenerConfig, TcpProxyConfig, Timeouts};
use crate::headers::{self, RequestContext};
use crate::metrics::Metrics;
use crate::proxy_proto;
use crate::error::{
    bytes_body, response_404, response_redirect, response_status,
    response_www_auth, BoxBody, ErrorPages,
};
use crate::router::Router;
use arc_swap::ArcSwap;
use async_trait::async_trait;
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
    pub metrics: Arc<Metrics>,
    // Optional GeoIP reader; present when server.geoip is configured.
    pub geoip: Option<Arc<geoip::CountryReader>>,
    // When true, /healthz /livez /readyz are intercepted before routing.
    pub health_enabled: bool,
    // Per-status custom error pages; empty if none configured.
    pub error_pages: Arc<ErrorPages>,
}

// Wraps the per-request authenticator so it implements AuthProvider
// for the access evaluator (which doesn't know about hyper::Request).
struct RequestAuthProvider<'a> {
    authenticator: &'a dyn Authenticator,
    request: &'a Request<Incoming>,
}

#[async_trait]
impl AuthProvider for RequestAuthProvider<'_> {
    async fn authenticate(&self) -> Principal {
        self.authenticator.authenticate(self.request).await
    }
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
    // True for TLS listeners; used to populate the {scheme} template
    // variable in header rules.
    is_tls: bool,
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
        let is_tls = self.is_tls;
        let handler_timeout = self
            .timeouts
            .handler_secs
            .map(Duration::from_secs);
        Box::pin(async move {
            let start = Instant::now();
            let method = req.method().clone();
            let path = req.uri().path().to_owned();
            let query = req.uri().query()
                .unwrap_or("")
                .to_owned();
            let path_and_query = req.uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/")
                .to_owned();
            let host = req
                .headers()
                .get(hyper::header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
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

            state.metrics.inc_active();

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
                    let ms = start.elapsed().as_millis();
                    state.metrics.dec_active();
                    state.metrics.record(
                        resp.status().as_u16(), ms,
                    );
                    state.metrics.record_path(&path);
                    log_access(&method, &path, resp.status().as_u16(),
                               ms, peer);
                    return Ok(resp);
                }
            }

            // Health endpoint interception: /healthz, /livez, /readyz.
            // Answered before vhost routing so they work without a Host
            // header and cannot be shadowed by user-defined locations.
            if state.health_enabled {
                if let Some(resp) =
                    crate::handler::health::try_serve(&req)
                {
                    let ms = start.elapsed().as_millis();
                    state.metrics.dec_active();
                    state.metrics.record(
                        resp.status().as_u16(), ms,
                    );
                    state.metrics.record_path(&path);
                    log_access(
                        &method, &path,
                        resp.status().as_u16(), ms, peer,
                    );
                    return Ok(resp);
                }
            }

            let serve_fut = async {
                match state.router.route(&req, &bind) {
                    Some(route) => {
                        // Look up country only when the policy needs it.
                        let country: Option<String> = match (
                            &state.geoip,
                            &route.access_policy,
                        ) {
                            (Some(reader), Some(policy))
                                if policy.needs_geoip =>
                            {
                                geoip::lookup_country(reader, peer.ip())
                            }
                            _ => None,
                        };

                        // Evaluate access policy with lazy authentication.
                        // The principal is only fetched from the
                        // authenticator when an identity condition is
                        // actually evaluated.
                        let principal = if let Some(policy) = &route.access_policy {
                            let auth_provider = RequestAuthProvider {
                                authenticator: &*state.authenticator,
                                request: &req,
                            };
                            let mut ctx = EvalContext::new(
                                peer.ip(),
                                country.as_deref(),
                                &auth_provider,
                            );
                            let outcome = policy.evaluate(&mut ctx).await;
                            let principal = ctx.take_principal();
                            match outcome {
                                AccessOutcome::Allow => {}
                                AccessOutcome::Deny(401) => {
                                    tracing::warn!(
                                        %peer, %method,
                                        path, host,
                                        "auth failed"
                                    );
                                    let realm = route
                                        .basic_auth
                                        .as_ref()
                                        .map(|a| a.realm.as_str())
                                        .unwrap_or("Restricted");
                                    return response_www_auth(
                                        realm,
                                        Some(&state.error_pages),
                                    )
                                    .await;
                                }
                                AccessOutcome::Deny(code) => {
                                    tracing::warn!(
                                        %peer, %method,
                                        path, host,
                                        status = code,
                                        "access denied"
                                    );
                                    return response_status(
                                        code,
                                        Some(&state.error_pages),
                                    )
                                    .await;
                                }
                                AccessOutcome::Redirect(to, code) => {
                                    return response_redirect(&to, code);
                                }
                            }
                            principal
                        } else {
                            Principal::Anonymous
                        };

                        // If header rules need the principal and auth
                        // was not triggered by the access policy
                        // (principal is still Anonymous), authenticate now.
                        let principal = if route
                            .header_rules
                            .as_ref()
                            .map(|r| r.needs_principal)
                            .unwrap_or(false)
                            && matches!(principal, Principal::Anonymous)
                        {
                            state.authenticator.authenticate(&req).await
                        } else {
                            principal
                        };

                        // Build request context once; used by the
                        // redirect handler for template rendering and
                        // by both header-rule passes below.
                        let peer_ip = peer.ip().to_string();
                        let (username, groups_str) =
                            principal_strings(&principal);
                        let req_ctx = RequestContext {
                            client_ip:      &peer_ip,
                            username,
                            groups:         &groups_str,
                            method:         method.as_str(),
                            path:           &path,
                            query:          &query,
                            path_and_query: &path_and_query,
                            host:           &host,
                            scheme: if is_tls { "https" } else { "http" },
                        };

                        // Apply request-header rules before the handler
                        // consumes the request.
                        if let Some(rules) = &route.header_rules {
                            if !rules.request.is_empty() {
                                headers::apply_request_headers(
                                    req.headers_mut(),
                                    &rules.request,
                                    &req_ctx,
                                );
                            }
                        }

                        let mut resp = route
                            .handler
                            .serve(req, &route.matched_prefix, &req_ctx)
                            .await;

                        // Apply response-header rules to the response
                        // before it reaches the client.
                        if let Some(rules) = &route.header_rules {
                            if !rules.response.is_empty() {
                                headers::apply_response_headers(
                                    resp.headers_mut(),
                                    &rules.response,
                                    &req_ctx,
                                );
                            }
                        }

                        resp
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

            let status = resp.status().as_u16();
            let ms = start.elapsed().as_millis();
            state.metrics.dec_active();
            state.metrics.record(status, ms);
            state.metrics.record_path(&path);
            log_access(&method, &path, status, ms, peer);
            Ok(resp)
        })
    }
}

// Emit one access-log line per completed request at INFO level.
// Fields are structured so log aggregators can parse them; the
// human-readable format is also easy to read with plain `grep`.
fn log_access(
    method: &hyper::Method,
    path: &str,
    status: u16,
    ms: u128,
    peer: SocketAddr,
) {
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

// Bind a TCP socket for the listener -- exported so main() can bind
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
                            is_tls: false,
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
                                is_tls: true,
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

// -- TCP proxy listener --------------------------------------------

// `acceptor` is Some when the listener should terminate TLS before
// forwarding the decrypted stream to the upstream.
pub async fn run_tcp_proxy(
    cfg: ListenerConfig,
    proxy: TcpProxyConfig,
    listener: TcpListener,
    acceptor: Option<Arc<ArcSwap<TlsAcceptor>>>,
    mut shutdown: watch::Receiver<bool>,
    access: Option<Arc<AccessBlock>>,
    geoip: Option<Arc<geoip::CountryReader>>,
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
                        let conn_access = access.clone();
                        let conn_geoip = geoip.clone();
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
                                        conn_access, conn_geoip,
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
                                    conn_access, conn_geoip,
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
    access: Option<Arc<AccessBlock>>,
    geoip: Option<Arc<geoip::CountryReader>>,
) -> anyhow::Result<()>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    if *shutdown.borrow() {
        return Ok(());
    }

    if let Some(policy) = &access {
        let country = if policy.needs_geoip {
            geoip.as_ref()
                .and_then(|r| geoip::lookup_country(r, peer_addr.ip()))
        } else {
            None
        };
        let anon = AnonymousAuthProvider;
        let mut ctx = EvalContext::new(
            peer_addr.ip(),
            country.as_deref(),
            &anon,
        );
        match policy.evaluate(&mut ctx).await {
            AccessOutcome::Allow => {}
            // Redirect is meaningless over raw TCP; treat as deny.
            _ => {
                debug!(%peer_addr, "tcp proxy: access denied");
                return Ok(());
            }
        }
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

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AnonymousAuthenticator;
    use crate::config::{Config, ListenerConfig, Timeouts};
    use crate::error::ErrorPages;
    use crate::metrics::Metrics;
    use crate::router::Router;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty};
    use hyper::Request;
    use std::collections::HashMap;
    use tokio::net::TcpListener as TokioTcpListener;
    use tokio::sync::watch;

    // Spin up an in-process test HTTP server backed by a given AppState.
    // Returns the bound address and a shutdown sender.
    async fn start_server(
        state: Arc<AppState>,
    ) -> (std::net::SocketAddr, watch::Sender<bool>) {
        let std_listener =
            std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let listener = TokioTcpListener::from_std(std_listener).unwrap();
        let (tx, rx) = watch::channel(false);
        let cfg = ListenerConfig {
            bind: Some(addr.to_string()),
            fd: None,
            tls: None,
            default_vhost: None,
            timeouts: Timeouts::default(),
            tcp_proxy: None,
        };
        tokio::spawn(run_plain(cfg, listener, state, rx));
        (addr, tx)
    }

    // Send a plain-HTTP GET and return (status, headers, body bytes).
    async fn http_get(
        addr: std::net::SocketAddr,
        host: &str,
        path_and_query: &str,
    ) -> (hyper::StatusCode, hyper::HeaderMap, Bytes) {
        let stream =
            tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        let req = Request::builder()
            .uri(path_and_query)
            .header("host", host)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp
            .into_body()
            .collect()
            .await
            .map(|c| c.to_bytes())
            .unwrap_or_default();
        (status, headers, body)
    }

    // Build an AppState with a single vhost that catch-all redirects to HTTPS.
    fn redirect_state() -> Arc<AppState> {
        let config = Config::parse(r#"
            listener {
                bind "127.0.0.1:1"
            }
            vhost "example.com" {
                location "/" {
                    redirect {
                        to "https://{host}{path_and_query}"
                        code 301
                    }
                }
            }
        "#).unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&config),
        );
        let router = Router::new(&config, &metrics, &summary, None)
            .unwrap();
        Arc::new(AppState {
            router: Arc::new(router),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics,
            geoip: None,
            health_enabled: false,
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
        })
    }

    /// A request to /.well-known/acme-challenge/{token} must return the
    /// challenge key-auth even when a catch-all redirect location is
    /// configured for the vhost.  The ACME intercept runs before routing.
    #[tokio::test]
    async fn acme_challenge_not_blocked_by_redirect() {
        let state = redirect_state();
        state.acme_challenges.lock().unwrap().insert(
            "tok123".to_string(),
            "tok123.keyauth".to_string(),
        );
        let (addr, tx) = start_server(state).await;

        let (status, _, body) = http_get(
            addr,
            "example.com",
            "/.well-known/acme-challenge/tok123",
        )
        .await;
        assert_eq!(status, 200, "ACME challenge must be served");
        assert_eq!(body.as_ref(), b"tok123.keyauth");

        tx.send(true).unwrap();
    }

    /// Requests to non-ACME paths on a vhost with a catch-all redirect
    /// must receive a 301 with an https:// Location.
    #[tokio::test]
    async fn redirect_applies_to_normal_paths() {
        let state = redirect_state();
        let (addr, tx) = start_server(state).await;

        let (status, headers, _) =
            http_get(addr, "example.com", "/foo?bar=1").await;
        assert_eq!(status, 301);
        assert_eq!(
            headers.get("location").unwrap(),
            "https://example.com/foo?bar=1",
        );

        tx.send(true).unwrap();
    }

    /// An ACME path with an *unknown* token falls through to the router
    /// (the challenge map miss is not intercepted) and hits the redirect.
    #[tokio::test]
    async fn acme_path_unknown_token_falls_through_to_router() {
        let state = redirect_state();
        // Do NOT insert any token -- miss falls through to routing.
        let (addr, tx) = start_server(state).await;

        let (status, _, _) = http_get(
            addr,
            "example.com",
            "/.well-known/acme-challenge/nosuchtoken",
        )
        .await;
        // Falls through to the catch-all redirect location.
        assert_eq!(status, 301);

        tx.send(true).unwrap();
    }
}
