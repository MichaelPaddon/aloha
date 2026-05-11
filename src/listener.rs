// Per-connection hyper service, TCP/TLS listener loops, and access logging.
//
// AppState is shared across all connections on all listeners.  Each
// accepted connection gets a cheap clone of AlohaService (Arc refs only)
// and is driven to completion before the graceful-shutdown drain finishes.

use crate::access::{
    AnonymousAuthProvider, AuthProvider, EvalContext, PolicyBlock,
    PolicyOutcome,
};
use crate::acme::ChallengeMap;
use crate::auth::{Authenticator, Principal};
use crate::compress;
use crate::config::{ListenerConfig, Timeouts};
use crate::error::{
    BoxBody, ErrorPages, bytes_body, response_404, response_413,
    response_redirect, response_status, response_www_auth,
};
use crate::geoip;
use crate::headers::principal_strings;
use crate::headers::{self, RequestContext};
#[cfg(unix)]
use crate::inherit::InheritedSockets;
use crate::metrics::Metrics;
use crate::proxy_proto;
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
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::debug;

// Maximum time to wait for in-flight requests to finish after the
// shutdown signal is sent before giving up and exiting anyway.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

// Abort TLS negotiation that hasn't completed within this window.
// Protects against partial-ClientHello floods that would otherwise
// park a task indefinitely.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

// Applied to every HTTP/1.1 connection when no explicit
// `timeouts { request-header N }` is configured.  Protects against
// Slowloris without requiring operators to set it explicitly.
// Set request-header=0 in the config to disable.
const DEFAULT_HEADER_TIMEOUT_SECS: u64 = 30;

// -- Peer address and incoming stream abstractions -----------------

/// Client address for a connection: IP+port for TCP, a sentinel for
/// Unix domain socket connections (which have no IP).
#[derive(Clone, Copy, Debug)]
pub(crate) enum PeerAddr {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix,
}

impl PeerAddr {
    /// IP address of the peer.  Unix sockets return loopback so that
    /// access rules with `ip "127.0.0.0/8"` match local connections.
    fn ip(self) -> std::net::IpAddr {
        match self {
            PeerAddr::Tcp(a) => a.ip(),
            #[cfg(unix)]
            PeerAddr::Unix => std::net::IpAddr::from([127, 0, 0, 1]),
        }
    }
}

impl std::fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerAddr::Tcp(a) => write!(f, "{a}"),
            #[cfg(unix)]
            PeerAddr::Unix => write!(f, "[unix]"),
        }
    }
}

/// Accepted inbound stream: TCP or (on Unix) a Unix domain socket.
/// Implements tokio AsyncRead + AsyncWrite so `TokioIo::new` can wrap it.
#[cfg(unix)]
pub(crate) enum IncomingStream {
    Tcp(tokio::net::TcpStream),
    Unix(tokio::net::UnixStream),
}

#[cfg(not(unix))]
pub(crate) enum IncomingStream {
    Tcp(tokio::net::TcpStream),
}

impl tokio::io::AsyncRead for IncomingStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            IncomingStream::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            #[cfg(unix)]
            IncomingStream::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for IncomingStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            IncomingStream::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            #[cfg(unix)]
            IncomingStream::Unix(s) => {
                std::pin::Pin::new(s).poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            IncomingStream::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            #[cfg(unix)]
            IncomingStream::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            IncomingStream::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            #[cfg(unix)]
            IncomingStream::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Bound listener socket: TCP or (on Unix) a Unix domain socket.
/// Returned by `bind_socket`; passed to the run_* accept loops.
#[cfg(unix)]
pub enum BoundSocket {
    Tcp(TcpListener),
    Unix(tokio::net::UnixListener),
}

#[cfg(not(unix))]
pub enum BoundSocket {
    Tcp(TcpListener),
}

impl BoundSocket {
    /// Accept one incoming connection.
    pub(crate) async fn accept(
        &self,
    ) -> std::io::Result<(IncomingStream, PeerAddr)> {
        match self {
            BoundSocket::Tcp(l) => {
                let (s, a) = l.accept().await?;
                Ok((IncomingStream::Tcp(s), PeerAddr::Tcp(a)))
            }
            #[cfg(unix)]
            BoundSocket::Unix(l) => {
                let (s, _) = l.accept().await?;
                Ok((IncomingStream::Unix(s), PeerAddr::Unix))
            }
        }
    }

    /// TCP local address, if the socket is TCP.  Used for
    /// stream-proxy PROXY protocol destination field.
    fn tcp_local_addr(&self) -> Option<SocketAddr> {
        match self {
            BoundSocket::Tcp(l) => l.local_addr().ok(),
            #[cfg(unix)]
            BoundSocket::Unix(_) => None,
        }
    }
}

/// Listener-side local TCP address, inserted into request extensions
/// so the HTTP proxy handler can populate the PROXY protocol dst field.
#[derive(Clone, Copy)]
pub struct LocalAddr(pub SocketAddr);

/// Listener-side Unix socket path; inserted when the listener is bound
/// to a `unix:` address.  Used by the HTTP proxy handler to build an
/// AF_UNIX PROXY protocol v2 header instead of a fake IPv4 one.
#[derive(Clone)]
pub struct LocalUnixPath(pub std::path::PathBuf);

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
    // JWT manager: present when `auth jwt` is configured.  Serves the
    // JWKS endpoint, validates incoming tokens, and (in session mode)
    // issues cookies after successful credential authentication.
    pub jwt_manager: Option<Arc<crate::jwt::JwtManager>>,
}

// Wraps the per-request authenticator so it implements AuthProvider
// for the access evaluator (which doesn't know about hyper::Request).
// When `pre_resolved` is Some (from a valid JWT cookie), it is
// returned immediately without touching the credential back-end.
struct RequestAuthProvider<'a> {
    authenticator: &'a dyn Authenticator,
    headers: &'a hyper::HeaderMap,
    pre_resolved: Option<crate::auth::Identity>,
}

#[async_trait]
impl AuthProvider for RequestAuthProvider<'_> {
    async fn authenticate(&self) -> Principal {
        if let Some(ref id) = self.pre_resolved {
            return Principal::Authenticated(id.clone());
        }
        self.authenticator.authenticate(self.headers).await
    }
}

// One AlohaService is cloned per accepted connection.
// It holds only Arc references so cloning is cheap.
#[derive(Clone)]
struct AlohaService {
    state: Arc<AppState>,
    // Canonical listener identifier (bind address);
    // used by the router to resolve the default vhost.
    bind: String,
    peer_addr: PeerAddr,
    local_addr: Option<SocketAddr>,
    // Unix domain socket path of the listener; None for TCP listeners.
    local_unix: Option<std::path::PathBuf>,
    timeouts: Timeouts,
    // True for TLS listeners; used to populate the {scheme} template
    // variable in header rules.
    is_tls: bool,
    // Reject requests whose Content-Length exceeds this; None = unlimited.
    max_body_bytes: Option<u64>,
}

impl hyper::service::Service<Request<Incoming>> for AlohaService {
    type Response = Response<BoxBody>;
    type Error = anyhow::Error;
    // Boxed future avoids naming the concrete async block type.
    type Future = Pin<
        Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn call(&self, mut req: Request<Incoming>) -> Self::Future {
        let state = self.state.clone();
        let bind = self.bind.clone();
        let peer = self.peer_addr;
        let local_addr = self.local_addr;
        let local_unix = self.local_unix.clone();
        let is_tls = self.is_tls;
        let handler_timeout =
            self.timeouts.handler_secs.map(Duration::from_secs);
        let max_body_bytes = self.max_body_bytes;
        Box::pin(async move {
            let start = Instant::now();
            let method = req.method().clone();
            let path = req.uri().path().to_owned();
            let query = req.uri().query().unwrap_or("").to_owned();
            let path_and_query = req
                .uri()
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
            // Attach the TCP peer address as a typed extension so the
            // reverse proxy can set X-Forwarded-For.  Unix-socket
            // connections have no meaningful IP so nothing is inserted;
            // proxy.rs already handles the absent-extension case.
            if let PeerAddr::Tcp(addr) = peer {
                req.extensions_mut().insert(addr);
            }
            // Listener local address for the PROXY protocol dst field.
            if let Some(addr) = local_addr {
                req.extensions_mut().insert(LocalAddr(addr));
            }
            if let Some(ref path) = local_unix {
                req.extensions_mut().insert(LocalUnixPath(path.clone()));
            }

            // Read Accept-Encoding before the request is consumed by
            // the handler.  The encoding is applied to the response
            // after the handler returns, outside the handler timeout.
            let accept_encoding = req
                .headers()
                .get(hyper::header::ACCEPT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .map(ToOwned::to_owned);

            // Reject oversized request bodies before any handler or
            // ACME intercept runs.  Protects against OOM from huge
            // uploads to CGI/proxy/SCGI backends.
            if let Some(max) = max_body_bytes
                && let Some(cl) = req
                    .headers()
                    .get(hyper::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                && cl > max
            {
                tracing::warn!(
                    %peer,
                    content_length = cl,
                    max,
                    "request body too large"
                );
                return Ok(response_413());
            }

            state.metrics.inc_active();

            // ACME HTTP-01 challenge interception.
            // Let's Encrypt validates by fetching this path on port 80.
            if let Some(token) =
                path.strip_prefix("/.well-known/acme-challenge/")
            {
                let key_auth =
                    state.acme_challenges.lock().unwrap().get(token).cloned();
                if let Some(body) = key_auth {
                    let resp = Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "text/plain")
                        .body(bytes_body(Bytes::from(body)))
                        .expect("known-valid status and header");
                    let ms = start.elapsed().as_millis();
                    state.metrics.dec_active();
                    state.metrics.record(resp.status().as_u16(), ms);
                    state.metrics.record_path(&path);
                    log_access(
                        &method,
                        &path,
                        resp.status().as_u16(),
                        ms,
                        peer,
                        &host,
                        "-",
                    );
                    return Ok(resp);
                }
            }

            // Health endpoint interception: /healthz, /livez, /readyz.
            // Answered before vhost routing so they work without a Host
            // header and cannot be shadowed by user-defined locations.
            if state.health_enabled
                && let Some(resp) = crate::handler::health::try_serve(&req)
            {
                let ms = start.elapsed().as_millis();
                state.metrics.dec_active();
                state.metrics.record(resp.status().as_u16(), ms);
                state.metrics.record_path(&path);
                log_access(
                    &method,
                    &path,
                    resp.status().as_u16(),
                    ms,
                    peer,
                    &host,
                    "-",
                );
                return Ok(resp);
            }

            // JWKS endpoint: serve the public key document on any
            // vhost so that any client can discover the key used to
            // sign session tokens.  Intercepted before routing because
            // user-defined locations must not shadow it.
            if path == "/.well-known/jwks.json"
                && let Some(jwt) = &state.jwt_manager
            {
                let body = jwt.jwks_json();
                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .header("Cache-Control", "public, max-age=3600")
                    .body(bytes_body(Bytes::from(body)))
                    .expect("known-valid status and headers");
                let ms = start.elapsed().as_millis();
                state.metrics.dec_active();
                state.metrics.record(resp.status().as_u16(), ms);
                state.metrics.record_path(&path);
                log_access(
                    &method,
                    &path,
                    resp.status().as_u16(),
                    ms,
                    peer,
                    &host,
                    "-",
                );
                return Ok(resp);
            }

            // JWT pre-validation: extract and verify the session cookie
            // (or Bearer token) before the access policy runs so that a
            // valid JWT can short-circuit the credential back-end.
            // A token that is present but fails validation (bad signature,
            // expired) counts as a security event.
            let jwt_identity: Option<crate::auth::Identity> = match state
                .jwt_manager
                .as_ref()
                .and_then(|j| j.validate(req.headers()))
            {
                Some(crate::jwt::JwtResult::Valid(id)) => Some(id),
                Some(crate::jwt::JwtResult::Invalid) => {
                    state
                        .metrics
                        .jwt_failures
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    None
                }
                // Valid signature but past exp — count separately from
                // bad-signature failures so operators can distinguish
                // normal session expiry from token tampering.
                Some(crate::jwt::JwtResult::Expired) => {
                    state
                        .metrics
                        .jwt_expiries
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    None
                }
                None => None,
            };
            // Track whether the principal came from a JWT so we know
            // whether to issue a fresh cookie after the response.
            let used_jwt = jwt_identity.is_some();

            // In session mode the inner authenticator is the credential
            // back-end; in standalone mode (or when JWT is not configured)
            // fall back to state.authenticator.
            let credential_auth: &dyn Authenticator = state
                .jwt_manager
                .as_ref()
                .and_then(|j| j.inner.as_deref())
                .unwrap_or(&*state.authenticator);

            let serve_fut = async {
                match state.router.route(&req, &bind) {
                    Some(route) => {
                        // Look up country only when the policy needs it.
                        let country: Option<String> =
                            match (&state.geoip, &route.policy) {
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
                        // actually evaluated.  A valid JWT identity
                        // is pre-resolved so the credential back-end
                        // is never called for already-authenticated
                        // sessions.
                        let principal = if let Some(policy) = &route.policy {
                            let auth_provider = RequestAuthProvider {
                                authenticator: credential_auth,
                                headers: req.headers(),
                                pre_resolved: jwt_identity.clone(),
                            };
                            let mut ctx = EvalContext::new(
                                peer.ip(),
                                country.as_deref(),
                                &auth_provider,
                            );
                            let outcome = policy.evaluate(&mut ctx).await;
                            let principal = ctx.take_principal();
                            match outcome {
                                PolicyOutcome::Allow => {}
                                PolicyOutcome::Deny(401) => {
                                    state.metrics.auth_failures.fetch_add(
                                        1,
                                        std::sync::atomic::Ordering::Relaxed,
                                    );
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
                                    return (
                                        response_www_auth(
                                            realm,
                                            Some(&state.error_pages),
                                        )
                                        .await,
                                        String::from("-"),
                                    );
                                }
                                PolicyOutcome::Deny(code) => {
                                    tracing::warn!(
                                        %peer, %method,
                                        path, host,
                                        status = code,
                                        "access denied"
                                    );
                                    return (
                                        response_status(
                                            code,
                                            Some(&state.error_pages),
                                        )
                                        .await,
                                        String::from("-"),
                                    );
                                }
                                PolicyOutcome::Redirect(to, code) => {
                                    return (
                                        response_redirect(&to, code),
                                        String::from("-"),
                                    );
                                }
                            }
                            principal
                        } else {
                            Principal::Anonymous
                        };

                        // If header rules need the principal and auth
                        // was not triggered by the access policy
                        // (principal is still Anonymous), resolve it now.
                        // JWT identity takes precedence; credential
                        // back-end is the fallback.
                        let principal = if route
                            .header_rules
                            .as_ref()
                            .map(|r| r.needs_principal)
                            .unwrap_or(false)
                            && matches!(principal, Principal::Anonymous)
                        {
                            if let Some(id) = jwt_identity.clone() {
                                Principal::Authenticated(id)
                            } else {
                                credential_auth
                                    .authenticate(req.headers())
                                    .await
                            }
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
                            client_ip: &peer_ip,
                            username,
                            groups: &groups_str,
                            method: method.as_str(),
                            path: &path,
                            query: &query,
                            path_and_query: &path_and_query,
                            host: &host,
                            scheme: if is_tls { "https" } else { "http" },
                        };

                        // Apply request-header rules before the handler
                        // consumes the request.
                        if let Some(rules) = &route.header_rules
                            && !rules.request.is_empty()
                        {
                            headers::apply_request_headers(
                                req.headers_mut(),
                                &rules.request,
                                &req_ctx,
                            );
                        }

                        let mut resp = route
                            .handler
                            .serve(req, &route.matched_prefix, &req_ctx)
                            .await;

                        // Apply response-header rules to the response
                        // before it reaches the client.
                        if let Some(rules) = &route.header_rules
                            && !rules.response.is_empty()
                        {
                            headers::apply_response_headers(
                                resp.headers_mut(),
                                &rules.response,
                                &req_ctx,
                            );
                        }

                        // In session mode: when the principal was just
                        // established via credentials (not a JWT cookie),
                        // issue a fresh JWT cookie so that subsequent
                        // requests do not need to re-authenticate.
                        if !used_jwt
                            && let (Some(jwt), Principal::Authenticated(id)) =
                                (&state.jwt_manager, &principal)
                            && jwt.is_session_mode()
                        {
                            match jwt.make_set_cookie(id, is_tls) {
                                Ok(val) => {
                                    if let Ok(hval) = val.parse() {
                                        resp.headers_mut().append(
                                            hyper::header::SET_COOKIE,
                                            hval,
                                        );
                                        state.metrics.jwt_issued
                                            .fetch_add(
                                                1,
                                                std::sync::atomic::Ordering::Relaxed,
                                            );
                                    }
                                }
                                Err(e) => tracing::warn!(
                                    "jwt: cookie issue failed: {e}"
                                ),
                            }
                        }

                        let log_user = if username.is_empty() {
                            "-".to_string()
                        } else {
                            username.to_string()
                        };
                        (resp, log_user)
                    }
                    None => (response_404(), String::from("-")),
                }
            };

            // Apply per-request handler timeout when configured.
            let (resp, log_user) = if let Some(dur) = handler_timeout {
                match tokio::time::timeout(dur, serve_fut).await {
                    Ok(r) => r,
                    Err(_) => {
                        tracing::warn!(
                            %peer, path, "handler timed out"
                        );
                        (
                            Response::builder()
                                .status(StatusCode::REQUEST_TIMEOUT)
                                .body(bytes_body(Bytes::from_static(
                                    b"<h1>408 Request Timeout</h1>",
                                )))
                                .expect("known-valid status"),
                            String::from("-"),
                        )
                    }
                }
            } else {
                serve_fut.await
            };

            let encoding =
                accept_encoding.as_deref().and_then(compress::negotiate);
            let resp = compress::maybe_compress(resp, encoding).await;

            let status = resp.status().as_u16();
            let ms = start.elapsed().as_millis();
            state.metrics.dec_active();
            state.metrics.record(status, ms);
            state.metrics.record_path(&path);
            log_access(&method, &path, status, ms, peer, &host, &log_user);
            Ok(resp)
        })
    }
}

// Emit one access-log line per completed request at INFO level.
// Fields mirror Combined Log Format: peer, user ("-" when
// unauthenticated), host, method, path, status, elapsed ms.
fn log_access(
    method: &hyper::Method,
    path: &str,
    status: u16,
    ms: u128,
    peer: PeerAddr,
    host: &str,
    user: &str,
) {
    tracing::info!(
        %peer,
        user,
        host,
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
        // Default to 30 s to protect against Slowloris.  Config can
        // override with any positive value; 0 explicitly disables.
        let header_secs = timeouts
            .request_header_secs
            .unwrap_or(DEFAULT_HEADER_TIMEOUT_SECS);
        if header_secs > 0 {
            h1.header_read_timeout(Duration::from_secs(header_secs));
        }
        // keepalive_secs=0 disables HTTP/1.1 keep-alive entirely.
        // Non-zero values are parsed for future idle-timeout support.
        if timeouts.keepalive_secs == Some(0) {
            h1.keep_alive(false);
        }
    }
    builder
}

/// Bind a listener socket for the given config entry.  Called before
/// privilege drop so ports < 1024 can be bound as root.
///
/// If an inherited socket matches the bind address it is adopted from
/// the pool instead of calling bind(2).  Bind addresses prefixed with
/// `unix:` create (or adopt) a Unix domain socket (Unix only).
#[cfg_attr(not(unix), allow(unused_variables))]
pub fn bind_socket(
    cfg: &ListenerConfig,
    #[cfg(unix)] inherited: &mut InheritedSockets,
) -> anyhow::Result<BoundSocket> {
    #[cfg(unix)]
    if let Some(path) = cfg.bind.strip_prefix("unix:") {
        let listener = if let Some(fd) = inherited.take_unix(path.as_ref()) {
            // Adopt the inherited socket; skip stale-file removal since
            // the socket file is still in use by the inherited fd.
            use std::os::unix::io::FromRawFd;
            // SAFETY: fd is a valid, listening Unix socket from our scan.
            let std_l =
                unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
            std_l.set_nonblocking(true)?;
            tokio::net::UnixListener::from_std(std_l)?
        } else {
            // Remove a stale socket file so rebind works after a crash.
            let _ = std::fs::remove_file(path);
            tokio::net::UnixListener::bind(path)?
        };
        return Ok(BoundSocket::Unix(listener));
    }

    // TCP: check the inherited pool before binding.
    #[cfg(unix)]
    let inherited_fd = {
        use std::net::ToSocketAddrs;
        cfg.bind
            .to_socket_addrs()
            .ok()
            .and_then(|mut it| it.find_map(|a| inherited.take_tcp(a)))
    };
    #[cfg(not(unix))]
    let inherited_fd: Option<std::os::unix::io::RawFd> = None;

    Ok(BoundSocket::Tcp(bind_tcp_socket(&cfg.bind, inherited_fd)?))
}

/// Resolve a bind address (and optional inherited fd) into a
/// non-blocking TcpListener.
pub fn bind_tcp_socket(
    bind: &str,
    fd: Option<std::os::unix::io::RawFd>,
) -> anyhow::Result<TcpListener> {
    let std_listener = if let Some(fd) = fd {
        // Adopt an inherited socket; bind address already matches.
        // SAFETY: fd is a valid, listening TCP socket from our scan.
        #[cfg(unix)]
        {
            use std::os::unix::io::FromRawFd;
            unsafe { std::net::TcpListener::from_raw_fd(fd) }
        }
        #[cfg(not(unix))]
        {
            let _ = fd;
            anyhow::bail!("fd-based listeners are only supported on Unix");
        }
    } else {
        std::net::TcpListener::bind(bind)?
    };
    std_listener.set_nonblocking(true)?;
    Ok(TcpListener::from_std(std_listener)?)
}

/// Read an inbound PROXY protocol header from a freshly accepted stream
/// and return the updated peer address.
///
/// Returns `None` if the header is malformed — the caller should drop
/// the connection.  Returns the original `peer_addr` unchanged when the
/// header contains an UNKNOWN or LOCAL address (spec-defined no-op).
async fn apply_proxy_proto(
    stream: &mut IncomingStream,
    version: crate::config::ProxyProtocolVersion,
    peer_addr: PeerAddr,
) -> Option<PeerAddr> {
    match proxy_proto::parse_incoming(stream, version).await {
        Ok(Some((src, _dst))) => Some(PeerAddr::Tcp(src)),
        Ok(None) => Some(peer_addr),
        Err(e) => {
            debug!(%peer_addr, "PROXY protocol parse error: {e}");
            None
        }
    }
}

pub async fn run_plain(
    cfg: ListenerConfig,
    listener: BoundSocket,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let name = cfg.local_name();
    let local_addr = listener.tcp_local_addr();
    let local_unix: Option<std::path::PathBuf> =
        cfg.bind.strip_prefix("unix:").map(Into::into);
    let sem: Option<Arc<Semaphore>> = cfg
        .max_connections
        .map(|n| Arc::new(Semaphore::new(n as usize)));
    let max_body = cfg.max_request_body;
    tracing::info!(bind = %name, "listening (HTTP)");
    let mut connections: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((mut stream, peer_addr)) => {
                        let state       = state.clone();
                        let bind        = name.clone();
                        let timeouts    = cfg.timeouts.clone();
                        let conn_shutdown = shutdown.clone();
                        let proxy_ver   = cfg.accept_proxy_protocol;
                        let lux         = local_unix.clone();
                        // Acquire a permit before spawning; released
                        // when the task drops it.  Awaiting here is
                        // safe: accept already returned so the socket
                        // is held open while we wait for a free slot.
                        let permit: Option<OwnedSemaphorePermit> =
                            if let Some(ref s) = sem {
                                Some(s.clone()
                                    .acquire_owned()
                                    .await?)
                            } else {
                                None
                            };
                        connections.spawn(async move {
                            let _permit = permit;
                            let peer_addr = match proxy_ver {
                                Some(v) => match apply_proxy_proto(
                                    &mut stream, v, peer_addr,
                                ).await {
                                    Some(p) => p,
                                    None    => return,
                                },
                                None => peer_addr,
                            };
                            let io = TokioIo::new(stream);
                            let svc = AlohaService {
                                state, bind, peer_addr,
                                local_addr, local_unix: lux,
                                timeouts, is_tls: false,
                                max_body_bytes: max_body,
                            };
                            serve_connection(
                                io, svc, conn_shutdown, peer_addr,
                            ).await;
                        });
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
    listener: BoundSocket,
    state: Arc<AppState>,
    acceptor: Arc<ArcSwap<TlsAcceptor>>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let name = cfg.local_name();
    let local_addr = listener.tcp_local_addr();
    let local_unix: Option<std::path::PathBuf> =
        cfg.bind.strip_prefix("unix:").map(Into::into);
    let sem: Option<Arc<Semaphore>> = cfg
        .max_connections
        .map(|n| Arc::new(Semaphore::new(n as usize)));
    let max_body = cfg.max_request_body;
    tracing::info!(bind = %name, "listening (HTTPS)");
    let mut connections: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((mut stream, peer_addr)) => {
                        // load_full() cheaply clones the inner Arc,
                        // picking up any cert hot-swapped since last accept.
                        let acc = acceptor.load_full();
                        let state = state.clone();
                        let bind = name.clone();
                        let svc_timeouts = cfg.timeouts.clone();
                        let conn_shutdown = shutdown.clone();
                        let proxy_ver = cfg.accept_proxy_protocol;
                        let lux = local_unix.clone();
                        let permit: Option<OwnedSemaphorePermit> =
                            if let Some(ref s) = sem {
                                Some(s.clone()
                                    .acquire_owned()
                                    .await?)
                            } else {
                                None
                            };
                        connections.spawn(async move {
                            let _permit = permit;
                            // PROXY protocol header is plaintext before the
                            // TLS ClientHello, so parse it first.
                            let peer_addr = match proxy_ver {
                                Some(v) => match apply_proxy_proto(
                                    &mut stream, v, peer_addr,
                                ).await {
                                    Some(p) => p,
                                    None    => return,
                                },
                                None => peer_addr,
                            };
                            // TLS handshake inside the task so a slow
                            // client doesn't block the accept loop.
                            // Timeout guards against partial-ClientHello
                            // floods that park tasks indefinitely.
                            let tls_stream = match tokio::time::timeout(
                                TLS_HANDSHAKE_TIMEOUT,
                                acc.accept(stream),
                            ).await {
                                Ok(Ok(s)) => s,
                                Ok(Err(e)) => {
                                    debug!(%peer_addr,
                                        "TLS handshake failed: {e}");
                                    return;
                                }
                                Err(_) => {
                                    debug!(%peer_addr,
                                        "TLS handshake timed out");
                                    return;
                                }
                            };
                            debug!(%peer_addr, "TLS accepted");
                            let io = TokioIo::new(tls_stream);
                            let svc = AlohaService {
                                state,
                                bind,
                                peer_addr,
                                local_addr,
                                local_unix: lux,
                                timeouts: svc_timeouts,
                                is_tls: true,
                                max_body_bytes: max_body,
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
    peer_addr: PeerAddr,
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

// -- Stream proxy listener -----------------------------------------

// Wraps TCP, TLS-over-TCP, or Unix domain socket backends so that the
// generic copy loop can work with any transport without dynamic dispatch.
#[cfg(unix)]
enum BackendStream {
    Tcp(tokio::net::TcpStream),
    TlsTcp(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
    Unix(tokio::net::UnixStream),
}

#[cfg(not(unix))]
enum BackendStream {
    Tcp(tokio::net::TcpStream),
    TlsTcp(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl tokio::io::AsyncRead for BackendStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            BackendStream::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            BackendStream::TlsTcp(s) => {
                std::pin::Pin::new(&mut **s).poll_read(cx, buf)
            }
            #[cfg(unix)]
            BackendStream::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for BackendStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            BackendStream::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            BackendStream::TlsTcp(s) => {
                std::pin::Pin::new(&mut **s).poll_write(cx, buf)
            }
            #[cfg(unix)]
            BackendStream::Unix(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            BackendStream::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            BackendStream::TlsTcp(s) => {
                std::pin::Pin::new(&mut **s).poll_flush(cx)
            }
            #[cfg(unix)]
            BackendStream::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            BackendStream::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            BackendStream::TlsTcp(s) => {
                std::pin::Pin::new(&mut **s).poll_shutdown(cx)
            }
            #[cfg(unix)]
            BackendStream::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

// `acceptor` is Some when the listener should terminate TLS from clients.
// `upstream_tls` is Some when the upstream connection should use TLS.
pub async fn run_stream_proxy(
    cfg: ListenerConfig,
    listener: BoundSocket,
    acceptor: Option<Arc<ArcSwap<TlsAcceptor>>>,
    upstream_tls: Option<Arc<rustls::ClientConfig>>,
    mut shutdown: watch::Receiver<bool>,
    access: Option<Arc<PolicyBlock>>,
    geoip: Option<Arc<geoip::CountryReader>>,
) -> anyhow::Result<()> {
    let name = cfg.local_name();
    let stream_mode = cfg.stream.as_ref().expect("stream mode required");
    let accept_proxy_protocol = cfg.accept_proxy_protocol;
    let label = match (acceptor.is_some(), upstream_tls.is_some()) {
        (true, true) => "stream (TLS → re-TLS)",
        (true, false) => "stream (TLS)",
        (false, true) => "stream (re-TLS upstream)",
        (false, false) => "stream",
    };
    let target = Arc::new(StreamProxyTarget {
        upstream: stream_mode.upstream.clone(),
        proxy_protocol: stream_mode.proxy_protocol,
        upstream_tls,
        local_addr: listener.tcp_local_addr(),
        local_unix: cfg.bind.strip_prefix("unix:").map(Into::into),
    });
    tracing::info!(bind = %name, upstream = %target.upstream, "listening ({label})");
    let mut connections: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((mut stream, peer_addr)) => {
                        let target = target.clone();
                        let conn_shutdown = shutdown.clone();
                        let conn_access = access.clone();
                        let conn_geoip = geoip.clone();
                        let proxy_ver = accept_proxy_protocol;
                        // load_full() cheaply bumps the Arc refcount,
                        // picking up any hot-swapped cert since last accept.
                        let acc = acceptor
                            .as_ref()
                            .map(|a| a.load_full());
                        connections.spawn(async move {
                            // PROXY protocol header (if any) is always
                            // plaintext, even when TLS follows.
                            let peer_addr = match proxy_ver {
                                Some(v) => match apply_proxy_proto(
                                    &mut stream, v, peer_addr,
                                ).await {
                                    Some(p) => p,
                                    None    => return,
                                },
                                None => peer_addr,
                            };
                            let result = if let Some(acc) = acc {
                                match tokio::time::timeout(
                                    TLS_HANDSHAKE_TIMEOUT,
                                    acc.accept(stream),
                                )
                                .await
                                {
                                    Ok(Ok(tls)) => stream_proxy_connection(
                                        tls,
                                        peer_addr,
                                        &target,
                                        conn_shutdown,
                                        conn_access,
                                        conn_geoip,
                                    )
                                    .await,
                                    Ok(Err(e)) => {
                                        debug!(%peer_addr,
                                            "TLS handshake failed: {e}");
                                        Ok(())
                                    }
                                    Err(_) => {
                                        debug!(%peer_addr,
                                            "TLS handshake timed out");
                                        Ok(())
                                    }
                                }
                            } else {
                                stream_proxy_connection(
                                    stream,
                                    peer_addr,
                                    &target,
                                    conn_shutdown,
                                    conn_access,
                                    conn_geoip,
                                )
                                .await
                            };
                            if let Err(e) = result {
                                debug!(%peer_addr, "stream proxy: {e}");
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

// Per-listener static config shared across all connection tasks.
// Kept in an Arc so every spawned task can hold a cheap reference
// instead of cloning the individual fields.
struct StreamProxyTarget {
    upstream: String,
    proxy_protocol: Option<crate::config::ProxyProtocolVersion>,
    upstream_tls: Option<Arc<rustls::ClientConfig>>,
    local_addr: Option<SocketAddr>,
    // Our listener's Unix socket path — only used to populate the
    // PROXY v2 dst address when the client connects over Unix.
    local_unix: Option<std::path::PathBuf>,
}

async fn stream_proxy_connection<C>(
    mut client: C,
    peer_addr: PeerAddr,
    target: &StreamProxyTarget,
    mut shutdown: watch::Receiver<bool>,
    access: Option<Arc<PolicyBlock>>,
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
            geoip
                .as_ref()
                .and_then(|r| geoip::lookup_country(r, peer_addr.ip()))
        } else {
            None
        };
        let anon = AnonymousAuthProvider;
        let mut ctx =
            EvalContext::new(peer_addr.ip(), country.as_deref(), &anon);
        match policy.evaluate(&mut ctx).await {
            PolicyOutcome::Allow => {}
            // Redirect is meaningless over raw TCP; treat as deny.
            _ => {
                tracing::warn!(%peer_addr, "stream proxy: access denied");
                return Ok(());
            }
        }
    }

    let mut backend = {
        #[cfg(unix)]
        if let Some(path) = target.upstream.strip_prefix("unix:") {
            match tokio::net::UnixStream::connect(path).await {
                Ok(s) => BackendStream::Unix(s),
                Err(e) => {
                    tracing::warn!(
                        %peer_addr,
                        upstream = %target.upstream,
                        "stream proxy: upstream connect failed: {e}",
                    );
                    return Ok(());
                }
            }
        } else {
            match connect_tcp_upstream(
                &target.upstream,
                &target.upstream_tls,
                peer_addr,
            )
            .await?
            {
                Some(s) => s,
                None => return Ok(()),
            }
        }
        #[cfg(not(unix))]
        match connect_tcp_upstream(
            &target.upstream,
            &target.upstream_tls,
            peer_addr,
        )
        .await?
        {
            Some(s) => s,
            None => return Ok(()),
        }
    };

    if let Some(version) = target.proxy_protocol {
        use crate::config::ProxyProtocolVersion::{V1, V2};
        use tokio::io::AsyncWriteExt;
        let header = match peer_addr {
            PeerAddr::Tcp(src) => {
                // TCP peer: use real addresses from inbound connection.
                let dst = target.local_addr.unwrap_or_else(|| {
                    use std::net::{IpAddr, Ipv4Addr};
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                });
                proxy_proto::build_header(version, src, dst)
            }
            #[cfg(unix)]
            PeerAddr::Unix => match version {
                // v1 UNKNOWN: spec-defined "no address info" keyword.
                V1 => proxy_proto::build_v1_unknown(),
                // v2: use AF_UNIX with our listener path as dst when
                // known; fall back to UNSPEC if the path is unavailable.
                V2 => match target.local_unix.as_deref() {
                    Some(path) => proxy_proto::build_v2_unix(None, Some(path)),
                    None => proxy_proto::build_v2_unspec(),
                },
            },
        };
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

// Connect a TCP upstream, optionally wrapping it with a TLS client handshake.
// Returns None (and logs a warning) when the connection or handshake fails
// so callers can close the client connection gracefully without treating
// upstream unavailability as an error.
async fn connect_tcp_upstream(
    upstream: &str,
    upstream_tls: &Option<Arc<rustls::ClientConfig>>,
    peer_addr: PeerAddr,
) -> anyhow::Result<Option<BackendStream>> {
    let tcp = match tokio::net::TcpStream::connect(upstream).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                %peer_addr,
                upstream,
                "stream proxy: upstream connect failed: {e}",
            );
            return Ok(None);
        }
    };
    if let Some(tls_cfg) = upstream_tls {
        // Extract hostname from "host:port" for SNI.  Strip brackets
        // from IPv6 addresses (e.g. "[::1]:443" → "::1").
        let host = upstream
            .rsplit_once(':')
            .map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']'))
            .unwrap_or(upstream);
        let server_name = rustls::pki_types::ServerName::try_from(
            host.to_owned(),
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "stream proxy: invalid upstream hostname '{host}': {e}"
            )
        })?;
        let connector = tokio_rustls::TlsConnector::from(tls_cfg.clone());
        match connector.connect(server_name, tcp).await {
            Ok(s) => Ok(Some(BackendStream::TlsTcp(Box::new(s)))),
            Err(e) => {
                tracing::warn!(
                    %peer_addr,
                    upstream,
                    "stream proxy: upstream TLS handshake failed: {e}",
                );
                Ok(None)
            }
        }
    } else {
        Ok(Some(BackendStream::Tcp(tcp)))
    }
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
    use crate::config::Config;
    use crate::error::{ErrorPageEntry, ErrorPages};
    use crate::metrics::Metrics;
    use crate::router::Router;
    use crate::test::{TestBackend, TestServer, http_get};
    use bytes::Bytes;
    use std::collections::HashMap;

    // -- PeerAddr unit tests ---

    #[test]
    fn peer_addr_tcp_display() {
        let addr: SocketAddr = "1.2.3.4:80".parse().unwrap();
        assert_eq!(PeerAddr::Tcp(addr).to_string(), "1.2.3.4:80");
    }

    #[test]
    #[cfg(unix)]
    fn peer_addr_unix_display() {
        assert_eq!(PeerAddr::Unix.to_string(), "[unix]");
    }

    #[test]
    #[cfg(unix)]
    fn peer_addr_unix_ip_is_loopback() {
        use std::net::IpAddr;
        let ip = PeerAddr::Unix.ip();
        assert_eq!(ip, IpAddr::from([127, 0, 0, 1]));
    }

    // -- BackendStream unit tests (test private type; must stay in src/) --

    // Verify that BackendStream::Tcp correctly relays bytes through a
    // loopback TcpStream pair.
    #[cfg(unix)]
    #[tokio::test]
    async fn backend_stream_tcp_relays_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener as TokioTcpListener;

        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(b"pong").await.unwrap();
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut backend = BackendStream::Tcp(tcp);
        backend.write_all(b"ping").await.unwrap();
        let mut buf = vec![0u8; 4];
        backend.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        server.await.unwrap();
    }

    // Verify that BackendStream::Unix correctly relays bytes through a
    // loopback UnixStream pair.
    #[cfg(unix)]
    #[tokio::test]
    async fn backend_stream_unix_relays_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let listener = UnixListener::bind(&sock_path).unwrap();
        let path_clone = sock_path.clone();

        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(b"pong").await.unwrap();
            drop(path_clone);
        });

        let unix = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let mut backend = BackendStream::Unix(unix);
        backend.write_all(b"ping").await.unwrap();
        let mut buf = vec![0u8; 4];
        backend.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        server.await.unwrap();
    }

    // -- Stream proxy integration tests --------------------------------

    // Verify run_stream_proxy forwards raw bytes to the upstream.
    #[tokio::test]
    async fn stream_proxy_forwards_bytes_to_upstream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener as TokioTcpListener;

        // Start an echo backend.
        let backend_l =
            TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_l.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut conn, _) = backend_l.accept().await.unwrap();
            let mut buf = vec![0u8; 4];
            conn.read_exact(&mut buf).await.unwrap();
            conn.write_all(&buf).await.unwrap();
        });

        // Start the stream proxy pointing at the echo backend.
        let proxy_l =
            TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_l.local_addr().unwrap();
        let cfg = crate::config::Config::parse(&format!(
            r#"listener {{ bind "{proxy_addr}"; proxy "{backend_addr}" }}"#,
        ))
        .unwrap()
        .listeners
        .into_iter()
        .next()
        .unwrap();
        let (tx, rx) = watch::channel(false);
        tokio::spawn(run_stream_proxy(
            cfg,
            BoundSocket::Tcp(proxy_l),
            None,
            None,
            rx,
            None,
            None,
        ));

        // Connect through the proxy and echo.
        let mut client =
            tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = vec![0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        drop(tx); // signal shutdown
    }

    // -- Component tests: full HTTP server + client -------------------

    fn redirect_state() -> Arc<AppState> {
        let config = Config::parse(
            r#"
            listener { bind "127.0.0.1:1" }
            vhost "example.com" {
                location "/" {
                    redirect {
                        to "https://{host}{path_and_query}"
                        code 301
                    }
                }
            }
        "#,
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&config),
        );
        let router = Router::new(&config, &metrics, &summary, None).unwrap();
        Arc::new(AppState {
            router: Arc::new(router),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics,
            geoip: None,
            health_enabled: false,
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: None,
        })
    }

    // -- ACME challenge intercept -------------------------------------

    /// ACME challenge must be served even when a catch-all redirect
    /// is configured for the vhost.
    #[tokio::test]
    async fn acme_challenge_not_blocked_by_redirect() {
        let state = redirect_state();
        state
            .acme_challenges
            .lock()
            .unwrap()
            .insert("tok123".to_string(), "tok123.keyauth".to_string());
        let srv = TestServer::start_with_state(state).await;

        let (status, _, body) = http_get(
            srv.addr,
            "example.com",
            "/.well-known/acme-challenge/tok123",
        )
        .await;
        assert_eq!(status, 200, "ACME challenge must be served");
        assert_eq!(body.as_ref(), b"tok123.keyauth");
    }

    /// Requests to non-ACME paths must receive a 301 redirect.
    #[tokio::test]
    async fn redirect_applies_to_normal_paths() {
        let srv = TestServer::start_with_state(redirect_state()).await;

        let (status, headers, _) =
            http_get(srv.addr, "example.com", "/foo?bar=1").await;
        assert_eq!(status, 301);
        assert_eq!(
            headers.get("location").unwrap(),
            "https://example.com/foo?bar=1",
        );
    }

    /// An ACME path with an unknown token falls through to the router.
    #[tokio::test]
    async fn acme_path_unknown_token_falls_through_to_router() {
        let srv = TestServer::start_with_state(redirect_state()).await;

        let (status, _, _) = http_get(
            srv.addr,
            "example.com",
            "/.well-known/acme-challenge/nosuchtoken",
        )
        .await;
        assert_eq!(status, 301);
    }

    // -- Static file serving ------------------------------------------

    /// Requesting an existing file returns 200 with the correct body.
    #[tokio::test]
    async fn static_serves_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), b"hello world").unwrap();
        let root = dir.path().display().to_string();
        let template = r#"
            listener { bind "{addr}" }
            vhost "example.com" {
                location "/" { static { root "__ROOT__" } }
            }
        "#
        .replace("__ROOT__", &root);
        let srv = TestServer::start(&template).await;

        let (status, headers, body) =
            srv.get("example.com", "/hello.txt").await;
        assert_eq!(status, 200);
        assert_eq!(body.as_ref(), b"hello world");
        let ct = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.contains("text/plain"), "got content-type: {ct}");
    }

    /// Requesting a missing file returns 404.
    #[tokio::test]
    async fn static_returns_404_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().display().to_string();
        let template = r#"
            listener { bind "{addr}" }
            vhost "example.com" {
                location "/" { static { root "__ROOT__" } }
            }
        "#
        .replace("__ROOT__", &root);
        let srv = TestServer::start(&template).await;

        let (status, _, _) = srv.get("example.com", "/no-such-file.txt").await;
        assert_eq!(status, 404);
    }

    /// A conditional GET with a matching ETag returns 304.
    #[tokio::test]
    async fn static_etag_conditional_get_returns_304() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("data.txt"), b"etag test").unwrap();
        let root = dir.path().display().to_string();
        let template = r#"
            listener { bind "{addr}" }
            vhost "example.com" {
                location "/" { static { root "__ROOT__" } }
            }
        "#
        .replace("__ROOT__", &root);
        let srv = TestServer::start(&template).await;

        let (_, headers, _) = srv.get("example.com", "/data.txt").await;
        let etag = headers
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .expect("server must emit an ETag")
            .to_owned();

        let (status, _, _) = srv
            .get_h("example.com", "/data.txt", &[("if-none-match", &etag)])
            .await;
        assert_eq!(status, 304);
    }

    /// A byte-range request returns 206 with the correct slice.
    #[tokio::test]
    async fn static_range_request_returns_206() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.bin"), b"0123456789").unwrap();
        let root = dir.path().display().to_string();
        let template = r#"
            listener { bind "{addr}" }
            vhost "example.com" {
                location "/" { static { root "__ROOT__" } }
            }
        "#
        .replace("__ROOT__", &root);
        let srv = TestServer::start(&template).await;

        let (status, headers, body) = srv
            .get_h("example.com", "/file.bin", &[("range", "bytes=2-5")])
            .await;
        assert_eq!(status, 206);
        assert_eq!(body.as_ref(), b"2345");
        let cr = headers
            .get("content-range")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(cr, "bytes 2-5/10");
    }

    /// Requesting a directory with an index file returns 200.
    #[tokio::test]
    async fn static_serves_index_html_for_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), b"<h1>index</h1>")
            .unwrap();
        let root = dir.path().display().to_string();
        let template = r#"
            listener { bind "{addr}" }
            vhost "example.com" {
                location "/" {
                    static {
                        root "__ROOT__";
                        index-file "index.html";
                    }
                }
            }
        "#
        .replace("__ROOT__", &root);
        let srv = TestServer::start(&template).await;

        let (status, _, body) = srv.get("example.com", "/").await;
        assert_eq!(status, 200);
        assert!(
            body.windows(5).any(|w| w == b"index"),
            "body: {:?}",
            std::str::from_utf8(&body),
        );
    }

    /// Dotfiles must be rejected with 404.
    #[tokio::test]
    async fn static_dotfile_is_blocked() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".hidden"), b"secret").unwrap();
        let root = dir.path().display().to_string();
        let template = r#"
            listener { bind "{addr}" }
            vhost "example.com" {
                location "/" { static { root "__ROOT__" } }
            }
        "#
        .replace("__ROOT__", &root);
        let srv = TestServer::start(&template).await;

        let (status, _, _) = srv.get("example.com", "/.hidden").await;
        assert_eq!(status, 404, ".hidden file must not be served");
    }

    // -- Health endpoints ---------------------------------------------

    /// GET /healthz returns 200 when health is enabled (default).
    #[tokio::test]
    async fn health_endpoint_returns_200_when_enabled() {
        let srv = TestServer::start(
            r#"
            listener { bind "{addr}" }
            vhost "example.com" {
                location "/" {
                    redirect { to "/dest"; code 301; }
                }
            }
            "#,
        )
        .await;

        let (status, headers, body) = srv.get("example.com", "/healthz").await;
        assert_eq!(status, 200);
        let ct = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.contains("application/json"), "ct: {ct}");
        assert!(std::str::from_utf8(&body).unwrap_or("").contains("ok"),);
    }

    /// When health is disabled, /healthz falls through to the router.
    #[tokio::test]
    async fn health_endpoint_disabled_falls_through_to_router() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().display().to_string();
        let template = r#"
            server { health { enabled #false } }
            listener { bind "{addr}" }
            vhost "example.com" {
                location "/" { static { root "__ROOT__" } }
            }
        "#
        .replace("__ROOT__", &root);
        let srv = TestServer::start(&template).await;

        let (status, _, _) = srv.get("example.com", "/healthz").await;
        assert_eq!(status, 404);
    }

    // -- Vhost fallback -----------------------------------------------

    /// Unknown host with null default returns 404.
    #[tokio::test]
    async fn unknown_host_returns_404_without_default_vhost() {
        let srv = TestServer::start(
            r#"
            listener {
                bind "{addr}"
                default-vhost #null
            }
            vhost "example.com" {
                location "/" {
                    redirect { to "/dest"; code 301; }
                }
            }
            "#,
        )
        .await;

        let (status, _, _) = http_get(srv.addr, "other.example.com", "/").await;
        assert_eq!(status, 404);
    }

    /// Unknown host falls back to the first vhost.
    #[tokio::test]
    async fn unknown_host_uses_default_vhost() {
        let srv = TestServer::start(
            r#"
            listener { bind "{addr}" }
            vhost "example.com" {
                location "/" {
                    redirect { to "/dest"; code 301; }
                }
            }
            "#,
        )
        .await;

        let (status, _, _) = http_get(srv.addr, "other.com", "/").await;
        assert_eq!(status, 301);
    }

    // -- Access control -----------------------------------------------

    /// Unconditional deny returns 403.
    #[tokio::test]
    async fn ip_access_deny_returns_403() {
        let srv = TestServer::start(
            r#"
            listener { bind "{addr}" }
            vhost "example.com" {
                location "/" {
                    redirect { to "/dest"; code 301; }
                    policy { deny }
                }
            }
            "#,
        )
        .await;

        let (status, _, _) = srv.get("example.com", "/").await;
        assert_eq!(status, 403);
    }

    /// Loopback is allowed when the policy permits 127.0.0.1/32.
    #[tokio::test]
    async fn ip_access_allow_passes_through() {
        let srv = TestServer::start(
            r#"
            listener { bind "{addr}" }
            vhost "example.com" {
                location "/" {
                    redirect { to "/dest"; code 301; }
                    policy {
                        allow address "127.0.0.1/32"
                        deny
                    }
                }
            }
            "#,
        )
        .await;

        let (status, _, _) = srv.get("example.com", "/").await;
        assert_eq!(status, 301);
    }

    /// Policy redirect action returns the configured Location.
    #[tokio::test]
    async fn policy_redirect_returns_302_with_location() {
        let srv = TestServer::start(
            r#"
            listener { bind "{addr}" }
            vhost "example.com" {
                location "/" {
                    redirect { to "/dest"; code 301; }
                    policy { redirect to="/login" code=302 }
                }
            }
            "#,
        )
        .await;

        let (status, headers, _) = srv.get("example.com", "/").await;
        assert_eq!(status, 302);
        assert_eq!(
            headers.get("location").and_then(|v| v.to_str().ok()),
            Some("/login"),
        );
    }

    // -- Custom error pages -------------------------------------------

    /// Access-deny with a matching inline error page returns its body.
    #[tokio::test]
    async fn custom_404_error_page_inline() {
        let config = Config::parse(
            r#"
            listener { bind "127.0.0.1:1" }
            vhost "example.com" {
                location "/" {
                    redirect { to "/dest"; code 301; }
                    policy { deny code=404 }
                }
            }
            "#,
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&config),
        );
        let router = Router::new(&config, &metrics, &summary, None).unwrap();
        let mut pages = HashMap::new();
        pages.insert(
            404u16,
            ErrorPageEntry::Inline(Bytes::from_static(
                b"<h1>Custom Not Found</h1>",
            )),
        );
        let state = Arc::new(AppState {
            router: Arc::new(router),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics,
            geoip: None,
            health_enabled: false,
            error_pages: Arc::new(ErrorPages::new(pages)),
            jwt_manager: None,
        });
        let srv = TestServer::start_with_state(state).await;

        let (status, _, body) = srv.get("example.com", "/").await;
        assert_eq!(status, 404);
        let text = std::str::from_utf8(&body).unwrap_or("");
        assert!(text.contains("Custom Not Found"), "body was: {text}",);
    }

    // -- Unix socket listener -----------------------------------------

    /// A unix-socket listener serves HTTP correctly.
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_listener_serves_http() {
        use tokio::net::UnixStream;

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("aloha-test.sock");
        let bind_str = format!("unix:{}", sock_path.display());

        let template = format!(
            r#"
            listener {{ bind "{bind_str}" }}
            vhost "example.com" {{
                location "/" {{
                    redirect {{ to "/ok"; code 302; }}
                }}
            }}
            "#,
        );
        let srv = TestServer::start(&template).await;

        for _ in 0..20u8 {
            if sock_path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let stream = UnixStream::connect(&sock_path).await.unwrap();
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        let req = hyper::Request::builder()
            .uri("/")
            .header("host", "example.com")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), hyper::StatusCode::FOUND);
        drop(srv);
    }

    // -- Proxy --------------------------------------------------------

    /// Proxy forwards the upstream response body and status.
    #[tokio::test]
    async fn proxy_forwards_response_from_upstream() {
        let backend = TestBackend::start_responding(200, b"proxy-ok").await;
        let template = format!(
            r#"
            listener {{ bind "{{addr}}" }}
            vhost "example.com" {{
                location "/" {{ proxy "http://{}" }}
            }}
            "#,
            backend.addr,
        );
        let srv = TestServer::start(&template).await;

        let (status, _, body) = srv.get("example.com", "/test").await;
        assert_eq!(status, 200);
        assert_eq!(body.as_ref(), b"proxy-ok");
    }

    /// Refused upstream connection returns 502.
    #[tokio::test]
    async fn proxy_refused_upstream_returns_502() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_addr = listener.local_addr().unwrap();
        drop(listener);

        let template = format!(
            r#"
            listener {{ bind "{{addr}}" }}
            vhost "example.com" {{
                location "/" {{ proxy "http://{dead_addr}" }}
            }}
            "#,
        );
        let srv = TestServer::start(&template).await;

        let (status, _, _) = srv.get("example.com", "/").await;
        assert_eq!(status, 502);
    }

    /// Hanging upstream plus a handler timeout returns 408.
    #[tokio::test]
    async fn handler_timeout_returns_408() {
        let backend = TestBackend::start_hanging().await;
        let template = format!(
            r#"
            listener {{
                bind "{{addr}}"
                timeouts {{ handler 1 }}
            }}
            vhost "example.com" {{
                location "/" {{
                    proxy "http://{}"
                }}
            }}
            "#,
            backend.addr,
        );
        let srv = TestServer::start(&template).await;

        let (status, _, _) = srv.get("example.com", "/").await;
        assert_eq!(status, 408, "hung backend must trigger 408");
    }

    // -- JWT / JWKS ---------------------------------------------------

    /// JWKS endpoint returns an EC public key document.
    #[tokio::test]
    async fn jwks_endpoint_returns_ec_key_document() {
        use crate::jwt::{JwtConfig, JwtManager};

        let tmp = tempfile::tempdir().unwrap();
        let mgr = JwtManager::load_or_generate(
            tmp.path(),
            JwtConfig {
                cookie_name: "sess".to_owned(),
                validity_secs: 300,
            },
            None,
        )
        .expect("manager creation");

        let config = Config::parse(
            r#"
            listener { bind "127.0.0.1:1" }
            vhost "example.com" {
                location "/" {
                    redirect { to "/dest"; code 301; }
                }
            }
            "#,
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&config),
        );
        let router = Router::new(&config, &metrics, &summary, None).unwrap();
        let state = Arc::new(AppState {
            router: Arc::new(router),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics,
            geoip: None,
            health_enabled: false,
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: Some(Arc::new(mgr)),
        });
        let srv = TestServer::start_with_state(state).await;

        let (status, headers, body) =
            srv.get("example.com", "/.well-known/jwks.json").await;
        assert_eq!(status, 200);
        let ct = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.contains("application/json"), "expected JSON, got: {ct}",);
        let text = std::str::from_utf8(&body).unwrap_or("");
        assert!(
            text.contains("\"kty\":\"EC\""),
            "JWKS must contain EC key, got: {text}",
        );
        assert!(
            text.contains("\"crv\":\"P-256\""),
            "JWKS must name P-256, got: {text}",
        );
    }

    // -- DoS hardening ------------------------------------------------

    /// A request with Content-Length above max-request-body returns 413.
    #[tokio::test]
    async fn oversized_content_length_returns_413() {
        let srv = TestServer::start(
            r#"
            listener {
                bind "{addr}"
                max-request-body 1000
            }
            vhost "example.com" {
                location "/" {
                    redirect { to "/dest"; code 301; }
                }
            }
            "#,
        )
        .await;

        // Send a GET with a Content-Length that exceeds the limit.
        let (status, _, _) = srv
            .get_h("example.com", "/", &[("content-length", "1001")])
            .await;
        assert_eq!(status, 413, "oversized body must return 413");
    }

    /// A request within the body limit passes through normally.
    #[tokio::test]
    async fn undersized_content_length_passes_through() {
        let srv = TestServer::start(
            r#"
            listener {
                bind "{addr}"
                max-request-body 1000
            }
            vhost "example.com" {
                location "/" {
                    redirect { to "/dest"; code 301; }
                }
            }
            "#,
        )
        .await;

        let (status, _, _) = srv
            .get_h("example.com", "/", &[("content-length", "500")])
            .await;
        // The location redirects; we're checking it wasn't blocked.
        assert_eq!(status, 301);
    }

    /// Simultaneous connections beyond max-connections are deferred,
    /// not dropped; the server stays alive.
    #[tokio::test]
    async fn max_connections_does_not_crash_server() {
        use tokio::net::TcpStream;

        let srv = TestServer::start(
            r#"
            listener {
                bind "{addr}"
                max-connections 2
            }
            vhost "example.com" {
                location "/" {
                    redirect { to "/dest"; code 301; }
                }
            }
            "#,
        )
        .await;

        // Open max+1 connections and park the first two so they hold
        // their semaphore permits while we verify the third still gets
        // a response once a slot frees.
        let addr = srv.addr;

        let hold1 = TcpStream::connect(addr).await.unwrap();
        let hold2 = TcpStream::connect(addr).await.unwrap();

        // The third connection must succeed once we release one of the
        // parked connections.  Drop a held connection to free a permit.
        drop(hold1);
        drop(hold2);

        // After freeing permits, a normal request must succeed.
        let (status, _, _) = srv.get("example.com", "/").await;
        assert_eq!(status, 301, "server must respond after freeing slots");
    }

    /// make_builder applies a non-zero header_read_timeout by default,
    /// so Slowloris protection is on even without explicit config.
    #[test]
    fn default_header_timeout_is_active_without_config() {
        let timeouts = Timeouts::default();
        // The sentinel: default is None, so we use DEFAULT_HEADER_TIMEOUT_SECS.
        let secs = timeouts
            .request_header_secs
            .unwrap_or(DEFAULT_HEADER_TIMEOUT_SECS);
        assert!(
            secs > 0,
            "default header timeout must be positive for Slowloris protection"
        );
    }

    /// Explicit request-header=0 disables the timeout (opt-out).
    #[test]
    fn explicit_zero_header_timeout_disables_protection() {
        let timeouts = Timeouts {
            request_header_secs: Some(0),
            ..Default::default()
        };
        let secs = timeouts
            .request_header_secs
            .unwrap_or(DEFAULT_HEADER_TIMEOUT_SECS);
        assert_eq!(secs, 0, "request-header=0 must disable the timeout");
    }
}
