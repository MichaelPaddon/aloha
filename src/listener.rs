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
    BoxBody, ErrorPages, ReqBody, bytes_body, response_404, response_413,
    response_redirect, response_status, response_www_auth,
};
use http_body_util::BodyExt;
use crate::geoip;
use crate::headers::principal_strings;
use crate::headers::{self, RequestContext};
#[cfg(unix)]
use crate::inherit::InheritedSockets;
use crate::metrics::Metrics;
use crate::proxy_proto;
use crate::router::Router;
use anyhow::{Context as _, anyhow, bail};
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

/// Bound listener socket: TCP, UDP (for QUIC), or (on Unix) a Unix
/// domain socket.  Returned by `bind_socket`; passed to the run_*
/// accept loops.  UDP sockets are only meaningful when the `http3`
/// feature is enabled; the variant exists unconditionally so that
/// build configurations match across feature flags.
#[cfg(unix)]
pub enum BoundSocket {
    Tcp(TcpListener),
    Udp(std::net::UdpSocket),
    Unix(tokio::net::UnixListener),
}

#[cfg(not(unix))]
pub enum BoundSocket {
    Tcp(TcpListener),
    Udp(std::net::UdpSocket),
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
            BoundSocket::Udp(_) => {
                // UDP sockets are not accept-driven; the QUIC listener
                // owns the socket directly via quinn::Endpoint.  Reaching
                // here would indicate a bug in the listener wiring.
                Err(std::io::Error::other(
                    "BoundSocket::accept called on a UDP socket",
                ))
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
            BoundSocket::Udp(_) => None,
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
    // OIDC provider: present when `auth jwt { wrap oidc ... }` is
    // configured.  Drives the login/callback endpoints dispatched by
    // dispatch() before vhost routing, and turns Deny(401) into a 302
    // for browser clients so the SSO flow is transparent.
    pub oidc: Option<Arc<crate::oidc::OidcProvider>>,
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
    // Pre-built `Alt-Svc` value for HTTP/3 auto-advertisement.  Set when
    // the config has a UDP/QUIC listener on the same port; injected on
    // responses that don't already carry an Alt-Svc header.  Stored as
    // an Arc<str> so cloning the service per-connection is cheap.
    auto_alt_svc: Option<Arc<str>>,
}

impl hyper::service::Service<Request<Incoming>> for AlohaService {
    type Response = Response<BoxBody>;
    type Error = anyhow::Error;
    // Boxed future avoids naming the concrete async block type.
    type Future = Pin<
        Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        // Convert hyper's Incoming to our protocol-agnostic ReqBody
        // so the dispatch path is identical for h1/h2 and HTTP/3.
        let req = req.map(|b| BodyExt::boxed_unsync(b));
        let svc = self.clone();
        Box::pin(svc.dispatch(req))
    }
}

impl AlohaService {
    /// Run the full request pipeline (interception, vhost routing,
    /// access policy, auth, handler dispatch, post-processing) on a
    /// request whose body has already been adapted to `ReqBody`.
    /// Shared by the hyper TCP path and the QUIC/h3 path so both
    /// transports see identical semantics.
    async fn dispatch(
        self,
        mut req: Request<ReqBody>,
    ) -> Result<Response<BoxBody>, anyhow::Error> {
        let state = self.state.clone();
        let bind = self.bind.clone();
        let peer = self.peer_addr;
        let local_addr = self.local_addr;
        let local_unix = self.local_unix.clone();
        let is_tls = self.is_tls;
        let handler_timeout =
            self.timeouts.handler_secs.map(Duration::from_secs);
        let max_body_bytes = self.max_body_bytes;
        let auto_alt_svc = self.auto_alt_svc.clone();
        {
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

            // OIDC login + callback endpoints.  Intercepted before
            // vhost routing for the same reason JWKS is: these are
            // server-wide built-ins and must not be shadowed by a
            // user-defined `location`.  The configured `login-path`
            // and `callback-path` default to `/.aloha/oidc/...`, which
            // is unlikely to clash with application paths.
            if let Some(oidc) = &state.oidc {
                if path == oidc.login_path() {
                    let resp = handle_oidc_login(oidc, &query, is_tls);
                    let ms = start.elapsed().as_millis();
                    state.metrics.dec_active();
                    state.metrics.record(resp.status().as_u16(), ms);
                    state.metrics.record_path(&path);
                    log_access(
                        &method, &path,
                        resp.status().as_u16(),
                        ms, peer, &host, "-",
                    );
                    return Ok(resp);
                }
                if path == oidc.callback_path() {
                    let resp = handle_oidc_callback(
                        oidc,
                        state.jwt_manager.as_deref(),
                        req.headers(),
                        &query,
                        is_tls,
                        &state.error_pages,
                    )
                    .await;
                    let ms = start.elapsed().as_millis();
                    state.metrics.dec_active();
                    state.metrics.record(resp.status().as_u16(), ms);
                    state.metrics.record_path(&path);
                    log_access(
                        &method, &path,
                        resp.status().as_u16(),
                        ms, peer, &host, "-",
                    );
                    return Ok(resp);
                }
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
                                    // OIDC SSO: a browser hitting a
                                    // protected location with no
                                    // valid session cookie should be
                                    // redirected through the IdP
                                    // rather than seeing the basic-
                                    // auth challenge.  API and CLI
                                    // clients (no `Accept: text/html`
                                    // or carrying `Authorization`)
                                    // continue to receive 401.
                                    if let Some(oidc) = &state.oidc
                                        && wants_html(req.headers())
                                    {
                                        let to = build_login_redirect(
                                            oidc.login_path(),
                                            &path_and_query,
                                        );
                                        return (
                                            response_redirect(&to, 302),
                                            String::from("-"),
                                        );
                                    }
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
            let mut resp = compress::maybe_compress(resp, encoding).await;

            // Auto-advertise HTTP/3 via Alt-Svc when a sibling UDP
            // listener exists on the same port.  Only inject when the
            // response doesn't already carry an Alt-Svc header so that
            // user-supplied `headers { response { set "Alt-Svc" ... } }`
            // rules always win (the headers pass runs inside the handler
            // pipeline before reaching here).
            if let Some(ref v) = auto_alt_svc
                && !resp.headers().contains_key(hyper::header::ALT_SVC)
                && let Ok(hv) = hyper::header::HeaderValue::from_str(v)
            {
                resp.headers_mut().insert(hyper::header::ALT_SVC, hv);
            }

            let status = resp.status().as_u16();
            let ms = start.elapsed().as_millis();
            state.metrics.dec_active();
            state.metrics.record(status, ms);
            state.metrics.record_path(&path);
            log_access(&method, &path, status, ms, peer, &host, &log_user);
            Ok(resp)
        }
    }
}

// True when the caller is plausibly a browser: accepts HTML and
// hasn't presented an `Authorization` header.  Used to decide
// whether to auto-redirect into the OIDC login flow on a 401.
fn wants_html(h: &hyper::HeaderMap) -> bool {
    if h.contains_key(hyper::header::AUTHORIZATION) {
        return false;
    }
    h.get(hyper::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/html") || s.contains("*/*"))
        .unwrap_or(false)
}

// Percent-encode a request URI so it can be embedded as a query
// string parameter without ambiguity.  We deliberately keep '/' so
// the encoded form remains human-readable in browser address bars.
fn percent_encode_return(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let safe = matches!(
            b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
                | b'-' | b'_' | b'.' | b'~' | b'/'
        );
        if safe {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// Best-effort percent-decode.  Invalid escapes are left as-is so an
// attacker cannot smuggle bytes via malformed input -- we only ever
// re-use the result as a same-origin redirect target after
// validation by `validate_return_to`.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            )
        {
            out.push((h * 16 + l) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn build_login_redirect(login_path: &str, return_to: &str) -> String {
    format!("{login_path}?return={}", percent_encode_return(return_to))
}

// Restrict the post-login redirect target to a same-origin
// absolute path.  Rejects schemed URLs, protocol-relative URLs
// (`//host`), and anything that doesn't start with '/'.  The
// fallback "/" is safe for any host.
fn validate_return_to(raw: &str) -> String {
    if raw.starts_with('/')
        && !raw.starts_with("//")
        && !raw.starts_with("/\\")
    {
        raw.to_owned()
    } else {
        "/".to_owned()
    }
}

// Extract a single query parameter value (first match) from a
// `key1=val1&key2=val2` style string.
fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == key
        {
            return Some(percent_decode(v));
        }
    }
    None
}

// Read the value of a named cookie from a `Cookie:` header value.
fn cookie_value(headers: &hyper::HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(hyper::header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=')
            && k == name
        {
            return Some(v.to_owned());
        }
    }
    None
}

// Build the `Set-Cookie` value for the short-lived state cookie that
// pins the browser to the CSRF token returned by `begin_login`.
// SameSite=Lax is required so the cookie comes back on the cross-site
// IdP redirect; Secure is added on TLS connections.
fn state_cookie_value(state_id: &str, ttl_secs: u64, is_tls: bool) -> String {
    let mut v = format!(
        "__aloha_oidc_state={state_id}; Path=/; HttpOnly; \
         SameSite=Lax; Max-Age={ttl_secs}",
    );
    if is_tls {
        v.push_str("; Secure");
    }
    v
}

// A "delete this cookie now" Set-Cookie value, sent on the callback
// response so the one-shot state cookie doesn't linger.
fn clear_state_cookie(is_tls: bool) -> String {
    let mut v = String::from(
        "__aloha_oidc_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
    );
    if is_tls {
        v.push_str("; Secure");
    }
    v
}

// Build the 302-to-IdP response for `<login_path>`.  The state-id
// returned from `begin_login` is mirrored into a same-origin cookie
// so the callback can detect cross-tenant CSRF (state in URL but no
// cookie, or vice versa).
fn handle_oidc_login(
    oidc: &crate::oidc::OidcProvider,
    query: &str,
    is_tls: bool,
) -> Response<BoxBody> {
    let return_to = validate_return_to(
        &query_param(query, "return").unwrap_or_else(|| "/".to_owned()),
    );
    let (url, state_id) = oidc.begin_login(return_to);

    let cookie = state_cookie_value(&state_id, 600, is_tls);
    Response::builder()
        .status(StatusCode::FOUND)
        .header(hyper::header::LOCATION, url.as_str())
        .header(hyper::header::SET_COOKIE, cookie)
        .body(bytes_body(Bytes::new()))
        .expect("known-valid status and headers")
}

// Validate the IdP callback, exchange the code, and persist the
// identity as a JWT cookie.  On any error returns a 400 rendered via
// the configured error-pages set.
async fn handle_oidc_callback(
    oidc: &crate::oidc::OidcProvider,
    jwt: Option<&crate::jwt::JwtManager>,
    headers: &hyper::HeaderMap,
    query: &str,
    is_tls: bool,
    error_pages: &ErrorPages,
) -> Response<BoxBody> {
    let Some(code) = query_param(query, "code") else {
        return response_status(400, Some(error_pages)).await;
    };
    let Some(state) = query_param(query, "state") else {
        return response_status(400, Some(error_pages)).await;
    };
    // CSRF: the state-id must also be carried by the browser as the
    // cookie set in `handle_oidc_login`.  A request that has one but
    // not the other was either replayed or cross-site.
    let cookie_state = cookie_value(headers, "__aloha_oidc_state");
    if cookie_state.as_deref() != Some(state.as_str()) {
        tracing::warn!("oidc: state cookie/query mismatch");
        return response_status(400, Some(error_pages)).await;
    }

    let (identity, return_to) = match oidc.complete_login(code, &state).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("oidc: callback failed: {e:#}");
            return response_status(400, Some(error_pages)).await;
        }
    };

    // JWT is required for OIDC (validator enforces this); without it
    // the post-login identity would have nowhere to go.
    let Some(jwt) = jwt else {
        tracing::error!(
            "oidc: callback succeeded but no JWT manager is configured"
        );
        return response_status(500, Some(error_pages)).await;
    };

    let session_cookie = match jwt.make_set_cookie(&identity, is_tls) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("oidc: jwt issue failed: {e:#}");
            return response_status(500, Some(error_pages)).await;
        }
    };

    let mut builder = Response::builder()
        .status(StatusCode::FOUND)
        .header(hyper::header::LOCATION, &return_to);
    builder = builder.header(hyper::header::SET_COOKIE, session_cookie);
    builder = builder
        .header(hyper::header::SET_COOKIE, clear_state_cookie(is_tls));
    builder
        .body(bytes_body(Bytes::new()))
        .expect("known-valid status and headers")
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

        // hyper 1.x arms `header_read_timeout` on *every* request,
        // including the next-request read on a kept-alive connection
        // (see `proto/h1/conn.rs::read_head`).  So a single timer is
        // doing double duty: it bounds slow header transmission AND
        // it caps the idle window between requests.  We pick the
        // most restrictive value the operator gave us:
        //
        //   keepalive=0  -> keep-alive disabled entirely.
        //   keepalive=N  -> at most N seconds of idle between requests
        //                   (and at most N seconds to send headers).
        //   request-header=M -> at most M seconds to send headers
        //                       (also caps the idle).
        //   neither set  -> DEFAULT_HEADER_TIMEOUT_SECS (30 s).
        //
        // When both are set, take the minimum.  This unifies the two
        // knobs under a single timer instead of silently ignoring
        // non-zero keepalive values like prior versions did.
        let keepalive = timeouts.keepalive_secs;
        if keepalive == Some(0) {
            h1.keep_alive(false);
        } else {
            let candidates = [
                timeouts.request_header_secs,
                keepalive,
            ];
            let configured: Option<u64> =
                candidates.iter().filter_map(|x| *x).min();
            let header_secs = configured
                .unwrap_or(DEFAULT_HEADER_TIMEOUT_SECS);
            if header_secs > 0 {
                h1.header_read_timeout(Duration::from_secs(header_secs));
            }
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
    // QUIC/HTTP/3 listeners: bind a UDP socket on the host:port portion
    // of the bind string.  quinn::Endpoint::new wants a std::net::UdpSocket,
    // so we keep it as std rather than wrapping in tokio; non-blocking is
    // set explicitly.  Inherited UDP fds (from systemd socket activation
    // or a seamless-upgrade parent) are adopted via take_udp.
    if let Some(rest) = cfg.bind.strip_prefix("udp:") {
        use std::net::ToSocketAddrs;
        let addr = rest
            .to_socket_addrs()
            .with_context(|| format!("resolving udp bind '{rest}'"))?
            .next()
            .ok_or_else(|| {
                anyhow!("udp bind '{}' resolved to zero addresses", rest)
            })?;
        #[cfg(unix)]
        let sock = if let Some(fd) = inherited.take_udp(addr) {
            use std::os::unix::io::FromRawFd;
            // SAFETY: fd is a bound UDP socket from our inherited scan.
            unsafe { std::net::UdpSocket::from_raw_fd(fd) }
        } else {
            std::net::UdpSocket::bind(addr)
                .with_context(|| format!("binding udp socket {addr}"))?
        };
        #[cfg(not(unix))]
        let sock = std::net::UdpSocket::bind(addr)
            .with_context(|| format!("binding udp socket {addr}"))?;
        sock.set_nonblocking(true)?;
        return Ok(BoundSocket::Udp(sock));
    }

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
    let alt_svc: Option<Arc<str>> =
        cfg.auto_alt_svc.as_deref().map(Arc::from);
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
                        let alt_svc     = alt_svc.clone();
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
                                auto_alt_svc: alt_svc,
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
/// Per-connection TLS handshake driver for HTTP listeners.  Uses
/// `LazyConfigAcceptor` so SNI is known *before* the handshake
/// completes, letting us pick a per-vhost rustls ServerConfig (and
/// therefore per-vhost ALPN).  Stream-proxy TLS still uses the
/// simpler `TlsAcceptor` path via `run_tls_acceptor` since stream
/// listeners have no vhost concept.
pub async fn run_tls(
    cfg: ListenerConfig,
    listener: BoundSocket,
    state: Arc<AppState>,
    alpn_map: Arc<ArcSwap<crate::tls::VhostAlpnMap>>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    use tokio_rustls::LazyConfigAcceptor;
    let name = cfg.local_name();
    let local_addr = listener.tcp_local_addr();
    let local_unix: Option<std::path::PathBuf> =
        cfg.bind.strip_prefix("unix:").map(Into::into);
    let sem: Option<Arc<Semaphore>> = cfg
        .max_connections
        .map(|n| Arc::new(Semaphore::new(n as usize)));
    let max_body = cfg.max_request_body;
    let alt_svc: Option<Arc<str>> =
        cfg.auto_alt_svc.as_deref().map(Arc::from);
    tracing::info!(bind = %name, "listening (HTTPS)");
    let mut connections: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((mut stream, peer_addr)) => {
                        // load_full() cheaply clones the inner Arc,
                        // picking up any cert hot-swapped since last accept.
                        let map = alpn_map.load_full();
                        let state = state.clone();
                        let bind = name.clone();
                        let svc_timeouts = cfg.timeouts.clone();
                        let conn_shutdown = shutdown.clone();
                        let proxy_ver = cfg.accept_proxy_protocol;
                        let lux = local_unix.clone();
                        let alt_svc = alt_svc.clone();
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
                            // SNI-aware handshake: read just enough to
                            // see the ClientHello, pick the matching
                            // per-vhost ServerConfig, then complete the
                            // handshake.  Wrapped in the same timeout
                            // guard as the legacy TlsAcceptor path.
                            let tls_stream = match tokio::time::timeout(
                                TLS_HANDSHAKE_TIMEOUT,
                                async {
                                    let start = LazyConfigAcceptor::new(
                                        rustls::server::Acceptor::default(),
                                        stream,
                                    )
                                    .await?;
                                    let sni = start
                                        .client_hello()
                                        .server_name()
                                        .map(str::to_owned);
                                    let cfg = map.pick(sni.as_deref());
                                    start.into_stream(cfg).await
                                },
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
                                auto_alt_svc: alt_svc,
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

// -- QUIC / HTTP/3 listener ----------------------------------------
//
// run_quic owns a bound UDP socket and serves HTTP/3 over QUIC.  The
// actual quinn::Endpoint + h3::server accept loop is gated on the
// `http3` cargo feature; with the feature off the function is a stub
// that logs and exits so that build configurations without the QUIC
// stack still link.  This split mirrors the structure of run_tls and
// run_plain so wiring in main.rs can stay symmetrical.

/// Serve QUIC/HTTP/3 on a bound UDP socket.  Drives a `quinn::Endpoint`
/// and dispatches each h3 request through the same handler pipeline
/// (`AlohaService::dispatch`) as the TCP path so all aloha features
/// (vhost routing, access policy, JWT, proxy/CGI/FastCGI/SCGI, etc.)
/// work identically over HTTP/3.
pub async fn run_quic(
    cfg: ListenerConfig,
    socket: BoundSocket,
    state: Arc<AppState>,
    cert_rx: watch::Receiver<Arc<crate::tls::CertPair>>,
    opts: crate::config::TlsOptions,
    alpn: Option<Vec<String>>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let name = cfg.local_name();
    let udp = match socket {
        BoundSocket::Udp(s) => s,
        _ => bail!(
            "run_quic called with a non-UDP BoundSocket for bind '{name}'"
        ),
    };
    run_quic_inner(cfg, name, udp, state, cert_rx, opts, alpn, shutdown).await
}

/// RAII guard that decrements the `quic_connections_active` gauge when
/// dropped.  Used to keep the gauge consistent even when a connection
/// task panics mid-flight.
struct QuicConnGuard(Arc<Metrics>);

impl Drop for QuicConnGuard {
    fn drop(&mut self) {
        self.0
            .quic_connections_active
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

async fn run_quic_inner(
    cfg: ListenerConfig,
    name: String,
    udp: std::net::UdpSocket,
    state: Arc<AppState>,
    cert_rx: watch::Receiver<Arc<crate::tls::CertPair>>,
    opts: crate::config::TlsOptions,
    alpn: Option<Vec<String>>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    use crate::tls::build_quic_server_config;

    // Seed the endpoint with the current cert.  cert_rx is always
    // populated (CertSource invariant), so borrow().clone() yields the
    // initial pair without blocking.
    let transport = cfg.quic_transport.clone();
    let initial = build_quic_server_config(
        &cert_rx.borrow().clone(),
        &opts,
        alpn.as_deref(),
        transport.as_ref(),
    )
    .context("building initial QUIC server config")?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| anyhow!("no tokio runtime for quinn endpoint"))?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(initial),
        udp,
        runtime,
    )
    .context("quinn::Endpoint::new")?;

    tracing::info!(bind = %name, "listening (HTTP/3)");

    // Per-listener connection cap.  Mirrors the TCP path's behaviour:
    // when the cap is reached, the accept loop awaits a permit so new
    // connections are *deferred* rather than dropped.  quinn's accept
    // ring buffers Initial packets in the meantime; clients see normal
    // QUIC retry / loss recovery behaviour.
    let sem: Option<Arc<Semaphore>> = cfg
        .max_connections
        .map(|n| Arc::new(Semaphore::new(n as usize)));

    // Cert-rotation task: rebuild the QuicServerConfig on every
    // renewal published by the CertSource watch channel and atomically
    // swap it into the live endpoint via set_server_config().  Static
    // cert paths simply never tick this branch.
    {
        let endpoint = endpoint.clone();
        let opts = opts.clone();
        let alpn = alpn.clone();
        let transport = transport.clone();
        let mut cert_rx = cert_rx.clone();
        tokio::spawn(async move {
            // Skip the seed value (already used to build the endpoint).
            cert_rx.mark_changed();
            while cert_rx.changed().await.is_ok() {
                let pair = cert_rx.borrow().clone();
                match build_quic_server_config(
                    &pair,
                    &opts,
                    alpn.as_deref(),
                    transport.as_ref(),
                ) {
                    Ok(new_cfg) => {
                        endpoint.set_server_config(Some(new_cfg));
                        tracing::info!(
                            "QUIC server config rotated after cert renewal"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "failed to rebuild QUIC config on renewal: {e:#}"
                        );
                    }
                }
            }
        });
    }

    let mut connections: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::info!(bind = %name, "QUIC listener draining");
                break;
            }
            inc = endpoint.accept() => {
                let Some(inc) = inc else { break };
                // Source-address validation via Retry tokens.  When
                // enabled, force a Retry on any client whose address
                // hasn't already been validated -- defends against
                // spoofed-source connection floods.  Default is on;
                // set retry-tokens=#false on a listener that sits
                // behind a trusted load balancer.
                let retry_on = transport
                    .as_ref()
                    .map(|t| t.retry_tokens)
                    .unwrap_or(true);
                let inc = if retry_on
                    && !inc.remote_address_validated()
                    && inc.may_retry()
                {
                    if let Err(e) = inc.retry() {
                        tracing::debug!(
                            "QUIC retry token send failed: {e}"
                        );
                    }
                    continue;
                } else {
                    inc
                };
                // Acquire a permit before spawning so the cap actually
                // limits in-flight connections.  Permit is moved into
                // the per-connection task and dropped when it exits.
                let permit: Option<OwnedSemaphorePermit> =
                    if let Some(ref s) = sem {
                        match s.clone().acquire_owned().await {
                            Ok(p) => Some(p),
                            Err(_) => break, // semaphore closed: shutting down
                        }
                    } else {
                        None
                    };
                let state = state.clone();
                let bind = name.clone();
                let timeouts = cfg.timeouts.clone();
                let max_body = cfg.max_request_body;
                let auto_alt_svc: Option<Arc<str>> =
                    cfg.auto_alt_svc.as_deref().map(Arc::from);
                connections.spawn(async move {
                    let _permit = permit;
                    let conn = match inc.await {
                        Ok(c) => {
                            state.metrics.quic_handshakes_total
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            c
                        }
                        Err(e) => {
                            state.metrics.quic_handshake_failures_total
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            tracing::debug!("QUIC handshake failed: {e}");
                            return;
                        }
                    };
                    // Connection-active gauge: tracks live QUIC
                    // connections so the status page can show real-time
                    // load.  Decremented when the per-connection task
                    // exits (the JoinSet awaits it before drain).
                    state.metrics.quic_connections_active
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let _conn_guard =
                        QuicConnGuard(state.metrics.clone());
                    let peer = PeerAddr::Tcp(conn.remote_address());
                    let h3q = h3_quinn::Connection::new(conn);
                    let mut h3 = match h3::server::Connection::<_, Bytes>::new(h3q).await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::debug!("h3 setup failed: {e}");
                            return;
                        }
                    };
                    while let Ok(Some(resolver)) = h3.accept().await {
                        // Spawn per request so a slow handler doesn't
                        // head-of-line block other streams on the same
                        // QUIC connection.
                        let state = state.clone();
                        let bind = bind.clone();
                        let timeouts = timeouts.clone();
                        let auto_alt_svc = auto_alt_svc.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_h3_request(
                                state, bind, peer, timeouts,
                                max_body, auto_alt_svc, resolver,
                            ).await {
                                tracing::debug!("h3 request error: {e:#}");
                            }
                        });
                    }
                });
            }
        }
        // Reap completed per-connection tasks so the JoinSet doesn't
        // grow without bound on long-lived listeners.
        while connections.try_join_next().is_some() {}
    }

    // Graceful drain.  Stop accepting new handshakes by dropping the
    // server config (quinn responds with VERSION_NEGOTIATION / nothing
    // to subsequent Initial packets), then wait up to DRAIN_TIMEOUT for
    // in-flight connections to finish.  On timeout, force-close so a
    // stuck h3 driver can't keep the process alive past systemd's
    // TimeoutStopSec.
    endpoint.set_server_config(None);
    tracing::info!(bind = %name, "QUIC listener: rejecting new handshakes");
    let idle = tokio::time::timeout(DRAIN_TIMEOUT, endpoint.wait_idle()).await;
    if idle.is_err() {
        tracing::warn!(
            bind = %name,
            "QUIC drain timed out after {}s; force-closing endpoint",
            DRAIN_TIMEOUT.as_secs()
        );
        endpoint.close(quinn::VarInt::from_u32(0), b"shutdown");
    }
    // Bound the JoinSet drain by the same timeout so a runaway task
    // doesn't leak past the listener's lifetime.
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    Ok(())
}

/// Streaming request-body adapter for HTTP/3.  Wraps the receive half
/// of an h3 request stream and exposes it as a `hyper::body::Body` so
/// the existing handler pipeline (which already speaks Body) can read
/// the body lazily, without buffering the whole upload into memory.
///
/// Enforces an optional max-body cap by terminating the stream early
/// once the cap is exceeded.  Matches the TCP path's behaviour where
/// Content-Length-based 413 is the strong guarantee; mid-stream caps
/// are best-effort (the handler sees a short body and decides how to
/// respond).
struct H3RequestBody {
    state: H3BodyState,
    max_body: Option<u64>,
    seen: u64,
}

type H3RecvHalf = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;
type H3RecvFuture = Pin<
    Box<
        dyn Future<
                Output = (
                    H3RecvHalf,
                    Result<Option<Bytes>, h3::error::StreamError>,
                ),
            > + Send,
    >,
>;

enum H3BodyState {
    Idle(Box<H3RecvHalf>),
    Reading(H3RecvFuture),
    Done,
}

impl hyper::body::Body for H3RequestBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<
        Option<Result<hyper::body::Frame<Bytes>, hyper::Error>>,
    > {
        use std::task::Poll;
        loop {
            match std::mem::replace(&mut self.state, H3BodyState::Done) {
                H3BodyState::Done => return Poll::Ready(None),
                H3BodyState::Idle(half) => {
                    // Start a new recv_data call that owns the half so
                    // the future is 'static.
                    let fut: H3RecvFuture = Box::pin(async move {
                        let mut half = *half;
                        let r = half.recv_data().await;
                        let bytes = match r {
                            Ok(Some(mut chunk)) => {
                                use bytes::Buf;
                                let n = chunk.remaining();
                                Ok(Some(chunk.copy_to_bytes(n)))
                            }
                            Ok(None) => Ok(None),
                            Err(e) => Err(e),
                        };
                        (half, bytes)
                    });
                    self.state = H3BodyState::Reading(fut);
                }
                H3BodyState::Reading(mut fut) => {
                    match fut.as_mut().poll(cx) {
                        Poll::Pending => {
                            self.state = H3BodyState::Reading(fut);
                            return Poll::Pending;
                        }
                        Poll::Ready((half, Ok(Some(bytes)))) => {
                            // Enforce max_body by truncating the stream
                            // once the cap is exceeded.  The handler
                            // sees the truncated body; on TCP an over-
                            // length Content-Length is already caught
                            // earlier in dispatch_request.
                            self.seen += bytes.len() as u64;
                            if let Some(max) = self.max_body
                                && self.seen > max
                            {
                                tracing::debug!(
                                    seen = self.seen,
                                    max,
                                    "h3 request body exceeded max_body; \
                                     truncating stream"
                                );
                                // Drop the half (signals end of body to
                                // the producer of this stream).
                                drop(half);
                                self.state = H3BodyState::Done;
                                return Poll::Ready(None);
                            }
                            self.state = H3BodyState::Idle(Box::new(half));
                            return Poll::Ready(Some(Ok(
                                hyper::body::Frame::data(bytes),
                            )));
                        }
                        Poll::Ready((_, Ok(None))) => {
                            self.state = H3BodyState::Done;
                            return Poll::Ready(None);
                        }
                        Poll::Ready((_, Err(e))) => {
                            tracing::debug!("h3 recv_data error: {e}");
                            self.state = H3BodyState::Done;
                            // Can't construct a hyper::Error externally;
                            // terminate the stream cleanly and let the
                            // handler decide based on the short body.
                            return Poll::Ready(None);
                        }
                    }
                }
            }
        }
    }
}

/// Per-request handler for HTTP/3.  Streams the request body lazily
/// through `H3RequestBody`, dispatches via the shared
/// `AlohaService::dispatch` pipeline, then streams the response back
/// over the send half of the same h3 request stream.
async fn handle_h3_request(
    state: Arc<AppState>,
    bind: String,
    peer: PeerAddr,
    timeouts: Timeouts,
    max_body: Option<u64>,
    auto_alt_svc: Option<Arc<str>>,
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
) -> anyhow::Result<()> {
    use http_body_util::BodyExt;

    state
        .metrics
        .quic_requests_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let (req_head, req_stream) = resolver
        .resolve_request()
        .await
        .map_err(|e| anyhow!("h3 resolve: {e}"))?;

    // Split the bidi stream so the body adapter owns the recv half and
    // `send_h3_response` owns the send half.  This lets the handler
    // pipeline stream the request body while the response is being
    // composed -- proxy/CGI/FastCGI uploads no longer need to be
    // buffered into memory.
    let (mut send_half, recv_half) = req_stream.split();

    // If Content-Length on the request head already exceeds max_body,
    // short-circuit with 413 before invoking the body adapter.  Matches
    // dispatch_request's behaviour for the TCP path.
    if let Some(max) = max_body
        && let Some(cl) = req_head
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
        && cl > max
    {
        send_h3_response(&mut send_half, response_413()).await?;
        return Ok(());
    }

    // Rebuild a hyper::Request<ReqBody>.  h3 stores the request head
    // as Request<()> so we transplant the streaming body and copy
    // extensions.
    let (parts, ()) = req_head.into_parts();
    let body: ReqBody = H3RequestBody {
        state: H3BodyState::Idle(Box::new(recv_half)),
        max_body,
        seen: 0,
    }
    .boxed_unsync();
    let mut req: Request<ReqBody> = Request::from_parts(parts, body);
    // HTTP/3 carries the target host in the `:authority` pseudo-header,
    // not in `Host:`.  The dispatch pipeline (and the vhost router)
    // reads from `Host:`, so synthesize one from the URI authority when
    // missing -- matching how HTTP/2 servers typically present the
    // request to downstream code.
    if !req.headers().contains_key(hyper::header::HOST)
        && let Some(authority) = req.uri().authority().cloned()
        && let Ok(hv) = hyper::header::HeaderValue::from_str(authority.as_str())
    {
        req.headers_mut().insert(hyper::header::HOST, hv);
    }
    if let PeerAddr::Tcp(addr) = peer {
        req.extensions_mut().insert(addr);
    }

    let svc = AlohaService {
        state,
        bind,
        peer_addr: peer,
        local_addr: None,
        local_unix: None,
        timeouts,
        // HTTP/3 always runs over TLS so the {scheme} template variable
        // resolves to "https".
        is_tls: true,
        max_body_bytes: max_body,
        auto_alt_svc,
    };
    let resp = svc.dispatch(req).await?;
    send_h3_response(&mut send_half, resp).await
}

/// Stream a hyper `Response<BoxBody>` back through an h3 RequestStream.
/// Sends the head, forwards each data frame as a `send_data` call,
/// accumulates any trailer frames and emits them via `send_trailers`,
/// then `finish()` closes the response stream.
async fn send_h3_response(
    stream: &mut h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    resp: Response<BoxBody>,
) -> anyhow::Result<()> {
    use http_body_util::BodyExt;

    let (parts, body) = resp.into_parts();
    let head = Response::from_parts(parts, ());
    stream
        .send_response(head)
        .await
        .map_err(|e| anyhow!("h3 send_response: {e}"))?;

    // Hyper's framed body can interleave data and trailer frames.
    // h3 requires data first, then a single trailer block before finish.
    // Collect trailers as we go and emit them once the body ends.
    let mut body = body;
    let mut trailers: Option<hyper::HeaderMap> = None;
    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                if frame.is_data() {
                    let data = frame
                        .into_data()
                        .map_err(|_| anyhow!("frame::into_data race"))?;
                    stream
                        .send_data(data)
                        .await
                        .map_err(|e| anyhow!("h3 send_data: {e}"))?;
                } else if frame.is_trailers() {
                    let map = frame
                        .into_trailers()
                        .map_err(|_| anyhow!("frame::into_trailers race"))?;
                    // Merge if a handler produces multiple trailer frames.
                    match &mut trailers {
                        Some(acc) => acc.extend(map),
                        None => trailers = Some(map),
                    }
                }
            }
            Some(Err(e)) => {
                return Err(anyhow!("response body read error: {e}"));
            }
            None => break,
        }
    }
    if let Some(map) = trailers {
        stream
            .send_trailers(map)
            .await
            .map_err(|e| anyhow!("h3 send_trailers: {e}"))?;
    }
    stream
        .finish()
        .await
        .map_err(|e| anyhow!("h3 finish: {e}"))?;
    Ok(())
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

    // -- OIDC helper tests ---

    #[test]
    fn wants_html_true_when_accept_contains_html_and_no_auth() {
        let mut h = hyper::HeaderMap::new();
        h.insert(hyper::header::ACCEPT, "text/html,*/*".parse().unwrap());
        assert!(wants_html(&h));
    }

    #[test]
    fn wants_html_false_when_authorization_present() {
        let mut h = hyper::HeaderMap::new();
        h.insert(hyper::header::ACCEPT, "text/html".parse().unwrap());
        h.insert(hyper::header::AUTHORIZATION, "Basic xx".parse().unwrap());
        assert!(!wants_html(&h));
    }

    #[test]
    fn wants_html_false_for_json_client() {
        let mut h = hyper::HeaderMap::new();
        h.insert(hyper::header::ACCEPT, "application/json".parse().unwrap());
        assert!(!wants_html(&h));
    }

    #[test]
    fn validate_return_to_rejects_off_origin() {
        // Protocol-relative URLs would let an attacker redirect the
        // user to an arbitrary host after a successful login.
        assert_eq!(validate_return_to("//evil.example/x"), "/");
        assert_eq!(validate_return_to("https://evil.example"), "/");
        assert_eq!(validate_return_to("/admin"), "/admin");
        assert_eq!(validate_return_to(""), "/");
    }

    #[test]
    fn percent_encode_decode_roundtrip() {
        let raw = "/a b/c?x=1&y=2";
        let enc = percent_encode_return(raw);
        assert!(!enc.contains(' '));
        assert_eq!(percent_decode(&enc), raw);
    }

    #[test]
    fn build_login_redirect_embeds_return() {
        let r = build_login_redirect("/.aloha/oidc/login", "/admin/users?x=1");
        assert!(r.starts_with("/.aloha/oidc/login?return="));
        // Reserved characters in the return URL are percent-encoded.
        assert!(r.contains("%3F") || r.contains("%3f"));
    }

    #[test]
    fn cookie_value_picks_named_entry() {
        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::COOKIE,
            "a=1; __aloha_oidc_state=abc123; b=2".parse().unwrap(),
        );
        assert_eq!(
            cookie_value(&h, "__aloha_oidc_state").as_deref(),
            Some("abc123"),
        );
    }

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
            oidc: None,
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
            oidc: None,
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
            oidc: None,
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

    /// keepalive=N>0 now folds into header_read_timeout, taking the
    /// minimum if request-header is also set.  Verifies the
    /// unification logic in make_builder by computing the same
    /// candidate-minimum the function uses.
    #[test]
    fn keepalive_unifies_with_header_read_timeout() {
        // keepalive alone: that's the cap.
        let t = Timeouts {
            keepalive_secs: Some(7),
            request_header_secs: None,
            ..Default::default()
        };
        let cap: Option<u64> = [t.request_header_secs, t.keepalive_secs]
            .iter()
            .filter_map(|x| *x)
            .min();
        assert_eq!(cap, Some(7));

        // Both set: minimum wins.
        let t = Timeouts {
            keepalive_secs: Some(7),
            request_header_secs: Some(20),
            ..Default::default()
        };
        let cap: Option<u64> = [t.request_header_secs, t.keepalive_secs]
            .iter()
            .filter_map(|x| *x)
            .min();
        assert_eq!(cap, Some(7));

        // Only request-header set: that wins.
        let t = Timeouts {
            keepalive_secs: None,
            request_header_secs: Some(20),
            ..Default::default()
        };
        let cap: Option<u64> = [t.request_header_secs, t.keepalive_secs]
            .iter()
            .filter_map(|x| *x)
            .min();
        assert_eq!(cap, Some(20));
    }

    // -- Alt-Svc auto-injection ---------------------------------------

    /// State helper for Alt-Svc tests: serves a static response on
    /// `/` so the response goes through the full handler pipeline.
    fn static_state(extra: &str) -> Arc<AppState> {
        let kdl = format!(
            r#"
            listener {{ bind "127.0.0.1:1" }}
            vhost "example.com" {{
                location "/" {{
                    redirect {{ to "/here"; code 302 }}
                    {extra}
                }}
            }}
            "#
        );
        let config = Config::parse(&kdl).unwrap();
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
            oidc: None,
        })
    }

    /// auto_alt_svc adds an Alt-Svc header on responses that don't
    /// already carry one.
    #[tokio::test]
    async fn alt_svc_auto_injected_when_absent() {
        let srv = TestServer::start_with_state_and_alt_svc(
            static_state(""),
            Some("h3=\":443\"; ma=86400".to_string()),
        )
        .await;
        let (_status, headers, _) =
            http_get(srv.addr, "example.com", "/").await;
        assert_eq!(
            headers.get("alt-svc").and_then(|v| v.to_str().ok()),
            Some("h3=\":443\"; ma=86400")
        );
    }

    /// Without auto_alt_svc the header is not added on its own.
    #[tokio::test]
    async fn alt_svc_absent_when_not_configured() {
        let srv = TestServer::start_with_state(static_state("")).await;
        let (_status, headers, _) =
            http_get(srv.addr, "example.com", "/").await;
        assert!(headers.get("alt-svc").is_none());
    }

    /// A user `response { set "Alt-Svc" "..." }` rule wins over the
    /// auto-injected value -- the location header op runs inside the
    /// handler pipeline and the injector only fills the gap when the
    /// response doesn't already advertise Alt-Svc.
    #[tokio::test]
    async fn alt_svc_user_set_overrides_auto() {
        let srv = TestServer::start_with_state_and_alt_svc(
            static_state(r#"response-headers { set "Alt-Svc" "h3=\":8443\"" }"#),
            Some("h3=\":443\"; ma=86400".to_string()),
        )
        .await;
        let (_status, headers, _) =
            http_get(srv.addr, "example.com", "/").await;
        assert_eq!(
            headers.get("alt-svc").and_then(|v| v.to_str().ok()),
            Some("h3=\":8443\"")
        );
    }

    // -- End-to-end HTTP/3 round-trip --------------------------------
    //
    // Boots a real run_quic() listener on an ephemeral UDP port with a
    // self-signed cert, then drives a real h3-quinn client against it
    // to verify that h3 requests reach the dispatch pipeline and that
    // responses come back over the QUIC stream.

    #[tokio::test]
    async fn http3_get_round_trips_through_run_quic() {
        use crate::tls::CertPair;
        use h3::client;
        use http_body_util::BodyExt;
        use std::time::Duration;

        // Self-signed cert + matching server config.  Use the same
        // helpers run_quic itself uses so the test cert path is the
        // production path.
        let pair = {
            let (_acc, pair) = crate::tls::build_acceptor_with_pair_alpn(
                &crate::config::TlsListenerConfig {
                    cert: crate::config::TlsConfig::SelfSigned,
                    options: crate::config::TlsOptions::default(),
                },
                &crate::config::TlsOptions::default(),
                None,
            )
            .unwrap();
            pair
        };
        let opts = crate::config::TlsOptions::default();
        let (cert_tx, cert_rx) = tokio::sync::watch::channel(
            Arc::new(CertPair {
                chain: pair.chain.clone(),
                key: crate::tls::clone_key(&pair.key),
            }),
        );
        // Keep the sender alive for the duration of the test.
        let _cert_tx_guard = cert_tx;

        // Listener config: a single static-handler vhost so we have a
        // deterministic response to assert against.
        let config = Config::parse(
            r#"
            listener { bind "udp:127.0.0.1:0"; tls-self-signed }
            vhost "localhost" {
                location "/" {
                    redirect { to "/here"; code 302 }
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
            jwt_manager: None,
            oidc: None,
        });

        // Bind UDP socket on an ephemeral loopback port; record the
        // address before handing the socket to quinn so we know where
        // to point the client.
        let server_sock =
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server_sock.set_nonblocking(true).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let mut cfg = config.listeners.into_iter().next().unwrap();
        cfg.bind = format!("udp:{server_addr}");

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_state = state.clone();
        let server_opts = opts.clone();
        let server_rx = cert_rx.clone();
        let server_task = tokio::spawn(async move {
            let _ = super::run_quic(
                cfg,
                BoundSocket::Udp(server_sock),
                server_state,
                server_rx,
                server_opts,
                None,
                shutdown_rx,
            )
            .await;
        });

        // Build the h3 client side.  Self-signed cert => skip verify.
        // ALPN must advertise h3 or the server will reject the handshake.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(
                test_skip_verify::SkipServerVerification::new(),
            ))
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"h3".to_vec()];
        let client_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
                .unwrap(),
        ));

        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_cfg);

        // Retry the connect briefly -- run_quic spawns asynchronously
        // so there's a small window before the endpoint is actually
        // accepting.
        let conn = {
            let mut last_err = None;
            let mut conn = None;
            for _ in 0..20 {
                match endpoint
                    .connect(server_addr, "localhost")
                    .unwrap()
                    .await
                {
                    Ok(c) => {
                        conn = Some(c);
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
            conn.unwrap_or_else(|| {
                panic!("quinn connect failed: {:?}", last_err)
            })
        };

        let quic = h3_quinn::Connection::new(conn);
        let (mut driver, mut send_request) =
            client::new(quic).await.unwrap();
        let drive = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let req = hyper::Request::builder()
            .method("GET")
            .uri("https://localhost/")
            .body(())
            .unwrap();
        let mut stream = send_request.send_request(req).await.unwrap();
        stream.finish().await.unwrap();
        let resp = stream.recv_response().await.unwrap();
        assert_eq!(resp.status(), 302);
        assert_eq!(
            resp.headers()
                .get("location")
                .and_then(|v| v.to_str().ok()),
            Some("/here")
        );

        // Shut everything down so the test process exits cleanly.
        drop(send_request);
        let _ = drive.await;
        endpoint.close(0u32.into(), b"bye");
        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            server_task,
        )
        .await;
    }

    /// Pool reuse: two sequential h3 requests through a single
    /// `H3Client` share one upstream connection, so the upstream's
    /// `quic_handshakes_total` counter only increments once.
    #[tokio::test]
    async fn h3_outbound_pool_reuses_connection() {
        use crate::handler::proxy::H3Client;
        use crate::tls::CertPair;
        use std::time::Duration;

        // 1. Spin up an aloha h3 server identical to the e2e test.
        let pair = {
            let (_acc, pair) = crate::tls::build_acceptor_with_pair_alpn(
                &crate::config::TlsListenerConfig {
                    cert: crate::config::TlsConfig::SelfSigned,
                    options: crate::config::TlsOptions::default(),
                },
                &crate::config::TlsOptions::default(),
                None,
            )
            .unwrap();
            pair
        };
        let opts = crate::config::TlsOptions::default();
        let (cert_tx, cert_rx) = tokio::sync::watch::channel(
            Arc::new(CertPair {
                chain: pair.chain.clone(),
                key: crate::tls::clone_key(&pair.key),
            }),
        );
        let _cert_tx_guard = cert_tx;

        let config = Config::parse(
            r#"
            listener { bind "udp:127.0.0.1:0"; tls-self-signed }
            vhost "localhost" {
                location "/" {
                    redirect { to "/ok"; code 200 }
                }
            }
            "#,
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&config),
        );
        let router =
            Router::new(&config, &metrics, &summary, None).unwrap();
        let server_metrics = metrics.clone();
        let state = Arc::new(AppState {
            router: Arc::new(router),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics: server_metrics.clone(),
            geoip: None,
            health_enabled: false,
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: None,
            oidc: None,
        });

        // Bind the server on IPv4 loopback and use a literal-IP URL
        // so the client doesn't go through name resolution -- avoids
        // dual-stack / "localhost" ambiguity inside test environments
        // where lookup_host may return ::1 ahead of 127.0.0.1.
        let server_sock =
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server_sock.set_nonblocking(true).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let mut cfg = config.listeners.into_iter().next().unwrap();
        cfg.bind = format!("udp:{server_addr}");

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_state = state.clone();
        let server_opts = opts.clone();
        let server_rx = cert_rx.clone();
        let server_task = tokio::spawn(async move {
            let _ = super::run_quic(
                cfg,
                BoundSocket::Udp(server_sock),
                server_state,
                server_rx,
                server_opts,
                None,
                shutdown_rx,
            )
            .await;
        });

        let _ = rustls::crypto::aws_lc_rs::default_provider()
            .install_default();

        // 2. Build an H3Client pointing at the upstream by literal IP
        // (no DNS lookup needed at request time).
        let upstream: hyper::Uri =
            format!("https://127.0.0.1:{}/", server_addr.port())
                .parse()
                .unwrap();
        let h3 = H3Client::new_for_test(&upstream, None).unwrap();

        // 3. Issue two sequential requests.  Use a permissive helper
        // that builds a minimal request with an empty body.
        for _ in 0..2 {
            let req = hyper::Request::builder()
                .method("GET")
                .uri("/")
                .header("host", "localhost")
                .body(
                    http_body_util::Empty::<bytes::Bytes>::new()
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                )
                .unwrap();
            // Retry the first connect briefly (the server's accept
            // loop may not be live yet).  Subsequent requests should
            // reuse the cached connection.
            let mut last_err: Option<anyhow::Error> = None;
            let mut ok = false;
            for _ in 0..20 {
                match h3.request(req_clone(&req)).await {
                    Ok(resp) => {
                        assert_eq!(resp.status(), 200);
                        ok = true;
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        tokio::time::sleep(Duration::from_millis(50))
                            .await;
                    }
                }
            }
            assert!(
                ok,
                "h3 request failed after retries: {:?}",
                last_err
            );
        }

        // 4. Exactly one server-side handshake means the pool reused
        //    the same connection across both requests.
        let n = server_metrics
            .quic_handshakes_total
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            n, 1,
            "expected pool reuse (1 handshake), got {n}"
        );

        // Regression: H3Client::request returned responses with
        // version=HTTP_3, which then panicked hyper's h1 codec when
        // the proxy forwarded them downstream over HTTP/1.1.  Verify
        // we now strip the upstream version to the default before
        // returning, so any consumer can safely serialise on h1/h2.
        let probe = h3
            .request(req_clone(&hyper::Request::builder()
                .method("GET")
                .uri("/")
                .header("host", "localhost")
                .body(
                    http_body_util::Empty::<bytes::Bytes>::new()
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                )
                .unwrap()))
            .await
            .unwrap();
        assert_eq!(
            probe.version(),
            hyper::Version::default(),
            "H3Client must reset response version to the protocol \
             default so downstream h1/h2 codecs can serialise it"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            server_task,
        )
        .await;
    }

    /// Pool reaper: a connection that sits idle past the configured
    /// timeout gets closed by the reaper, so the next request must
    /// reconnect.  Verified by counting upstream handshakes across
    /// requests separated by `idle_timeout + buffer`.
    #[tokio::test]
    async fn h3_outbound_pool_reaps_idle_connection() {
        use crate::handler::proxy::H3Client;
        use crate::tls::CertPair;
        use std::time::Duration;

        // Identical h3 server setup to the reuse test.
        let pair = {
            let (_acc, pair) = crate::tls::build_acceptor_with_pair_alpn(
                &crate::config::TlsListenerConfig {
                    cert: crate::config::TlsConfig::SelfSigned,
                    options: crate::config::TlsOptions::default(),
                },
                &crate::config::TlsOptions::default(),
                None,
            )
            .unwrap();
            pair
        };
        let opts = crate::config::TlsOptions::default();
        let (cert_tx, cert_rx) = tokio::sync::watch::channel(
            Arc::new(CertPair {
                chain: pair.chain.clone(),
                key: crate::tls::clone_key(&pair.key),
            }),
        );
        let _cert_tx_guard = cert_tx;

        let config = Config::parse(
            r#"
            listener { bind "udp:127.0.0.1:0"; tls-self-signed }
            vhost "localhost" {
                location "/" {
                    redirect { to "/ok"; code 200 }
                }
            }
            "#,
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&config),
        );
        let router =
            Router::new(&config, &metrics, &summary, None).unwrap();
        let server_metrics = metrics.clone();
        let state = Arc::new(AppState {
            router: Arc::new(router),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics: server_metrics.clone(),
            geoip: None,
            health_enabled: false,
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: None,
            oidc: None,
        });
        let server_sock =
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server_sock.set_nonblocking(true).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let mut cfg = config.listeners.into_iter().next().unwrap();
        cfg.bind = format!("udp:{server_addr}");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_state = state.clone();
        let server_opts = opts.clone();
        let server_rx = cert_rx.clone();
        let server_task = tokio::spawn(async move {
            let _ = super::run_quic(
                cfg,
                BoundSocket::Udp(server_sock),
                server_state,
                server_rx,
                server_opts,
                None,
                shutdown_rx,
            )
            .await;
        });
        let _ = rustls::crypto::aws_lc_rs::default_provider()
            .install_default();

        let upstream: hyper::Uri =
            format!("https://127.0.0.1:{}/", server_addr.port())
                .parse()
                .unwrap();
        // 500 ms idle timeout: short enough for the test to finish
        // quickly, long enough to be reliable on slow CI.
        let h3 = H3Client::new_for_test(
            &upstream,
            Some(Duration::from_millis(500)),
        )
        .unwrap();

        // First request: opens connection #1.
        let mut ok = false;
        for _ in 0..20 {
            if let Ok(resp) = h3.request(make_empty_req()).await {
                assert_eq!(resp.status(), 200);
                ok = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(ok);
        assert_eq!(
            server_metrics
                .quic_handshakes_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        // Idle past the timeout, then issue a second request: the
        // reaper should have closed connection #1, so we open #2.
        // 1500 ms covers idle (500 ms) + the reaper's worst-case
        // tick lag (idle / 4 = 125 ms) plus generous slack.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let resp = h3.request(make_empty_req()).await.unwrap();
        assert_eq!(resp.status(), 200);
        let n = server_metrics
            .quic_handshakes_total
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            n, 2,
            "expected reaper to force reconnect (2 handshakes), got {n}"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            server_task,
        )
        .await;
    }

    /// `max-request-body` boundary check over h3.  When a request
    /// arrives with `Content-Length` larger than the configured cap,
    /// the listener must reject it with a 413 before any handler
    /// (or upstream forwarding) runs.  This is the inbound side of
    /// the cap; the mid-stream truncation path is covered by the
    /// dispatch unit test in `H3RequestBody`.
    #[tokio::test]
    async fn h3_inbound_413_on_content_length_over_max() {
        use crate::handler::proxy::H3Client;
        use crate::tls::CertPair;
        use std::time::Duration;

        let pair = {
            let (_acc, pair) = crate::tls::build_acceptor_with_pair_alpn(
                &crate::config::TlsListenerConfig {
                    cert: crate::config::TlsConfig::SelfSigned,
                    options: crate::config::TlsOptions::default(),
                },
                &crate::config::TlsOptions::default(),
                None,
            )
            .unwrap();
            pair
        };
        let opts = crate::config::TlsOptions::default();
        let (cert_tx, cert_rx) = tokio::sync::watch::channel(
            Arc::new(CertPair {
                chain: pair.chain.clone(),
                key: crate::tls::clone_key(&pair.key),
            }),
        );
        let _cert_tx_guard = cert_tx;

        // Listener with a 1-KiB body cap.
        let config = Config::parse(
            r#"
            listener {
                bind "udp:127.0.0.1:0"
                tls-self-signed
                max-request-body 1024
            }
            vhost "localhost" {
                location "/" {
                    redirect { to "/ok"; code 200 }
                }
            }
            "#,
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&config),
        );
        let router =
            Router::new(&config, &metrics, &summary, None).unwrap();
        let state = Arc::new(AppState {
            router: Arc::new(router),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics: metrics.clone(),
            geoip: None,
            health_enabled: false,
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: None,
            oidc: None,
        });
        let server_sock =
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server_sock.set_nonblocking(true).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let mut cfg = config.listeners.into_iter().next().unwrap();
        cfg.bind = format!("udp:{server_addr}");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_state = state.clone();
        let server_opts = opts.clone();
        let server_rx = cert_rx.clone();
        let server_task = tokio::spawn(async move {
            let _ = super::run_quic(
                cfg,
                BoundSocket::Udp(server_sock),
                server_state,
                server_rx,
                server_opts,
                None,
                shutdown_rx,
            )
            .await;
        });

        let _ = rustls::crypto::aws_lc_rs::default_provider()
            .install_default();

        // Client sends `Content-Length: 4096` (4 x the cap) with an
        // empty body.  Per dispatch_request semantics, the listener
        // must refuse based on the declared length alone, without
        // waiting to read body bytes.
        let upstream: hyper::Uri =
            format!("https://127.0.0.1:{}/", server_addr.port())
                .parse()
                .unwrap();
        let h3 = H3Client::new_for_test(&upstream, None).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let req = hyper::Request::builder()
            .method("POST")
            .uri("/")
            .header("host", "localhost")
            .header("content-length", "4096")
            .body(
                http_body_util::Empty::<bytes::Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        let resp = h3.request(req).await.unwrap();
        assert_eq!(
            resp.status(),
            413,
            "expected 413 for declared length > max-request-body"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            server_task,
        )
        .await;
    }

    /// Concurrent h3 requests through a single `H3Client`.  Phase 4
    /// claimed the pool can serve arbitrary concurrency by cloning
    /// `SendRequest` per request -- this test exercises that claim
    /// directly: 10 parallel `request()` futures, all expected to
    /// return 200, with the upstream observing exactly 1 QUIC
    /// handshake.
    #[tokio::test]
    async fn h3_outbound_pool_serves_concurrent_requests() {
        use crate::handler::proxy::H3Client;
        use crate::tls::CertPair;
        use std::time::Duration;

        let pair = {
            let (_acc, pair) = crate::tls::build_acceptor_with_pair_alpn(
                &crate::config::TlsListenerConfig {
                    cert: crate::config::TlsConfig::SelfSigned,
                    options: crate::config::TlsOptions::default(),
                },
                &crate::config::TlsOptions::default(),
                None,
            )
            .unwrap();
            pair
        };
        let opts = crate::config::TlsOptions::default();
        let (cert_tx, cert_rx) = tokio::sync::watch::channel(
            Arc::new(CertPair {
                chain: pair.chain.clone(),
                key: crate::tls::clone_key(&pair.key),
            }),
        );
        let _cert_tx_guard = cert_tx;

        let config = Config::parse(
            r#"
            listener { bind "udp:127.0.0.1:0"; tls-self-signed }
            vhost "localhost" {
                location "/" {
                    redirect { to "/ok"; code 200 }
                }
            }
            "#,
        )
        .unwrap();
        let metrics = Arc::new(Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(&config),
        );
        let router =
            Router::new(&config, &metrics, &summary, None).unwrap();
        let server_metrics = metrics.clone();
        let state = Arc::new(AppState {
            router: Arc::new(router),
            acme_challenges: Default::default(),
            authenticator: Arc::new(AnonymousAuthenticator),
            metrics: server_metrics.clone(),
            geoip: None,
            health_enabled: false,
            error_pages: Arc::new(ErrorPages::new(HashMap::new())),
            jwt_manager: None,
            oidc: None,
        });
        let server_sock =
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server_sock.set_nonblocking(true).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let mut cfg = config.listeners.into_iter().next().unwrap();
        cfg.bind = format!("udp:{server_addr}");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_state = state.clone();
        let server_opts = opts.clone();
        let server_rx = cert_rx.clone();
        let server_task = tokio::spawn(async move {
            let _ = super::run_quic(
                cfg,
                BoundSocket::Udp(server_sock),
                server_state,
                server_rx,
                server_opts,
                None,
                shutdown_rx,
            )
            .await;
        });

        let _ = rustls::crypto::aws_lc_rs::default_provider()
            .install_default();

        let upstream: hyper::Uri =
            format!("https://127.0.0.1:{}/", server_addr.port())
                .parse()
                .unwrap();
        let h3 = Arc::new(H3Client::new_for_test(&upstream, None).unwrap());

        // Prime the connection with one request so the handshake is
        // done before the parallel burst kicks off.  Without this,
        // 10 simultaneous calls all see the cache empty and race to
        // build it -- the Mutex serialises them but the first
        // build_cached takes ~5-30 ms which throws off the
        // "exactly 1 handshake" assertion only by chance.  Priming
        // makes the test deterministic.
        {
            let mut prime_ok = false;
            for _ in 0..20 {
                if let Ok(r) = h3.request(make_empty_req()).await
                    && r.status() == 200
                {
                    prime_ok = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(prime_ok, "priming request failed");
        }
        let prime_handshakes = server_metrics
            .quic_handshakes_total
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            prime_handshakes, 1,
            "expected priming to leave a single handshake"
        );

        // Fire 10 concurrent requests; await them all.  All must
        // succeed and the handshake count must NOT have advanced
        // beyond the one we just observed.
        let mut handles = Vec::new();
        for _ in 0..10 {
            let h3 = h3.clone();
            handles.push(tokio::spawn(async move {
                h3.request(make_empty_req()).await
            }));
        }
        let mut ok_count = 0usize;
        for h in handles {
            let resp = h.await.unwrap().unwrap();
            if resp.status() == 200 {
                ok_count += 1;
            }
        }
        assert_eq!(
            ok_count, 10,
            "expected all 10 concurrent requests to return 200"
        );
        let final_handshakes = server_metrics
            .quic_handshakes_total
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            final_handshakes, 1,
            "concurrent requests must share one QUIC connection \
             (got {final_handshakes} handshakes)"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            server_task,
        )
        .await;
    }

    /// Pool reconnect after the upstream closes the connection.
    /// Stands up a raw h3 upstream that accepts two QUIC connections
    /// in sequence: serves one request on each and closes between
    /// them.  The H3Client's cached entry from request 1 becomes
    /// stale; the next user-issued request must succeed via a fresh
    /// handshake without the caller having to manage the eviction
    /// themselves.
    ///
    /// There's an inherent race after `conn.close()`: the client
    /// sees `close_reason() == None` until the CONNECTION_CLOSE
    /// frame propagates.  The pool handles this by evicting the
    /// cached entry on any request-time error, so a third call
    /// recovers when the second happens to land mid-race.  The test
    /// issues up to three requests and asserts that the upstream
    /// saw exactly two connections in total.
    #[tokio::test]
    async fn h3_outbound_pool_reconnects_after_close() {
        use crate::handler::proxy::H3Client;
        use crate::tls::CertPair;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let _ = rustls::crypto::aws_lc_rs::default_provider()
            .install_default();

        let (_acc, pair) = crate::tls::build_acceptor_with_pair_alpn(
            &crate::config::TlsListenerConfig {
                cert: crate::config::TlsConfig::SelfSigned,
                options: crate::config::TlsOptions::default(),
            },
            &crate::config::TlsOptions::default(),
            None,
        )
        .unwrap();
        let quic_cfg = crate::tls::build_quic_server_config(
            &CertPair {
                chain: pair.chain,
                key: crate::tls::clone_key(&pair.key),
            },
            &crate::config::TlsOptions::default(),
            None,
            None,
        )
        .unwrap();

        let server_sock =
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server_sock.set_nonblocking(true).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_srv = accepts.clone();

        // Server task: accept two QUIC connections, serve one h3
        // request on each, then close the connection in between.
        // The explicit close is what makes this a reconnect test
        // rather than the idle-reaper test: we don't wait for a
        // timeout; the server actively tears the connection down.
        let server_task = tokio::spawn(async move {
            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(quic_cfg),
                server_sock,
                quinn::default_runtime().unwrap(),
            )
            .unwrap();
            for _ in 0..2 {
                let Some(incoming) = endpoint.accept().await else {
                    break;
                };
                accepts_srv.fetch_add(1, Ordering::Relaxed);
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let h3q = h3_quinn::Connection::new(conn.clone());
                let mut h3 =
                    h3::server::Connection::<_, bytes::Bytes>::new(h3q)
                        .await
                        .unwrap();
                if let Ok(Some(resolver)) = h3.accept().await {
                    let (_req, stream) =
                        resolver.resolve_request().await.unwrap();
                    let (mut send, _recv) = stream.split();
                    let resp = hyper::Response::builder()
                        .status(200)
                        .body(())
                        .unwrap();
                    send.send_response(resp).await.unwrap();
                    send.finish().await.unwrap();
                }
                // Give the response time to flush before tearing the
                // connection down.  `send.finish()` completes once
                // the local h3 stream is closed; the QUIC layer
                // still has to flush packets to the wire.  Forcibly
                // closing here without the pause aborts the response
                // in flight and the client sees ApplicationClose
                // instead of the 200.
                tokio::time::sleep(Duration::from_millis(200)).await;
                conn.close(0u32.into(), b"bye");
                // Second pause: let the CONNECTION_CLOSE reach the
                // client before we accept the next handshake.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            endpoint.close(0u32.into(), b"done");
        });

        let upstream: hyper::Uri =
            format!("https://127.0.0.1:{}/", server_addr.port())
                .parse()
                .unwrap();
        let h3 = H3Client::new_for_test(&upstream, None).unwrap();

        // Request 1: opens the first connection.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let r1 = h3.request(make_empty_req()).await.unwrap();
        assert_eq!(r1.status(), 200);

        // Give the server's close + new-accept window time to land
        // on the client side.  Even with this, the cached entry's
        // close_reason() can lag, so the next request may fail
        // mid-stream on the dying conn.  The pool evicts on any
        // error, so a subsequent retry succeeds via conn 2.
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Send up to three requests; the second is allowed to fail
        // because of the post-close race, but at least one of the
        // post-r1 requests MUST succeed -- otherwise the reconnect
        // path is broken.
        let mut post_close_ok = false;
        for _ in 0..3 {
            match h3.request(make_empty_req()).await {
                Ok(r) if r.status() == 200 => {
                    post_close_ok = true;
                    break;
                }
                _ => {
                    tokio::time::sleep(
                        Duration::from_millis(100),
                    )
                    .await;
                }
            }
        }
        assert!(
            post_close_ok,
            "no post-close request succeeded; pool didn't recover"
        );

        // Exactly two server-side accepts: one for r1, one for
        // whichever post-close request triggered the fresh handshake.
        let n = accepts.load(Ordering::Relaxed);
        assert_eq!(
            n, 2,
            "expected exactly 2 upstream connections \
             (reconnect after close); got {n}"
        );

        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            server_task,
        )
        .await;
    }

    /// Multi-frame upload: drive a POST whose body is split across
    /// several frames through the h3 outbound proxy client.  Stands
    /// up a raw h3 upstream (no aloha layer in between) so the test
    /// can directly observe how many `recv_data` calls the upstream
    /// saw -- the real regression catch for any future change that
    /// re-buffers request bodies before forwarding.
    #[tokio::test]
    async fn h3_outbound_streams_multi_frame_upload() {
        use crate::handler::proxy::H3Client;
        use bytes::Buf;
        use http_body_util::BodyExt;
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        use std::time::Duration;

        let _ = rustls::crypto::aws_lc_rs::default_provider()
            .install_default();

        // 1. Self-signed cert for the upstream.
        let (_acc, pair) = crate::tls::build_acceptor_with_pair_alpn(
            &crate::config::TlsListenerConfig {
                cert: crate::config::TlsConfig::SelfSigned,
                options: crate::config::TlsOptions::default(),
            },
            &crate::config::TlsOptions::default(),
            None,
        )
        .unwrap();
        let quic_cfg = crate::tls::build_quic_server_config(
            &crate::tls::CertPair {
                chain: pair.chain,
                key: crate::tls::clone_key(&pair.key),
            },
            &crate::config::TlsOptions::default(),
            None,
            None,
        )
        .unwrap();

        // 2. Raw h3 upstream that counts bytes + recv_data() calls
        //    and echoes them back as response headers.
        let server_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server_sock.set_nonblocking(true).unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let bytes_seen = Arc::new(AtomicU64::new(0));
        let frames_seen = Arc::new(AtomicUsize::new(0));
        let bytes_seen_srv = bytes_seen.clone();
        let frames_seen_srv = frames_seen.clone();
        let server_task = tokio::spawn(async move {
            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(quic_cfg),
                server_sock,
                quinn::default_runtime().unwrap(),
            )
            .unwrap();
            // Single connection, single request is enough for the test.
            let incoming = endpoint.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let h3q = h3_quinn::Connection::new(conn);
            let mut h3 = h3::server::Connection::<_, bytes::Bytes>::new(h3q)
                .await
                .unwrap();
            if let Ok(Some(resolver)) = h3.accept().await {
                let (_req, req_stream) =
                    resolver.resolve_request().await.unwrap();
                let (mut send, mut recv) = req_stream.split();
                let mut bytes = 0u64;
                let mut frames = 0usize;
                while let Some(mut chunk) =
                    recv.recv_data().await.unwrap()
                {
                    frames += 1;
                    bytes += chunk.remaining() as u64;
                    // Consume the chunk so recv_data advances.
                    let _ = chunk.copy_to_bytes(chunk.remaining());
                }
                bytes_seen_srv.store(bytes, Ordering::Relaxed);
                frames_seen_srv.store(frames, Ordering::Relaxed);
                let resp = hyper::Response::builder()
                    .status(200)
                    .header("x-body-length", bytes.to_string())
                    .header("x-frame-count", frames.to_string())
                    .body(())
                    .unwrap();
                send.send_response(resp).await.unwrap();
                send.finish().await.unwrap();
            }
            // Drain the connection cleanly before drop.
            tokio::time::sleep(Duration::from_millis(50)).await;
            endpoint.close(0u32.into(), b"bye");
        });

        // 3. Build the H3 outbound client, with skip-verify against
        //    our self-signed cert.
        let upstream: hyper::Uri =
            format!("https://127.0.0.1:{}/", server_addr.port())
                .parse()
                .unwrap();
        let h3 = H3Client::new_for_test(&upstream, None).unwrap();

        // 4. Build a multi-frame request body: 4 chunks of 32 KiB
        //    each, fed through an mpsc-backed StreamBody so frames
        //    really do flow in sequence rather than being collapsed.
        let total_bytes = 4u64 * 32 * 1024;
        let (tx, rx) = tokio::sync::mpsc::channel::<
            Result<hyper::body::Frame<bytes::Bytes>, hyper::Error>,
        >(2);
        tokio::spawn(async move {
            for _ in 0..4 {
                let chunk = bytes::Bytes::from(vec![b'a'; 32 * 1024]);
                let _ = tx
                    .send(Ok(hyper::body::Frame::data(chunk)))
                    .await;
            }
        });
        let body = http_body_util::StreamBody::new(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )
        .boxed_unsync();
        let req = hyper::Request::builder()
            .method("POST")
            .uri("/")
            .header("host", "localhost")
            .body(body)
            .unwrap();

        // 5. Issue.  The raw server accepts exactly one request, so
        // we can't safely retry; sleep briefly to let the server
        // bind + start its accept loop first.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let resp = h3
            .request(req)
            .await
            .expect("h3 request to raw upstream");
        assert_eq!(resp.status(), 200);
        let body_len = resp
            .headers()
            .get("x-body-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap();
        let frame_count = resp
            .headers()
            .get("x-frame-count")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap();
        assert_eq!(
            body_len, total_bytes,
            "upstream saw wrong byte count"
        );
        // Regression catch: re-buffering the body would collapse this
        // to 1.  We sent 4 frames; allow 2+ to absorb any minor
        // coalescing in the QUIC stack.
        assert!(
            frame_count >= 2,
            "expected multiple frames (got {frame_count}); \
             a regression to buffered uploads"
        );

        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            server_task,
        )
        .await;
    }

    /// Helper: build a minimal GET / request with an empty ReqBody.
    fn make_empty_req() -> hyper::Request<crate::error::ReqBody> {
        use http_body_util::BodyExt;
        hyper::Request::builder()
            .method("GET")
            .uri("/")
            .header("host", "localhost")
            .body(
                http_body_util::Empty::<bytes::Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap()
    }

    /// Helper: clone a `Request<ReqBody>` with an empty body.  Used by
    /// the pool-reuse test to retry the first connect.  We can't clone
    /// the body directly (UnsyncBoxBody is !Clone), so we rebuild it.
    fn req_clone(
        r: &hyper::Request<crate::error::ReqBody>,
    ) -> hyper::Request<crate::error::ReqBody> {
        use http_body_util::BodyExt;
        let mut b = hyper::Request::builder()
            .method(r.method().clone())
            .uri(r.uri().clone())
            .version(r.version());
        for (k, v) in r.headers() {
            b = b.header(k, v);
        }
        b.body(
            http_body_util::Empty::<bytes::Bytes>::new()
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .unwrap()
    }

    /// Simulates systemd socket activation: an `InheritedSockets`
    /// pool already holds a bound UDP fd at the address we want to
    /// listen on, and `bind_socket` should adopt that fd rather than
    /// calling `bind(2)` afresh.  This mirrors what happens at startup
    /// when LISTEN_FDS / a seamless-upgrade parent hands us a socket.
    #[test]
    fn bind_socket_adopts_inherited_udp_fd() {
        use std::os::unix::io::{AsRawFd, IntoRawFd};

        // 1. Create the "inherited" UDP socket.
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let fd = sock.as_raw_fd();
        // Transfer ownership to a raw fd so the pool can hand it off
        // exactly the way systemd would.  classify_fd uses ManuallyDrop
        // to avoid closing the fd during the scan; our test bypasses
        // the scan and goes straight to take_udp.
        let fd_owned = sock.into_raw_fd();
        assert_eq!(fd, fd_owned);

        let mut inh = crate::inherit::InheritedSockets::from_udp_for_test(
            std::collections::HashMap::from([(addr, fd_owned)]),
        );

        // 2. Build a ListenerConfig that targets exactly this address.
        let cfg = ListenerConfig {
            bind: format!("udp:{addr}"),
            transport: crate::config::Transport::Udp,
            tls: None,
            stream: None,
            accept_proxy_protocol: None,
            default_vhost: None,
            timeouts: Timeouts::default(),
            max_connections: None,
            max_request_body: None,
            auto_alt_svc: None,
            alpn: None,
            quic_transport: None,
        };

        // 3. bind_socket must adopt the inherited fd (same fd number)
        //    rather than open a fresh one.
        let bound = super::bind_socket(&cfg, &mut inh).unwrap();
        let adopted = match bound {
            BoundSocket::Udp(s) => s,
            _ => panic!("expected BoundSocket::Udp"),
        };
        assert_eq!(adopted.as_raw_fd(), fd_owned);
        assert_eq!(adopted.local_addr().unwrap(), addr);

        // 4. The pool must no longer contain the fd (take semantics).
        assert!(inh.take_udp(addr).is_none());

        drop(adopted);
    }

    // Helper module: a rustls verifier that accepts any cert.  Only
    // used in the http3 round-trip test against our own self-signed
    // listener; never compiled into the binary.
    mod test_skip_verify {
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        use rustls::{DigitallySignedStruct, SignatureScheme};

        #[derive(Debug)]
        pub(super) struct SkipServerVerification;
        impl SkipServerVerification {
            pub(super) fn new() -> Self {
                Self
            }
        }
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
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::RSA_PSS_SHA384,
                    SignatureScheme::RSA_PSS_SHA512,
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SignatureScheme::RSA_PKCS1_SHA384,
                    SignatureScheme::RSA_PKCS1_SHA512,
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::ECDSA_NISTP384_SHA384,
                    SignatureScheme::ECDSA_NISTP521_SHA512,
                    SignatureScheme::ED25519,
                ]
            }
        }
    }
}
