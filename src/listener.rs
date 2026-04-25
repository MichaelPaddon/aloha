use crate::acme::ChallengeMap;
use crate::config::{ListenerConfig, Timeouts};
use crate::error::{bytes_body, response_404, BoxBody};
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
use tokio_rustls::TlsAcceptor;
use tracing::debug;

pub struct AppState {
    pub router: Arc<Router>,
    // ACME HTTP-01 challenge tokens served at
    // /.well-known/acme-challenge/{token}.  Populated by AcmeManager
    // during certificate issuance; empty otherwise.
    pub acme_challenges: ChallengeMap,
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

    fn call(&self, req: Request<Incoming>) -> Self::Future {
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
                        route
                            .handler
                            .serve(&req, &route.matched_prefix)
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
) -> anyhow::Result<()> {
    let name = cfg.local_name();
    tracing::info!(bind = %name, "listening (HTTP)");
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let svc = AlohaService {
            state: state.clone(),
            bind: name.clone(),
            peer_addr,
            timeouts: cfg.timeouts.clone(),
        };
        tokio::spawn(async move {
            debug!(%peer_addr, "accepted connection");
            let builder = make_builder(&svc.timeouts);
            if let Err(e) = builder.serve_connection(io, svc).await {
                debug!(%peer_addr, "connection closed: {e}");
            }
        });
    }
}

// Acceptor is pre-built by main (possibly via AcmeManager) and passed
// in as an ArcSwap so that live cert rotation works without restart.
pub async fn run_tls(
    cfg: ListenerConfig,
    listener: TcpListener,
    state: Arc<AppState>,
    acceptor: Arc<ArcSwap<TlsAcceptor>>,
) -> anyhow::Result<()> {
    let name = cfg.local_name();
    tracing::info!(bind = %name, "listening (HTTPS)");
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        // load_full() cheaply clones the inner Arc for this connection,
        // picking up any cert that was hot-swapped since the last accept.
        let acc = acceptor.load_full();
        let state = state.clone();
        let bind = name.clone();
        let svc_timeouts = cfg.timeouts.clone();
        tokio::spawn(async move {
            // Complete the TLS handshake inside the task so a slow
            // or failing client does not block the accept loop.
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
            let builder = make_builder(&svc.timeouts);
            if let Err(e) = builder.serve_connection(io, svc).await {
                debug!(%peer_addr, "TLS connection closed: {e}");
            }
        });
    }
}
