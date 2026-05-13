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
use http_body_util::{BodyExt, combinators::BoxBody};
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
type UpstreamBody = BoxBody<bytes::Bytes, hyper::Error>;

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

// Client variants: one for TCP (http/https) and one for Unix sockets.
#[allow(clippy::large_enum_variant)]
enum ProxyClient {
    Http(Client<HttpsConnector<HttpConnector>, UpstreamBody>),
    #[cfg(unix)]
    Unix(Client<UnixConnector, UpstreamBody>),
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
}

impl ProxyHandler {
    pub fn new(
        upstream_str: &str,
        strip_prefix: bool,
        proxy_protocol: Option<ProxyProtocolVersion>,
    ) -> anyhow::Result<Self> {
        // Unix domain socket upstream: "unix:/path/to/socket"
        #[cfg(unix)]
        if let Some(path) = upstream_str.strip_prefix("unix:") {
            let connector = UnixConnector { path: path.into() };
            let client = Client::builder(TokioExecutor::new()).build(connector);
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
        // HttpsConnector handles both http:// and https:// upstreams.
        // Mozilla WebPKI roots are bundled; no OS cert store dependency.
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self {
            client: ProxyClient::Http(client),
            upstream,
            strip_prefix,
            proxy_protocol,
            #[cfg(unix)]
            unix_path: None,
        })
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

        let result = match &self.client {
            ProxyClient::Http(c) => c.request(backend_req).await,
            #[cfg(unix)]
            ProxyClient::Unix(c) => c.request(backend_req).await,
        };
        match result {
            Ok(resp) => convert_response(resp),
            Err(e) => {
                tracing::error!("proxy: backend request failed: {e}");
                response_502()
            }
        }
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
        parts.version = Version::HTTP_11;
        if let Some(authority) = self.upstream.authority()
            && let Ok(v) = HeaderValue::from_str(authority.as_str())
        {
            parts.headers.insert(hyper::header::HOST, v);
        }
        Ok(Request::from_parts(parts, body.map_err(|e| e).boxed()))
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
        assert!(ProxyHandler::new("http://backend:8080", false, None).is_ok());
    }

    #[test]
    fn new_accepts_https_upstream() {
        assert!(
            ProxyHandler::new("https://backend:8443", false, None).is_ok(),
            "https upstream should be accepted"
        );
    }

    #[cfg(unix)]
    #[test]
    fn new_accepts_unix_upstream() {
        let h = ProxyHandler::new("unix:/run/app.sock", false, None);
        assert!(h.is_ok(), "unix: upstream should be accepted on unix");
        // The internal URI collapses to localhost so that Host header
        // is a sensible value for the backend.
        let h = h.unwrap();
        assert_eq!(h.upstream.host(), Some("localhost"));
    }

    #[cfg(unix)]
    #[test]
    fn new_unix_upstream_uses_http_localhost_uri() {
        let h = ProxyHandler::new("unix:/run/app.sock", false, None).unwrap();
        assert_eq!(h.upstream.scheme_str(), Some("http"));
    }

    #[test]
    fn new_rejects_invalid_scheme() {
        assert!(ProxyHandler::new("ftp://backend", false, None).is_err());
    }

    #[test]
    fn new_rejects_missing_host() {
        assert!(ProxyHandler::new("http:///path", false, None).is_err());
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
            Some(ProxyProtocolVersion::V2),
        );
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
                                let req = req.map(|b| b.boxed());
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
                                let req = req.map(|b| b.boxed());
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
}
