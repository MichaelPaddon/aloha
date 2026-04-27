use crate::error::{response_502, HttpResponse};
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, Uri, Version};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::io;
use std::net::SocketAddr;

// Body type used for requests sent to the upstream.
type UpstreamBody = BoxBody<bytes::Bytes, hyper::Error>;

// Hop-by-hop headers that must not be forwarded (RFC 7230 §6.1).
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
    client: Client<HttpsConnector<HttpConnector>, UpstreamBody>,
    upstream: Uri,
    strip_prefix: bool,
}

impl ProxyHandler {
    pub fn new(upstream: &str, strip_prefix: bool) -> anyhow::Result<Self> {
        let upstream: Uri = upstream
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid upstream URL: {upstream}"))?;
        match upstream.scheme_str() {
            Some("http") | Some("https") => {}
            _ => anyhow::bail!(
                "upstream '{upstream}' must use http or https scheme"
            ),
        }
        if upstream.authority().is_none() {
            anyhow::bail!("upstream '{upstream}' must include a host");
        }
        // HttpsConnector handles both http:// and https:// upstreams.
        // Mozilla WebPKI roots are bundled; no OS cert store dependency.
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self { client, upstream, strip_prefix })
    }

    pub async fn serve(
        &self,
        req: Request<Incoming>,
        matched_prefix: &str,
    ) -> HttpResponse {
        let peer_ip = req
            .extensions()
            .get::<SocketAddr>()
            .map(|a| a.ip().to_string());

        let backend_uri = match build_backend_uri(
            &self.upstream,
            req.uri(),
            matched_prefix,
            self.strip_prefix,
        ) {
            Ok(u) => u,
            Err(e) => {
                tracing::error!("proxy: failed to build backend URI: {e}");
                return response_502();
            }
        };

        let (mut parts, body) = req.into_parts();

        // Remove hop-by-hop headers before forwarding (also strips any
        // headers listed in the Connection header value itself).
        strip_hop_by_hop(&mut parts.headers);

        // Set forwarding headers.
        set_forwarding_headers(&mut parts.headers, peer_ip.as_deref());

        // Rewrite URI and force HTTP/1.1 for the backend connection.
        parts.uri = backend_uri;
        parts.version = Version::HTTP_11;

        // Set Host to the upstream authority.
        if let Some(authority) = self.upstream.authority() {
            if let Ok(v) = HeaderValue::from_str(authority.as_str()) {
                parts.headers.insert(hyper::header::HOST, v);
            }
        }

        let backend_req =
            Request::from_parts(parts, body.map_err(|e| {
                // Map hyper::Error to the upstream body error type.
                // This is a no-op in practice since Incoming already
                // uses hyper::Error as its error type.
                e
            }).boxed());

        match self.client.request(backend_req).await {
            Ok(resp) => convert_response(resp),
            Err(e) => {
                tracing::error!("proxy: backend request failed: {e}");
                response_502()
            }
        }
    }
}

// ── URI rewriting ─────────────────────────────────────────────────

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

// ── Header handling ───────────────────────────────────────────────

// Remove all hop-by-hop headers from a header map, including any
// headers listed in the Connection header value itself.
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

// ── Response conversion ───────────────────────────────────────────

fn convert_response(resp: Response<Incoming>) -> HttpResponse {
    let (mut parts, body) = resp.into_parts();

    // Strip hop-by-hop headers from the backend response too.
    strip_hop_by_hop(&mut parts.headers);

    let boxed = body
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        .boxed();

    Response::from_parts(parts, boxed)
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    // ── ProxyHandler::new scheme validation ──────────────────────

    #[test]
    fn new_accepts_http_upstream() {
        assert!(ProxyHandler::new("http://backend:8080", false).is_ok());
    }

    #[test]
    fn new_accepts_https_upstream() {
        assert!(
            ProxyHandler::new("https://backend:8443", false).is_ok(),
            "https upstream should be accepted"
        );
    }

    #[test]
    fn new_rejects_invalid_scheme() {
        assert!(ProxyHandler::new("ftp://backend", false).is_err());
    }

    #[test]
    fn new_rejects_missing_host() {
        assert!(ProxyHandler::new("http:///path", false).is_err());
    }

    // ── build_backend_uri ─────────────────────────────────────────

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
        let u = build_backend_uri(
            &uri("http://backend"),
            &uri("/foo"),
            "/",
            false,
        )
        .unwrap();
        assert_eq!(u.to_string(), "http://backend/foo");
        assert!(u.query().is_none());
    }

    // ── strip_hop_by_hop ─────────────────────────────────────────

    #[test]
    fn strip_hop_by_hop_removes_standard_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("keep-alive"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
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

    // ── X-Forwarded-For ──────────────────────────────────────────

    #[test]
    fn x_forwarded_for_set_when_absent() {
        let mut headers = HeaderMap::new();
        set_forwarding_headers(&mut headers, Some("1.2.3.4"));
        assert_eq!(
            headers.get("x-forwarded-for").unwrap(),
            "1.2.3.4"
        );
        assert_eq!(headers.get("x-real-ip").unwrap(), "1.2.3.4");
    }

    #[test]
    fn x_forwarded_for_appends_to_existing() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("10.0.0.1"),
        );
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
}
