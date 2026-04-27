use bytes::Bytes;
use http_body_util::{combinators::BoxBody as ErasedBody, BodyExt, Full};
use hyper::{Response, StatusCode};
use std::convert::Infallible;

// Type-erased response body shared by all handlers.  Using a single
// concrete body type lets the static handler stream files without
// buffering while keeping error responses as simple in-memory buffers.
pub type BoxBody = ErasedBody<Bytes, std::io::Error>;
pub type HttpResponse = Response<BoxBody>;

// Wrap an owned or static byte buffer in the common body type.
pub fn bytes_body(b: impl Into<Bytes>) -> BoxBody {
    Full::new(b.into())
        .map_err(|_: Infallible| unreachable!())
        .boxed()
}

fn html_response(
    status: StatusCode,
    body: &'static str,
) -> HttpResponse {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(bytes_body(Bytes::from_static(body.as_bytes())))
        .expect("known-valid status and header")
}

pub fn response_400() -> HttpResponse {
    html_response(
        StatusCode::BAD_REQUEST,
        "<h1>400 Bad Request</h1>",
    )
}

pub fn response_403() -> HttpResponse {
    html_response(StatusCode::FORBIDDEN, "<h1>403 Forbidden</h1>")
}

pub fn response_404() -> HttpResponse {
    html_response(StatusCode::NOT_FOUND, "<h1>404 Not Found</h1>")
}

pub fn response_500() -> HttpResponse {
    html_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "<h1>500 Internal Server Error</h1>",
    )
}

pub fn response_502() -> HttpResponse {
    html_response(
        StatusCode::BAD_GATEWAY,
        "<h1>502 Bad Gateway</h1>",
    )
}

pub fn response_416(total_len: u64) -> HttpResponse {
    Response::builder()
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .header("Content-Range", format!("bytes */{total_len}"))
        .body(bytes_body(Bytes::from_static(
            b"<h1>416 Range Not Satisfiable</h1>",
        )))
        .expect("known-valid status and header")
}

/// Return a minimal response with any HTTP status code.
/// Used by the access policy to return custom deny codes.
pub fn response_status(code: u16) -> HttpResponse {
    Response::builder()
        .status(code)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(bytes_body(Bytes::from(format!(
            "<h1>{code}</h1>"
        ))))
        .unwrap_or_else(|_| {
            // code was invalid; fall back to 403
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "text/html; charset=utf-8")
                .body(bytes_body(Bytes::from_static(
                    b"<h1>403 Forbidden</h1>",
                )))
                .expect("known-valid")
        })
}

/// Return 401 with a `WWW-Authenticate: Basic` challenge header.
/// The realm is encoded as a quoted-string per RFC 7235 §2.1.
pub fn response_www_auth(realm: &str) -> HttpResponse {
    // Escape backslashes then double-quotes to form a valid quoted-string.
    let safe = realm.replace('\\', "\\\\").replace('"', "\\\"");
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(
            "WWW-Authenticate",
            format!("Basic realm=\"{safe}\""),
        )
        .header("Content-Type", "text/html; charset=utf-8")
        .body(bytes_body(Bytes::from_static(
            b"<h1>401 Unauthorized</h1>",
        )))
        .expect("known-valid status and header")
}

pub fn response_redirect(to: &str, code: u16) -> HttpResponse {
    Response::builder()
        .status(code)
        .header("Location", to)
        .body(bytes_body(Bytes::new()))
        .expect("caller-validated redirect code and URL")
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_400_status() {
        assert_eq!(response_400().status(), 400);
    }

    #[test]
    fn response_403_status() {
        assert_eq!(response_403().status(), 403);
    }

    #[test]
    fn response_404_status() {
        assert_eq!(response_404().status(), 404);
    }

    #[test]
    fn response_500_status() {
        assert_eq!(response_500().status(), 500);
    }

    #[test]
    fn response_502_status() {
        assert_eq!(response_502().status(), 502);
    }

    #[test]
    fn response_416_status_and_content_range() {
        let r = response_416(1234);
        assert_eq!(r.status(), 416);
        assert_eq!(
            r.headers().get("content-range").unwrap(),
            "bytes */1234"
        );
    }

    #[test]
    fn response_redirect_sets_location_and_code() {
        let r = response_redirect("/new/path", 301);
        assert_eq!(r.status(), 301);
        assert_eq!(r.headers().get("location").unwrap(), "/new/path");
    }

    #[test]
    fn response_redirect_302() {
        let r = response_redirect("https://example.com/", 302);
        assert_eq!(r.status(), 302);
        assert_eq!(
            r.headers().get("location").unwrap(),
            "https://example.com/"
        );
    }

    #[test]
    fn response_www_auth_status_and_header() {
        let r = response_www_auth("My Realm");
        assert_eq!(r.status(), 401);
        assert_eq!(
            r.headers().get("www-authenticate").unwrap(),
            "Basic realm=\"My Realm\""
        );
    }

    #[test]
    fn response_www_auth_escapes_quotes() {
        let r = response_www_auth("Say \"hello\"");
        let h = r.headers().get("www-authenticate").unwrap();
        assert_eq!(h, r#"Basic realm="Say \"hello\"""#);
    }

    #[test]
    fn response_www_auth_escapes_backslashes() {
        let r = response_www_auth(r"C:\path");
        let h = r.headers().get("www-authenticate").unwrap();
        assert_eq!(h, r#"Basic realm="C:\\path""#);
    }
}
