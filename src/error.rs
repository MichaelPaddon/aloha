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

pub fn response_401() -> HttpResponse {
    html_response(
        StatusCode::UNAUTHORIZED,
        "<h1>401 Unauthorized</h1>",
    )
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
    fn response_401_status_and_type() {
        let r = response_401();
        assert_eq!(r.status(), 401);
        assert_eq!(
            r.headers().get("content-type").unwrap(),
            "text/html; charset=utf-8"
        );
    }

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
}
