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

pub fn response_redirect(to: &str, code: u16) -> HttpResponse {
    Response::builder()
        .status(code)
        .header("Location", to)
        .body(bytes_body(Bytes::new()))
        .expect("caller-validated redirect code and URL")
}
