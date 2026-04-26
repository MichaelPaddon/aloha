use crate::error::{response_502, HttpResponse};
use hyper::Request;
use hyper::body::Incoming;

// Reverse-proxy handler — not yet implemented.
#[allow(dead_code)]
pub struct ProxyHandler {
    pub upstream: String,
}

impl ProxyHandler {
    pub fn new(upstream: &str) -> Self {
        Self { upstream: upstream.to_owned() }
    }

    pub async fn serve(
        &self,
        _req: Request<Incoming>,
        _prefix: &str,
    ) -> HttpResponse {
        response_502()
    }
}
