use crate::error::{response_502, HttpResponse};
use hyper::Request;
use hyper::body::Incoming;

// FastCGI handler — not yet implemented.
#[allow(dead_code)]
pub struct FcgiHandler {
    pub socket: String,
    pub index: Option<String>,
}

impl FcgiHandler {
    pub fn new(socket: &str, index: Option<String>) -> Self {
        Self { socket: socket.to_owned(), index }
    }

    pub async fn serve(
        &self,
        _req: &Request<Incoming>,
        _prefix: &str,
    ) -> HttpResponse {
        response_502()
    }
}
