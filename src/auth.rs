use async_trait::async_trait;
use hyper::Request;
use hyper::body::Incoming;

pub struct Identity {
    pub username: String,
    pub groups: Vec<String>,
}

#[allow(dead_code)] // Authenticated constructed only by real authenticators
pub enum Principal {
    Anonymous,
    Authenticated(Identity),
}

/// Pluggable authentication mechanism.  `AnonymousAuthenticator` is
/// the default until a real mechanism is configured.
#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(&self, req: &Request<Incoming>) -> Principal;
}

/// Always anonymous — replaced once a real auth mechanism is wired up.
pub struct AnonymousAuthenticator;

#[async_trait]
impl Authenticator for AnonymousAuthenticator {
    async fn authenticate(&self, _req: &Request<Incoming>) -> Principal {
        Principal::Anonymous
    }
}
