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

// ── HTTP Basic / PAM ──────────────────────────────────────────────

/// Decode an `Authorization: Basic <base64>` header.
/// Returns `(username, password)` or `None` if absent or malformed.
pub fn parse_basic_auth(
    headers: &hyper::HeaderMap,
) -> Option<(String, String)> {
    use base64::Engine as _;
    let val = headers
        .get(hyper::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let encoded = val.strip_prefix("Basic ")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(bytes).ok()?;
    let (user, pass) = decoded.split_once(':')?;
    Some((user.to_owned(), pass.to_owned()))
}

/// Authenticates against the system PAM stack, then resolves the
/// user's Unix group membership via `getgrouplist(3)`.
#[cfg(unix)]
pub struct PamAuthenticator {
    service: String,
}

#[cfg(unix)]
impl PamAuthenticator {
    pub fn new(service: impl Into<String>) -> Self {
        Self { service: service.into() }
    }
}

#[cfg(unix)]
#[async_trait]
impl Authenticator for PamAuthenticator {
    async fn authenticate(&self, req: &Request<Incoming>) -> Principal {
        let Some((username, password)) = parse_basic_auth(req.headers())
        else {
            return Principal::Anonymous;
        };
        let service = self.service.clone();
        let uname = username.clone();
        match tokio::task::spawn_blocking(move || {
            pam_validate(&service, &uname, &password)
        })
        .await
        {
            Ok(Ok(groups)) => Principal::Authenticated(Identity {
                username,
                groups,
            }),
            Ok(Err(e)) => {
                tracing::debug!("PAM auth failed for {username}: {e}");
                Principal::Anonymous
            }
            Err(e) => {
                tracing::warn!("PAM task panicked: {e}");
                Principal::Anonymous
            }
        }
    }
}

/// Call into libpam to authenticate username/password, then return
/// the user's group names.  Must run on a blocking thread.
#[cfg(unix)]
fn pam_validate(
    service: &str,
    username: &str,
    password: &str,
) -> anyhow::Result<Vec<String>> {
    let mut auth = pam::Authenticator::with_password(service)
        .map_err(|e| anyhow::anyhow!("PAM init: {e:?}"))?;
    auth.get_handler().set_credentials(username, password);
    auth.authenticate()
        .map_err(|e| anyhow::anyhow!("PAM authenticate: {e:?}"))?;
    lookup_groups(username)
}

/// Resolve Unix group names for `username` using `getgrouplist(3)`.
#[cfg(unix)]
fn lookup_groups(username: &str) -> anyhow::Result<Vec<String>> {
    use std::ffi::CString;
    use nix::unistd::{Group, User, getgrouplist};
    let cname = CString::new(username)?;
    let user = User::from_name(username)?
        .ok_or_else(|| anyhow::anyhow!("user '{username}' not found"))?;
    let gids = getgrouplist(&cname, user.gid)?;
    Ok(gids
        .into_iter()
        .filter_map(|gid| Group::from_gid(gid).ok().flatten())
        .map(|g| g.name)
        .collect())
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_auth(value: &str) -> hyper::HeaderMap {
        let mut map = hyper::HeaderMap::new();
        map.insert(
            hyper::header::AUTHORIZATION,
            value.parse().unwrap(),
        );
        map
    }

    #[test]
    fn parse_basic_auth_valid() {
        // "user:pass" base64-encodes to "dXNlcjpwYXNz"
        let h = headers_with_auth("Basic dXNlcjpwYXNz");
        let (u, p) = parse_basic_auth(&h).unwrap();
        assert_eq!(u, "user");
        assert_eq!(p, "pass");
    }

    #[test]
    fn parse_basic_auth_colon_in_password() {
        // Only the first colon splits user/pass.
        use base64::Engine as _;
        let enc = base64::engine::general_purpose::STANDARD
            .encode("alice:pass:word");
        let h = headers_with_auth(&format!("Basic {enc}"));
        let (u, p) = parse_basic_auth(&h).unwrap();
        assert_eq!(u, "alice");
        assert_eq!(p, "pass:word");
    }

    #[test]
    fn parse_basic_auth_missing_header() {
        let h = hyper::HeaderMap::new();
        assert!(parse_basic_auth(&h).is_none());
    }

    #[test]
    fn parse_basic_auth_wrong_scheme() {
        let h = headers_with_auth("Bearer sometoken");
        assert!(parse_basic_auth(&h).is_none());
    }

    #[test]
    fn parse_basic_auth_invalid_base64() {
        let h = headers_with_auth("Basic !!!notbase64!!!");
        assert!(parse_basic_auth(&h).is_none());
    }

    #[test]
    fn parse_basic_auth_no_colon() {
        use base64::Engine as _;
        let enc = base64::engine::general_purpose::STANDARD
            .encode("usernameonly");
        let h = headers_with_auth(&format!("Basic {enc}"));
        assert!(parse_basic_auth(&h).is_none());
    }
}
