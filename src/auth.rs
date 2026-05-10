// Authentication back-ends for HTTP Basic auth.
//
// Provides the Authenticator trait and three implementations:
//   AnonymousAuthenticator -- always returns Principal::Anonymous
//   PamAuthenticator       -- validates via the system PAM stack (Unix)
//   LdapAuthenticator      -- validates via an LDAP simple bind

use async_trait::async_trait;
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub struct Identity {
    pub username: String,
    pub groups: Vec<String>,
}

#[derive(Clone)]
pub enum Principal {
    Anonymous,
    Authenticated(Identity),
}

/// Pluggable authentication mechanism.  `AnonymousAuthenticator` is
/// the default until a real mechanism is configured.
///
/// Takes only the request headers — authenticators (Basic auth, etc.)
/// never need the body, and restricting the input makes unit testing
/// straightforward without requiring a real `Incoming` connection.
#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(&self, headers: &hyper::HeaderMap) -> Principal;
}

/// Always anonymous -- replaced once a real auth mechanism is wired up.
pub struct AnonymousAuthenticator;

#[async_trait]
impl Authenticator for AnonymousAuthenticator {
    async fn authenticate(&self, _headers: &hyper::HeaderMap) -> Principal {
        Principal::Anonymous
    }
}

// -- Subrequest auth -----------------------------------------------

/// Authenticates by making an HTTP GET to a configured endpoint.
/// Mirrors the nginx `auth_request` module: HTTP 200 → Authenticated,
/// any other status or network error → Anonymous.
///
/// Selected request headers (e.g. `Authorization`) are forwarded to the
/// auth endpoint.  The authenticated identity is read from optional
/// response headers configured via `user-header` and `groups-header`.
pub struct SubrequestAuthenticator {
    url: hyper::Uri,
    forward_headers: Vec<hyper::header::HeaderName>,
    user_header: Option<hyper::header::HeaderName>,
    groups_header: Option<hyper::header::HeaderName>,
    timeout: std::time::Duration,
    client: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        http_body_util::Empty<bytes::Bytes>,
    >,
}

impl SubrequestAuthenticator {
    pub fn new(
        cfg: &crate::config::SubrequestAuthConfig,
    ) -> anyhow::Result<Self> {
        use hyper::header::HeaderName;
        use hyper_util::client::legacy::Client;
        use hyper_util::rt::TokioExecutor;

        let url: hyper::Uri = cfg.url.parse().map_err(|e| {
            anyhow::anyhow!("invalid subrequest URL '{}': {e}", cfg.url)
        })?;
        let forward_headers = cfg
            .forward_headers
            .iter()
            .map(|s| {
                HeaderName::from_bytes(s.as_bytes()).map_err(|e| {
                    anyhow::anyhow!("invalid forward-header '{s}': {e}")
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let user_header = cfg
            .user_header
            .as_deref()
            .map(|s| {
                HeaderName::from_bytes(s.as_bytes()).map_err(|e| {
                    anyhow::anyhow!("invalid user-header '{s}': {e}")
                })
            })
            .transpose()?;
        let groups_header = cfg
            .groups_header
            .as_deref()
            .map(|s| {
                HeaderName::from_bytes(s.as_bytes()).map_err(|e| {
                    anyhow::anyhow!("invalid groups-header '{s}': {e}")
                })
            })
            .transpose()?;
        let client = Client::builder(TokioExecutor::new()).build_http();
        Ok(Self {
            url,
            forward_headers,
            user_header,
            groups_header,
            timeout: std::time::Duration::from_secs(cfg.timeout_secs),
            client,
        })
    }

    async fn call(&self, headers: &hyper::HeaderMap) -> Principal {
        use http_body_util::Empty;
        use hyper::{Method, Request};

        let mut builder =
            Request::builder().method(Method::GET).uri(self.url.clone());
        for name in &self.forward_headers {
            if let Some(val) = headers.get(name) {
                builder = builder.header(name.clone(), val.clone());
            }
        }
        let req = match builder.body(Empty::new()) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    url = %self.url,
                    "subrequest auth: failed to build request: {e}",
                );
                return Principal::Anonymous;
            }
        };
        let resp = match self.client.request(req).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    url = %self.url,
                    "subrequest auth: request failed: {e}",
                );
                return Principal::Anonymous;
            }
        };
        if resp.status() != hyper::StatusCode::OK {
            return Principal::Anonymous;
        }
        let username = self
            .user_header
            .as_ref()
            .and_then(|h| resp.headers().get(h))
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let groups: Vec<String> = self
            .groups_header
            .as_ref()
            .and_then(|h| resp.headers().get(h))
            .and_then(|v| v.to_str().ok())
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|g| !g.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Principal::Authenticated(Identity { username, groups })
    }
}

#[async_trait]
impl Authenticator for SubrequestAuthenticator {
    async fn authenticate(&self, headers: &hyper::HeaderMap) -> Principal {
        match tokio::time::timeout(self.timeout, self.call(headers)).await {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(
                    url = %self.url,
                    "subrequest auth: timed out",
                );
                Principal::Anonymous
            }
        }
    }
}

// -- HTTP Basic / PAM ----------------------------------------------

/// Decode an `Authorization: Basic <base64>` header.
/// Returns `(username, password)` or `None` if absent or malformed.
/// The password is wrapped in `Zeroizing` so it is zeroed on drop.
pub fn parse_basic_auth(
    headers: &hyper::HeaderMap,
) -> Option<(String, Zeroizing<String>)> {
    use base64::Engine as _;
    let val = headers.get(hyper::header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = val.strip_prefix("Basic ")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(bytes).ok()?;
    let (user, pass) = decoded.split_once(':')?;
    Some((user.to_owned(), Zeroizing::new(pass.to_owned())))
}

// -- LDAP ----------------------------------------------------------

/// Authenticates HTTP Basic credentials via an LDAP simple bind, then
/// searches for the user's group memberships.
///
/// Supports `ldap://`, `ldaps://`, and `ldapi://` (Unix socket) URLs.
/// A new connection is established for each authentication request.
pub struct LdapAuthenticator {
    config: Arc<crate::config::LdapAuthConfig>,
}

impl LdapAuthenticator {
    pub fn new(config: crate::config::LdapAuthConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

#[async_trait]
impl Authenticator for LdapAuthenticator {
    async fn authenticate(&self, headers: &hyper::HeaderMap) -> Principal {
        let Some((username, password)) = parse_basic_auth(headers) else {
            return Principal::Anonymous;
        };
        // An empty password causes many LDAP servers to accept any
        // bind as an anonymous bind, granting unintended access.
        if password.is_empty() {
            return Principal::Anonymous;
        }
        let cfg = self.config.clone();
        let uname = username.clone();
        let timeout = std::time::Duration::from_secs(cfg.timeout_secs);
        match tokio::time::timeout(
            timeout,
            ldap_authenticate(&cfg, &uname, &password),
        )
        .await
        {
            Ok(Ok(groups)) => {
                Principal::Authenticated(Identity { username, groups })
            }
            Ok(Err(e)) => {
                tracing::warn!(username, "auth failed: {e}");
                Principal::Anonymous
            }
            Err(_) => {
                tracing::warn!("LDAP auth timed out for {username}");
                Principal::Anonymous
            }
        }
    }
}

/// Convert a plain `ldapi://` URL to the percent-encoded form expected by
/// ldap3.  ldap3 requires the socket path in the authority component with
/// `/` encoded as `%2F`.  An already-encoded URL (authority starts with
/// `%2F` or `%2f`) is returned unchanged, as is any non-`ldapi://` URL.
///
/// `ldapi:///var/run/slapd/ldapi`  →  `ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi`
fn normalize_ldapi_url(url: &str) -> String {
    let Some(rest) = url.strip_prefix("ldapi://") else {
        return url.to_owned();
    };
    if rest.starts_with("%2F") || rest.starts_with("%2f") {
        return url.to_owned(); // already encoded
    }
    format!("ldapi://{}", rest.replace('/', "%2F"))
}

async fn ldap_authenticate(
    config: &crate::config::LdapAuthConfig,
    username: &str,
    password: &str,
) -> anyhow::Result<Vec<String>> {
    use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

    let settings = LdapConnSettings::new()
        .set_starttls(config.starttls)
        .set_conn_timeout(std::time::Duration::from_secs(config.timeout_secs));

    let url = normalize_ldapi_url(&config.url);
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url).await?;
    ldap3::drive!(conn);

    // Substitute and escape the username into the bind DN.
    let dn = config.bind_dn.replace("{user}", &escape_dn(username));
    ldap.simple_bind(&dn, password)
        .await?
        .success()
        .map_err(|e| anyhow::anyhow!("invalid credentials: {e:?}"))?;

    // Search for groups containing this user.
    let filter = config
        .group_filter
        .replace("{user}", &escape_filter(username));
    let (entries, _res) = ldap
        .search(
            &config.base_dn,
            Scope::Subtree,
            &filter,
            vec![config.group_attr.as_str()],
        )
        .await?
        .success()?;

    let groups = entries
        .into_iter()
        .filter_map(|e| {
            SearchEntry::construct(e)
                .attrs
                .get(&config.group_attr)?
                .first()
                .cloned()
        })
        .collect();

    ldap.unbind().await?;
    Ok(groups)
}

/// Escape a value for use inside an LDAP DN (RFC 4514 s.2.4).
///
/// The following characters are escaped with a leading `\`:
/// `,`, `+`, `"`, `\`, `<`, `>`, `;`, leading `#`, leading/trailing ` `.
pub fn escape_dn(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = s.chars().collect();
    let last = chars.len() - 1;
    let mut out = String::with_capacity(s.len());
    for (i, &ch) in chars.iter().enumerate() {
        match ch {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' => {
                out.push('\\');
                out.push(ch);
            }
            '#' if i == 0 => out.push_str("\\#"),
            ' ' if i == 0 || i == last => out.push_str("\\ "),
            c => out.push(c),
        }
    }
    out
}

/// Escape a value for use inside an LDAP search filter (RFC 4515 s.3).
///
/// `\`, `*`, `(`, `)`, and NUL are replaced with their `\xx` hex forms.
pub fn escape_filter(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\5c"),
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\0' => out.push_str("\\00"),
            c => out.push(c),
        }
    }
    out
}

// -- PAM -----------------------------------------------------------

/// Authenticates against the system PAM stack, then resolves the
/// user's Unix group membership via `getgrouplist(3)`.
#[cfg(unix)]
pub struct PamAuthenticator {
    service: String,
}

#[cfg(unix)]
impl PamAuthenticator {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

#[cfg(unix)]
#[async_trait]
impl Authenticator for PamAuthenticator {
    async fn authenticate(&self, headers: &hyper::HeaderMap) -> Principal {
        let Some((username, password)) = parse_basic_auth(headers) else {
            return Principal::Anonymous;
        };
        let service = self.service.clone();
        let uname = username.clone();
        match tokio::task::spawn_blocking(move || {
            pam_validate(&service, &uname, &password)
        })
        .await
        {
            Ok(Ok(groups)) => {
                Principal::Authenticated(Identity { username, groups })
            }
            Ok(Err(e)) => {
                tracing::warn!(username, "auth failed: {e}");
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
    use nix::unistd::{Group, User, getgrouplist};
    use std::ffi::CString;
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

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_auth(value: &str) -> hyper::HeaderMap {
        let mut map = hyper::HeaderMap::new();
        map.insert(hyper::header::AUTHORIZATION, value.parse().unwrap());
        map
    }

    #[test]
    fn parse_basic_auth_valid() {
        // "user:pass" base64-encodes to "dXNlcjpwYXNz"
        let h = headers_with_auth("Basic dXNlcjpwYXNz");
        let (u, p) = parse_basic_auth(&h).unwrap();
        assert_eq!(u, "user");
        assert_eq!(*p, "pass");
    }

    #[test]
    fn parse_basic_auth_colon_in_password() {
        // Only the first colon splits user/pass.
        use base64::Engine as _;
        let enc =
            base64::engine::general_purpose::STANDARD.encode("alice:pass:word");
        let h = headers_with_auth(&format!("Basic {enc}"));
        let (u, p) = parse_basic_auth(&h).unwrap();
        assert_eq!(u, "alice");
        assert_eq!(*p, "pass:word");
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
        let enc =
            base64::engine::general_purpose::STANDARD.encode("usernameonly");
        let h = headers_with_auth(&format!("Basic {enc}"));
        assert!(parse_basic_auth(&h).is_none());
    }

    #[test]
    fn parse_basic_auth_empty_username() {
        // ":password" -- empty username is technically valid per RFC 7617
        use base64::Engine as _;
        let enc = base64::engine::general_purpose::STANDARD.encode(":password");
        let h = headers_with_auth(&format!("Basic {enc}"));
        let (u, p) = parse_basic_auth(&h).unwrap();
        assert_eq!(u, "");
        assert_eq!(*p, "password");
    }

    #[test]
    fn parse_basic_auth_empty_password() {
        use base64::Engine as _;
        let enc = base64::engine::general_purpose::STANDARD.encode("alice:");
        let h = headers_with_auth(&format!("Basic {enc}"));
        let (u, p) = parse_basic_auth(&h).unwrap();
        assert_eq!(u, "alice");
        assert_eq!(*p, "");
    }

    #[test]
    fn parse_basic_auth_unicode_credentials() {
        // RFC 7617 allows UTF-8 in credentials.
        // Strings written with Rust unicode escapes to keep source ASCII.
        // \u{fc}=u-umlaut \u{ef}=i-umlaut \u{f6}=o-umlaut \u{e9}=e-acute
        // \u{e4}=a-umlaut \u{f0}=eth
        let user = "\u{fc}n\u{ef}c\u{f6}d\u{e9}";
        let pass = "p\u{e4}ssw\u{f6}r\u{f0}";
        use base64::Engine as _;
        let enc = base64::engine::general_purpose::STANDARD
            .encode(format!("{user}:{pass}"));
        let h = headers_with_auth(&format!("Basic {enc}"));
        let (u, p) = parse_basic_auth(&h).unwrap();
        assert_eq!(u, user);
        assert_eq!(*p, pass);
    }

    #[test]
    fn parse_basic_auth_case_sensitive_scheme() {
        // "basic" (lowercase) must not match -- RFC 7235 says the scheme
        // token is case-insensitive in HTTP, but our prefix match is
        // exact.  Browsers always send "Basic" with capital B.
        let h = headers_with_auth("basic dXNlcjpwYXNz");
        assert!(parse_basic_auth(&h).is_none());
    }

    #[test]
    fn parse_basic_auth_empty_credentials() {
        // Just ":" encodes to a valid split: ("", "")
        use base64::Engine as _;
        let enc = base64::engine::general_purpose::STANDARD.encode(":");
        let h = headers_with_auth(&format!("Basic {enc}"));
        let (u, p) = parse_basic_auth(&h).unwrap();
        assert_eq!(u, "");
        assert_eq!(*p, "");
    }

    // -- LDAP escaping ---------------------------------------------

    #[test]
    fn escape_dn_plain_username() {
        assert_eq!(escape_dn("alice"), "alice");
    }

    #[test]
    fn escape_dn_special_chars() {
        // Each of the RFC 4514 special characters must be backslash-escaped.
        assert_eq!(escape_dn("a,b"), "a\\,b");
        assert_eq!(escape_dn("a+b"), "a\\+b");
        assert_eq!(escape_dn("a\"b"), "a\\\"b");
        assert_eq!(escape_dn("a\\b"), "a\\\\b");
        assert_eq!(escape_dn("a<b"), "a\\<b");
        assert_eq!(escape_dn("a>b"), "a\\>b");
        assert_eq!(escape_dn("a;b"), "a\\;b");
    }

    #[test]
    fn escape_dn_leading_hash() {
        assert_eq!(escape_dn("#admin"), "\\#admin");
        // Hash not at position 0 is left alone.
        assert_eq!(escape_dn("ad#min"), "ad#min");
    }

    #[test]
    fn escape_dn_leading_trailing_space() {
        assert_eq!(escape_dn(" alice"), "\\ alice");
        assert_eq!(escape_dn("alice "), "alice\\ ");
        assert_eq!(escape_dn(" alice "), "\\ alice\\ ");
        // Space in the middle is left alone.
        assert_eq!(escape_dn("ali ce"), "ali ce");
    }

    #[test]
    fn escape_dn_empty() {
        assert_eq!(escape_dn(""), "");
    }

    #[test]
    fn escape_dn_unicode_passthrough() {
        // Non-ASCII characters that are not special pass through unchanged.
        assert_eq!(escape_dn("h\u{e9}llo"), "h\u{e9}llo");
    }

    #[test]
    fn escape_filter_plain_value() {
        assert_eq!(escape_filter("alice"), "alice");
    }

    #[test]
    fn escape_filter_special_chars() {
        assert_eq!(escape_filter("\\"), "\\5c");
        assert_eq!(escape_filter("*"), "\\2a");
        assert_eq!(escape_filter("("), "\\28");
        assert_eq!(escape_filter(")"), "\\29");
        assert_eq!(escape_filter("\0"), "\\00");
    }

    #[test]
    fn escape_filter_injection_attempt() {
        // A username designed to break out of a filter must be neutralised.
        let malicious = "alice)(uid=*))(|(uid=*";
        let safe = escape_filter(malicious);
        // Must not contain any bare `(` or `)`.
        assert!(!safe.contains('('));
        assert!(!safe.contains(')'));
    }

    #[test]
    fn escape_filter_wildcard_prevented() {
        let result = escape_filter("*");
        assert_eq!(result, "\\2a");
    }

    #[test]
    fn escape_filter_unicode_passthrough() {
        assert_eq!(escape_filter("h\u{e9}llo"), "h\u{e9}llo");
    }

    // -- SubrequestAuthenticator -----------------------------------

    // Bind a random port, serve one HTTP/1.1 response, and return the
    // local address and the server task handle.
    async fn mock_auth_server(
        status: u16,
        user_header: Option<&'static str>,
        groups_header: Option<&'static str>,
    ) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut response = format!(
            "HTTP/1.1 {status} \r\n\
             Content-Length: 0\r\n"
        );
        if let Some(u) = user_header {
            response.push_str(&format!("X-Auth-User: {u}\r\n"));
        }
        if let Some(g) = groups_header {
            response.push_str(&format!("X-Auth-Groups: {g}\r\n"));
        }
        response.push_str("\r\n");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Drain the request.
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        addr
    }

    fn subrequest_auth(
        addr: std::net::SocketAddr,
        forward: Vec<&'static str>,
        user_header: Option<&'static str>,
        groups_header: Option<&'static str>,
    ) -> SubrequestAuthenticator {
        let cfg = crate::config::SubrequestAuthConfig {
            url: format!("http://{addr}/auth"),
            forward_headers: forward.into_iter().map(str::to_owned).collect(),
            user_header: user_header.map(str::to_owned),
            groups_header: groups_header.map(str::to_owned),
            timeout_secs: 5,
        };
        SubrequestAuthenticator::new(&cfg).unwrap()
    }

    #[tokio::test]
    async fn subrequest_200_without_user_header_is_authenticated() {
        let addr = mock_auth_server(200, None, None).await;
        let auth = subrequest_auth(addr, vec![], None, None);
        let p = auth.authenticate(&hyper::HeaderMap::new()).await;
        assert!(matches!(p, Principal::Authenticated(ref id)
            if id.username.is_empty()));
    }

    #[tokio::test]
    async fn subrequest_200_with_user_header_sets_username() {
        let addr = mock_auth_server(200, Some("alice"), None).await;
        let auth = subrequest_auth(addr, vec![], Some("X-Auth-User"), None);
        let p = auth.authenticate(&hyper::HeaderMap::new()).await;
        match p {
            Principal::Authenticated(id) => {
                assert_eq!(id.username, "alice");
                assert!(id.groups.is_empty());
            }
            Principal::Anonymous => panic!("expected Authenticated"),
        }
    }

    #[tokio::test]
    async fn subrequest_200_with_groups_header_sets_groups() {
        let addr =
            mock_auth_server(200, Some("bob"), Some("admin,users")).await;
        let auth = subrequest_auth(
            addr,
            vec![],
            Some("X-Auth-User"),
            Some("X-Auth-Groups"),
        );
        let p = auth.authenticate(&hyper::HeaderMap::new()).await;
        match p {
            Principal::Authenticated(id) => {
                assert_eq!(id.username, "bob");
                assert_eq!(id.groups, vec!["admin", "users"]);
            }
            Principal::Anonymous => panic!("expected Authenticated"),
        }
    }

    #[tokio::test]
    async fn subrequest_403_returns_anonymous() {
        let addr = mock_auth_server(403, None, None).await;
        let auth = subrequest_auth(addr, vec![], None, None);
        let p = auth.authenticate(&hyper::HeaderMap::new()).await;
        assert!(matches!(p, Principal::Anonymous));
    }

    #[tokio::test]
    async fn subrequest_connection_refused_returns_anonymous() {
        // Port 1 is almost guaranteed to be refused on any OS.
        let auth =
            subrequest_auth("127.0.0.1:1".parse().unwrap(), vec![], None, None);
        let p = auth.authenticate(&hyper::HeaderMap::new()).await;
        assert!(matches!(p, Principal::Anonymous));
    }

    #[tokio::test]
    async fn subrequest_forwards_authorization_header() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Capture the received request to verify header forwarding.
        let capture = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            let raw = String::from_utf8_lossy(&buf[..n]).to_string();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            raw
        });
        let auth = subrequest_auth(addr, vec!["authorization"], None, None);
        let mut hdrs = hyper::HeaderMap::new();
        hdrs.insert(
            hyper::header::AUTHORIZATION,
            "Basic dXNlcjpwYXNz".parse().unwrap(),
        );
        auth.authenticate(&hdrs).await;
        let raw = capture.await.unwrap();
        assert!(
            raw.to_lowercase().contains("authorization:"),
            "Authorization header not forwarded: {raw}"
        );
    }

    // -- normalize_ldapi_url ---------------------------------------

    #[test]
    fn normalize_ldapi_plain_path() {
        assert_eq!(
            normalize_ldapi_url("ldapi:///var/run/slapd/ldapi"),
            "ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi",
        );
    }

    #[test]
    fn normalize_ldapi_already_encoded_uppercase() {
        let url = "ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi";
        assert_eq!(normalize_ldapi_url(url), url);
    }

    #[test]
    fn normalize_ldapi_already_encoded_lowercase() {
        let url = "ldapi://%2fvar%2frun%2fslapd%2fldapi";
        assert_eq!(normalize_ldapi_url(url), url);
    }

    #[test]
    fn normalize_ldapi_leaves_ldap_unchanged() {
        let url = "ldap://localhost:389";
        assert_eq!(normalize_ldapi_url(url), url);
    }

    #[test]
    fn normalize_ldapi_leaves_ldaps_unchanged() {
        let url = "ldaps://ldap.example.com:636";
        assert_eq!(normalize_ldapi_url(url), url);
    }

    #[test]
    fn normalize_ldapi_tmp_socket() {
        assert_eq!(
            normalize_ldapi_url("ldapi:///tmp/ldapi.sock"),
            "ldapi://%2Ftmp%2Fldapi.sock",
        );
    }
}
