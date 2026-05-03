// Authentication back-ends for HTTP Basic auth.
//
// Provides the Authenticator trait and three implementations:
//   AnonymousAuthenticator -- always returns Principal::Anonymous
//   PamAuthenticator       -- validates via the system PAM stack (Unix)
//   LdapAuthenticator      -- validates via an LDAP simple bind

use async_trait::async_trait;
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Clone)]
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
    async fn authenticate(
        &self,
        headers: &hyper::HeaderMap,
    ) -> Principal;
}

/// Always anonymous -- replaced once a real auth mechanism is wired up.
pub struct AnonymousAuthenticator;

#[async_trait]
impl Authenticator for AnonymousAuthenticator {
    async fn authenticate(
        &self,
        _headers: &hyper::HeaderMap,
    ) -> Principal {
        Principal::Anonymous
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
        Self { config: Arc::new(config) }
    }
}

#[async_trait]
impl Authenticator for LdapAuthenticator {
    async fn authenticate(
        &self,
        headers: &hyper::HeaderMap,
    ) -> Principal {
        let Some((username, password)) = parse_basic_auth(headers)
        else {
            return Principal::Anonymous;
        };
        // An empty password causes many LDAP servers to accept any
        // bind as an anonymous bind, granting unintended access.
        if password.is_empty() {
            return Principal::Anonymous;
        }
        let cfg = self.config.clone();
        let uname = username.clone();
        let timeout =
            std::time::Duration::from_secs(cfg.timeout_secs);
        match tokio::time::timeout(
            timeout,
            ldap_authenticate(&cfg, &uname, &password),
        )
        .await
        {
            Ok(Ok(groups)) => Principal::Authenticated(Identity {
                username,
                groups,
            }),
            Ok(Err(e)) => {
                tracing::warn!(username, "auth failed: {e}");
                Principal::Anonymous
            }
            Err(_) => {
                tracing::warn!(
                    "LDAP auth timed out for {username}"
                );
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
        .set_conn_timeout(
            std::time::Duration::from_secs(config.timeout_secs),
        );

    let url = normalize_ldapi_url(&config.url);
    let (conn, mut ldap) =
        LdapConnAsync::with_settings(settings, &url).await?;
    ldap3::drive!(conn);

    // Substitute and escape the username into the bind DN.
    let dn = config
        .bind_dn
        .replace("{user}", &escape_dn(username));
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
            '*'  => out.push_str("\\2a"),
            '('  => out.push_str("\\28"),
            ')'  => out.push_str("\\29"),
            '\0' => out.push_str("\\00"),
            c    => out.push(c),
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
        Self { service: service.into() }
    }
}

#[cfg(unix)]
#[async_trait]
impl Authenticator for PamAuthenticator {
    async fn authenticate(
        &self,
        headers: &hyper::HeaderMap,
    ) -> Principal {
        let Some((username, password)) = parse_basic_auth(headers)
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

// -- Credential cache ----------------------------------------------

/// Short-lived cache for HTTP Basic credentials.
///
/// Wraps any `Authenticator` and re-uses the last successful result
/// for `ttl` without calling the inner back-end (PAM/LDAP).  Failed
/// authentications are never cached so a corrected password takes
/// effect on the next request.  Passwords are stored as
/// `Zeroizing<String>` and are zeroed in memory on eviction or drop.
pub struct CachingAuthenticator<A> {
    inner: A,
    ttl:   std::time::Duration,
    cache: tokio::sync::RwLock<
        std::collections::HashMap<String, CacheEntry>,
    >,
}

struct CacheEntry {
    password:  Zeroizing<String>,
    principal: Principal,
    expires:   std::time::Instant,
}

impl<A: Authenticator> CachingAuthenticator<A> {
    pub fn new(inner: A, ttl: std::time::Duration) -> Self {
        Self {
            inner,
            ttl,
            cache: tokio::sync::RwLock::new(
                std::collections::HashMap::new(),
            ),
        }
    }
}

#[async_trait]
impl<A: Authenticator> Authenticator for CachingAuthenticator<A> {
    async fn authenticate(
        &self,
        headers: &hyper::HeaderMap,
    ) -> Principal {
        let Some((username, password)) = parse_basic_auth(headers)
        else {
            return Principal::Anonymous;
        };

        // Cache hit: verify password matches and entry is fresh.
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(&username) {
                if entry.expires > std::time::Instant::now()
                    && *entry.password == *password
                {
                    return entry.principal.clone();
                }
            }
        }

        // Miss: delegate to inner authenticator.
        let principal = self.inner.authenticate(headers).await;

        if let Principal::Authenticated(_) = &principal {
            let mut cache = self.cache.write().await;
            // Lazy eviction of stale entries before inserting.
            cache.retain(
                |_, e| e.expires > std::time::Instant::now(),
            );
            cache.insert(username, CacheEntry {
                password,
                principal: principal.clone(),
                expires: std::time::Instant::now() + self.ttl,
            });
        }

        principal
    }
}

// -- Tests ---------------------------------------------------------

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
        assert_eq!(*p, "pass");
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
        let enc = base64::engine::general_purpose::STANDARD
            .encode("usernameonly");
        let h = headers_with_auth(&format!("Basic {enc}"));
        assert!(parse_basic_auth(&h).is_none());
    }

    #[test]
    fn parse_basic_auth_empty_username() {
        // ":password" -- empty username is technically valid per RFC 7617
        use base64::Engine as _;
        let enc = base64::engine::general_purpose::STANDARD
            .encode(":password");
        let h = headers_with_auth(&format!("Basic {enc}"));
        let (u, p) = parse_basic_auth(&h).unwrap();
        assert_eq!(u, "");
        assert_eq!(*p, "password");
    }

    #[test]
    fn parse_basic_auth_empty_password() {
        use base64::Engine as _;
        let enc = base64::engine::general_purpose::STANDARD
            .encode("alice:");
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

    // -- CachingAuthenticator --------------------------------------

    // Minimal authenticator: accepts "correct" as password, counts calls.
    struct CountingAuthenticator {
        call_count: std::sync::atomic::AtomicUsize,
    }

    impl CountingAuthenticator {
        fn new() -> Self {
            Self {
                call_count: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.call_count
                .load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Authenticator for CountingAuthenticator {
        async fn authenticate(
            &self,
            headers: &hyper::HeaderMap,
        ) -> Principal {
            self.call_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match parse_basic_auth(headers) {
                Some((u, p)) if *p == "correct" => {
                    Principal::Authenticated(Identity {
                        username: u,
                        groups: vec![],
                    })
                }
                _ => Principal::Anonymous,
            }
        }
    }

    fn basic_headers(user: &str, pass: &str) -> hyper::HeaderMap {
        use base64::Engine as _;
        let cred = base64::engine::general_purpose::STANDARD
            .encode(format!("{user}:{pass}"));
        let mut map = hyper::HeaderMap::new();
        map.insert(
            hyper::header::AUTHORIZATION,
            format!("Basic {cred}").parse().unwrap(),
        );
        map
    }

    #[tokio::test]
    async fn cache_hit_avoids_inner_call() {
        let auth = CachingAuthenticator::new(
            CountingAuthenticator::new(),
            std::time::Duration::from_secs(60),
        );
        let h = basic_headers("alice", "correct");
        // First call: miss, goes to inner.
        let p1 = auth.authenticate(&h).await;
        assert!(matches!(p1, Principal::Authenticated(_)));
        assert_eq!(auth.inner.calls(), 1);
        // Second call: hit, inner not called again.
        let p2 = auth.authenticate(&h).await;
        assert!(matches!(p2, Principal::Authenticated(_)));
        assert_eq!(auth.inner.calls(), 1);
    }

    #[tokio::test]
    async fn cache_wrong_password_falls_through() {
        let auth = CachingAuthenticator::new(
            CountingAuthenticator::new(),
            std::time::Duration::from_secs(60),
        );
        // Populate cache with correct credentials.
        auth.authenticate(&basic_headers("alice", "correct")).await;
        assert_eq!(auth.inner.calls(), 1);
        // Different password: cache key mismatch → inner called again.
        let p = auth
            .authenticate(&basic_headers("alice", "wrong"))
            .await;
        assert!(matches!(p, Principal::Anonymous));
        assert_eq!(auth.inner.calls(), 2);
    }

    #[tokio::test]
    async fn cache_anonymous_not_stored() {
        let auth = CachingAuthenticator::new(
            CountingAuthenticator::new(),
            std::time::Duration::from_secs(60),
        );
        let h = basic_headers("alice", "wrong");
        auth.authenticate(&h).await;
        auth.authenticate(&h).await;
        // Inner called both times — anonymous results are never cached.
        assert_eq!(auth.inner.calls(), 2);
    }

    #[tokio::test]
    async fn cache_expired_entry_calls_inner() {
        let auth = CachingAuthenticator::new(
            CountingAuthenticator::new(),
            std::time::Duration::from_millis(1),
        );
        let h = basic_headers("alice", "correct");
        auth.authenticate(&h).await;
        assert_eq!(auth.inner.calls(), 1);
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        auth.authenticate(&h).await;
        assert_eq!(auth.inner.calls(), 2);
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
