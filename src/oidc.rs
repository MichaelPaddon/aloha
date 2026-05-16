// OIDC single sign-on back-end.
//
// On startup `OidcProvider::discover` runs OIDC discovery against the
// configured issuer and caches the resulting `CoreClient`.  Two hooks
// drive the login flow:
//
//   * `begin_login(return_to)` -- builds the authorisation URL,
//     stashes a PKCE verifier + nonce + return_to under the random
//     CSRF state, and returns both the URL and the state id.  Called
//     by the `<login_path>` endpoint dispatched in `listener.rs`.
//
//   * `complete_login(code, state)` -- consumes the stashed state,
//     exchanges the code with the IdP, validates the ID token, and
//     returns an `auth::Identity` plus the original return_to.
//     Called by the `<callback_path>` endpoint.
//
// The post-login identity is then persisted as a JWT session cookie
// via `JwtManager::make_set_cookie`, so subsequent requests carry
// authentication via the normal cookie path.

use crate::auth::Identity;
use crate::config::OidcConfig;
use anyhow::{Context, Result, anyhow, bail};
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthenticationFlow, CoreClaimName, CoreClaimType,
    CoreClient, CoreClientAuthMethod, CoreGrantType,
    CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse,
    CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType,
    CoreSubjectIdentifierType,
};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AdditionalProviderMetadata, AuthorizationCode, ClientId, ClientSecret,
    CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, ProviderMetadata, RedirectUrl, RefreshToken, Scope,
    TokenResponse,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Provider-metadata extension carrying the `end_session_endpoint`
/// URL.  The OIDC core spec puts this field in the RP-Initiated
/// Logout 1.0 addendum, which is why `openidconnect`'s
/// `CoreProviderMetadata` doesn't surface it -- the crate exposes
/// the `AdditionalProviderMetadata` trait for exactly this case.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct LogoutMetadata {
    #[serde(default)]
    end_session_endpoint: Option<url::Url>,
}
impl AdditionalProviderMetadata for LogoutMetadata {}

// Mirror `CoreProviderMetadata` exactly, swapping the additional-
// metadata slot.  This lets discovery deserialise our extra field
// while preserving every other Core type, so the rest of the OIDC
// pipeline keeps working unchanged.
type AlohaProviderMetadata = ProviderMetadata<
    LogoutMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

/// A pending login waiting for the IdP to redirect back to the
/// callback endpoint.
struct StateEntry {
    pkce_verifier: PkceCodeVerifier,
    nonce: Nonce,
    return_to: String,
    created: Instant,
}

/// A live refresh session backed by an IdP refresh token.  Looked up
/// by the opaque sid carried in the `__aloha_oidc_refresh` cookie.
struct RefreshEntry {
    refresh_token: RefreshToken,
    // Refresh-token validation does not require the original nonce
    // (it's only meaningful on the initial authorisation code flow).
    // We keep it here only for completeness; current code passes None
    // to the ID-token verifier on refresh.
    expires_at: Instant,
    // Raw ID-token JWT, used as `id_token_hint` when the logout
    // endpoint redirects to the IdP's `end_session_endpoint`.  Some
    // IdPs require this to identify the session being terminated.
    id_token: String,
}

/// Runtime handle for the configured OIDC IdP.  Constructed once at
/// startup; cloned via `Arc` into `AppState`.
pub struct OidcProvider {
    client: CoreClient,
    cfg: OidcConfig,
    states: Mutex<HashMap<String, StateEntry>>,
    state_ttl: Duration,
    // Refresh sessions; only populated when `cfg.refresh` is true.
    refreshes: Mutex<HashMap<String, RefreshEntry>>,
    refresh_ttl: Duration,
    // IdP's `end_session_endpoint` if exposed during discovery.
    // Without this, RP-initiated logout falls back to a local-only
    // cookie clear and a redirect to `post_logout_uri`.
    end_session_url: Option<url::Url>,
}

impl OidcProvider {
    /// Run OIDC discovery and build the runtime client.  Network
    /// failures bubble up; the caller decides whether to abort startup
    /// or retry in the background.
    pub async fn discover(cfg: OidcConfig) -> Result<Arc<Self>> {
        let issuer_url = IssuerUrl::new(cfg.issuer.clone())
            .with_context(|| format!("invalid OIDC issuer URL: {}", cfg.issuer))?;
        let metadata = AlohaProviderMetadata::discover_async(
            issuer_url,
            async_http_client,
        )
        .await
        .with_context(|| {
            format!("OIDC discovery failed for {}", cfg.issuer)
        })?;

        let end_session_url =
            metadata.additional_metadata().end_session_endpoint.clone();

        // CoreClient::from_provider_metadata accepts the Core
        // metadata type specifically.  Build the client directly from
        // the individual endpoints we need, which keeps us
        // independent of any future Core/Aloha-metadata divergence.
        let client = CoreClient::new(
            ClientId::new(cfg.client_id.clone()),
            cfg.client_secret.clone().map(ClientSecret::new),
            metadata.issuer().clone(),
            metadata.authorization_endpoint().clone(),
            metadata.token_endpoint().cloned(),
            metadata.userinfo_endpoint().cloned(),
            metadata.jwks().clone(),
        )
        .set_redirect_uri(
            RedirectUrl::new(cfg.redirect_uri.clone()).with_context(|| {
                format!("invalid redirect-uri: {}", cfg.redirect_uri)
            })?,
        );

        let provider = Arc::new(Self {
            client,
            state_ttl: Duration::from_secs(cfg.state_ttl_secs),
            refresh_ttl: Duration::from_secs(cfg.refresh_ttl_secs),
            cfg,
            states: Mutex::new(HashMap::new()),
            refreshes: Mutex::new(HashMap::new()),
            end_session_url,
        });

        // Periodic eviction of unfinished logins.  Without this the
        // state store would grow unboundedly if browsers abandon the
        // IdP redirect (closed tab, network failure, etc.).
        let weak = Arc::downgrade(&provider);
        let ttl = provider.state_ttl;
        tokio::spawn(async move {
            // Sweep at one-tenth of the TTL with a sensible floor so
            // entries are evicted promptly without busy-looping for
            // small TTLs.
            let interval = std::cmp::max(ttl / 10, Duration::from_secs(30));
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let Some(p) = weak.upgrade() else { break };
                p.evict_expired();
            }
        });

        Ok(provider)
    }

    /// Build the authorisation URL the browser should be redirected
    /// to.  Returns the URL plus the CSRF state id (mirrored back in
    /// the callback's query string).
    pub fn begin_login(&self, return_to: String) -> (url::Url, String) {
        let (pkce_challenge, pkce_verifier) =
            PkceCodeChallenge::new_random_sha256();

        let mut req = self.client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for scope in &self.cfg.scopes {
            req = req.add_scope(Scope::new(scope.clone()));
        }
        let (auth_url, csrf, nonce) =
            req.set_pkce_challenge(pkce_challenge).url();

        let state_id = csrf.secret().clone();
        let entry = StateEntry {
            pkce_verifier,
            nonce,
            return_to,
            created: Instant::now(),
        };
        self.states.lock().unwrap().insert(state_id.clone(), entry);

        (auth_url, state_id)
    }

    /// True when refresh-token support is enabled for this provider.
    pub fn refresh_enabled(&self) -> bool {
        self.cfg.refresh
    }

    /// Cookie name used to carry the opaque refresh-session id.
    pub fn refresh_cookie_name(&self) -> &str {
        &self.cfg.refresh_cookie_name
    }

    /// Sliding TTL applied to each refresh session, in seconds.
    pub fn refresh_ttl_secs(&self) -> u64 {
        self.cfg.refresh_ttl_secs
    }

    /// Path served as the in-browser logout endpoint.
    pub fn logout_path(&self) -> &str {
        &self.cfg.logout_path
    }

    /// Target the browser is redirected to after logout completes
    /// (whether the IdP-initiated branch ran or not).
    pub fn post_logout_uri(&self) -> &str {
        &self.cfg.post_logout_uri
    }

    /// When true, the logout endpoint bounces the browser through
    /// the IdP's `end_session_endpoint` if discovery exposed one.
    pub fn idp_logout_enabled(&self) -> bool {
        self.cfg.idp_logout
    }

    /// IdP's RP-initiated logout endpoint, if discovery surfaced it.
    pub fn end_session_url(&self) -> Option<&url::Url> {
        self.end_session_url.as_ref()
    }

    /// OAuth client id; passed as `client_id` query param on the
    /// end_session redirect for IdPs that accept it without an
    /// `id_token_hint`.
    pub fn client_id(&self) -> &str {
        &self.cfg.client_id
    }

    /// Drop the refresh entry matching `sid` and return its stored
    /// `id_token`.  Called by the logout endpoint to (a) tear down
    /// the server-side session and (b) recover the JWT to send back
    /// to the IdP as `id_token_hint`.  Returns `None` when no entry
    /// is present (e.g. the user opens the logout URL twice).
    pub fn take_logout_session(&self, sid: &str) -> Option<String> {
        self.refreshes.lock().unwrap().remove(sid).map(|e| e.id_token)
    }

    /// Exchange the authorisation code returned by the IdP for an ID
    /// token and verify it.  Returns the authenticated identity, the
    /// saved `return_to` URL, and (when refresh support is enabled
    /// and the IdP returned a refresh token) an opaque sid the caller
    /// should set in the refresh cookie.
    pub async fn complete_login(
        &self,
        code: String,
        state_id: &str,
    ) -> Result<(Identity, String, Option<String>)> {
        // Remove the entry first so a replayed callback can't reuse
        // the same PKCE verifier even if validation later fails.
        let entry = self
            .states
            .lock()
            .unwrap()
            .remove(state_id)
            .ok_or_else(|| anyhow!("unknown or expired OIDC state"))?;

        if entry.created.elapsed() > self.state_ttl {
            bail!("OIDC state expired before callback");
        }

        let token_response = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(entry.pkce_verifier)
            .request_async(async_http_client)
            .await
            .context("OIDC token exchange failed")?;

        let id_token = token_response
            .id_token()
            .ok_or_else(|| anyhow!("IdP response did not include an id_token"))?;
        let id_token_str = id_token.to_string();
        let claims = id_token
            .claims(&self.client.id_token_verifier(), &entry.nonce)
            .context("ID token validation failed")?;

        // The OIDC `sub` claim is always present and uniquely
        // identifies the user at this issuer.  When the operator
        // configures a different username claim (e.g.
        // `preferred_username`), we look it up via the additional
        // claims map — falling back to `sub` if absent.
        let extra = claims.additional_claims();
        let username = extract_string_claim(
            &self.cfg.username_claim,
            extra,
            claims.subject().as_str(),
        );
        let groups =
            extract_groups_claim(&self.cfg.groups_claim, extra);

        // Stash the refresh token (if any) under a fresh random sid.
        // The caller turns the sid into a long-lived HttpOnly cookie;
        // the refresh token itself never leaves the server.  The raw
        // ID token is stashed alongside it so the logout endpoint can
        // present it to the IdP as `id_token_hint`.
        let sid = if self.cfg.refresh {
            token_response.refresh_token().map(|rt| {
                let id = CsrfToken::new_random().secret().clone();
                self.refreshes.lock().unwrap().insert(
                    id.clone(),
                    RefreshEntry {
                        refresh_token: rt.clone(),
                        expires_at: Instant::now() + self.refresh_ttl,
                        id_token: id_token_str.clone(),
                    },
                );
                id
            })
        } else {
            None
        };

        Ok((Identity { username, groups }, entry.return_to, sid))
    }

    /// Use a stored refresh token to obtain a fresh ID token, re-
    /// derive the user's identity, and reset the sliding TTL.  When
    /// the IdP rotates the refresh token, the entry is re-keyed under
    /// a new sid; callers detect rotation by comparing the returned
    /// sid against the input.  Returns an error (and drops the entry)
    /// when the IdP rejects the refresh, e.g. because the underlying
    /// session has been revoked.
    pub async fn refresh(
        &self,
        sid: &str,
    ) -> Result<(Identity, String)> {
        let rt = {
            let map = self.refreshes.lock().unwrap();
            let entry = map.get(sid).ok_or_else(|| {
                anyhow!("unknown OIDC refresh session")
            })?;
            if Instant::now() > entry.expires_at {
                drop(map);
                self.refreshes.lock().unwrap().remove(sid);
                bail!("refresh session expired");
            }
            entry.refresh_token.clone()
        };

        let token_response = self
            .client
            .exchange_refresh_token(&rt)
            .request_async(async_http_client)
            .await
            .inspect_err(|_| {
                // The IdP's "no" is permanent for this token --
                // a revoked refresh token never becomes valid again.
                self.refreshes.lock().unwrap().remove(sid);
            })
            .context("OIDC refresh exchange failed")?;

        let id_token = token_response
            .id_token()
            .ok_or_else(|| anyhow!("refresh response had no id_token"))?;
        // OIDC Core §12.2 says the new id_token is OPTIONAL on
        // refresh -- but every IdP we care about returns one, and
        // without it we can't re-derive the user's identity, so
        // treat its absence as an error.  When it IS present we also
        // stash it for use as `id_token_hint` on logout.
        let new_id_token_str = id_token.to_string();
        // Per OIDC Core 1.0 §12.2 the nonce check is only required on
        // the initial authentication response; refresh responses are
        // bound to the prior session via the refresh token itself.
        let claims = id_token
            .claims(&self.client.id_token_verifier(), |_: Option<&Nonce>| Ok(()))
            .context("refreshed ID token validation failed")?;

        let extra = claims.additional_claims();
        let username = extract_string_claim(
            &self.cfg.username_claim,
            extra,
            claims.subject().as_str(),
        );
        let groups =
            extract_groups_claim(&self.cfg.groups_claim, extra);

        // Token rotation: when the IdP returns a new refresh token,
        // re-key the entry under a fresh sid.  The old sid stays
        // valid only long enough for this request's response to
        // arrive at the browser carrying the new cookie value.  The
        // id_token is always updated (some IdPs include a fresh one
        // even when keeping the refresh token, which is what we want
        // to send on logout).
        let new_sid = match token_response.refresh_token() {
            Some(new_rt) => {
                let id = CsrfToken::new_random().secret().clone();
                let mut map = self.refreshes.lock().unwrap();
                map.remove(sid);
                map.insert(
                    id.clone(),
                    RefreshEntry {
                        refresh_token: new_rt.clone(),
                        expires_at: Instant::now() + self.refresh_ttl,
                        id_token: new_id_token_str,
                    },
                );
                id
            }
            None => {
                // Same token still valid: just slide the TTL forward
                // and refresh the stored id_token alongside it.
                let mut map = self.refreshes.lock().unwrap();
                if let Some(e) = map.get_mut(sid) {
                    e.expires_at = Instant::now() + self.refresh_ttl;
                    e.id_token = new_id_token_str;
                }
                sid.to_owned()
            }
        };

        Ok((Identity { username, groups }, new_sid))
    }

    /// Path served as the in-browser login endpoint.
    pub fn login_path(&self) -> &str {
        &self.cfg.login_path
    }

    /// Path the IdP redirects to with the authorisation code.
    pub fn callback_path(&self) -> &str {
        &self.cfg.callback_path
    }

    fn evict_expired(&self) {
        let now = Instant::now();
        let ttl = self.state_ttl;
        self.states
            .lock()
            .unwrap()
            .retain(|_, e| now.duration_since(e.created) <= ttl);
        // Refresh sessions use absolute `expires_at` because the TTL
        // slides per refresh; states use a fixed-from-creation
        // window.  Both are bounded by config-level TTLs.
        self.refreshes
            .lock()
            .unwrap()
            .retain(|_, e| now <= e.expires_at);
    }

    #[cfg(test)]
    fn refresh_count(&self) -> usize {
        self.refreshes.lock().unwrap().len()
    }
}

/// Look up `name` in the ID token's additional-claims JSON object;
/// return its string value when present.  Falls back to `default`
/// when the claim is missing, not a string, or empty.
fn extract_string_claim(
    name: &str,
    extra: &openidconnect::EmptyAdditionalClaims,
    default: &str,
) -> String {
    // EmptyAdditionalClaims (the default) is opaque -- serialise it
    // to JSON and read the requested field.  This keeps the type
    // parameters trivial without having to plumb a custom claims
    // type through the whole library.
    let json = match serde_json::to_value(extra) {
        Ok(v) => v,
        Err(_) => return default.to_owned(),
    };
    match json.get(name).and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_owned(),
        _ => default.to_owned(),
    }
}

/// Read a groups claim from the additional-claims map.  Accepts both
/// a JSON array of strings and a single space-delimited string (the
/// shape SAML-style IdPs sometimes emit).  Returns an empty Vec when
/// the claim is missing or has neither shape.
fn extract_groups_claim(
    name: &str,
    extra: &openidconnect::EmptyAdditionalClaims,
) -> Vec<String> {
    let json = match serde_json::to_value(extra) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    match json.get(name) {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_owned()))
            .filter(|s| !s.is_empty())
            .collect(),
        Some(serde_json::Value::String(s)) => s
            .split_whitespace()
            .map(|w| w.to_owned())
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn empty() -> openidconnect::EmptyAdditionalClaims {
        openidconnect::EmptyAdditionalClaims {}
    }

    #[test]
    fn missing_groups_claim_returns_empty() {
        assert!(extract_groups_claim("groups", &empty()).is_empty());
    }

    #[test]
    fn missing_username_claim_falls_back_to_default() {
        let s = extract_string_claim("preferred_username", &empty(), "alice");
        assert_eq!(s, "alice");
    }

    // Build an OidcProvider without contacting the network, sufficient
    // for exercising the in-memory refresh store directly.  Discovery
    // and the OAuth client are sidestepped: tests only touch
    // `refreshes` via the refresh_count() helper and the public
    // `refresh()` failure paths exercised through unit code that
    // doesn't require an IdP.
    pub(crate) fn provider_for_store_with_end_session(
        ttl: Duration,
        end_session: url::Url,
    ) -> Arc<OidcProvider> {
        let p = provider_for_store(ttl);
        // Safe: only one Arc handle exists at construction time and
        // we haven't published it yet, so get_mut succeeds.
        let mut tmp = p;
        Arc::get_mut(&mut tmp).unwrap().end_session_url =
            Some(end_session);
        tmp
    }

    pub(crate) fn provider_for_store(ttl: Duration) -> Arc<OidcProvider> {
        // Use a minimal CoreClient that won't be invoked: the refresh
        // tests below only insert/inspect entries and verify
        // eviction.  Building a real client requires discovery, which
        // we intentionally avoid in unit tests.
        let cfg = crate::config::OidcConfig {
            issuer: "https://idp.example".into(),
            client_id: "id".into(),
            client_secret: None,
            redirect_uri: "https://app.example/cb".into(),
            scopes: vec!["openid".into()],
            username_claim: "sub".into(),
            groups_claim: "groups".into(),
            login_path: "/.aloha/oidc/login".into(),
            callback_path: "/.aloha/oidc/callback".into(),
            state_ttl_secs: 60,
            refresh: true,
            refresh_ttl_secs: ttl.as_secs(),
            refresh_cookie_name: "__aloha_oidc_refresh".into(),
            logout_path: "/.aloha/oidc/logout".into(),
            post_logout_uri: "/".into(),
            idp_logout: true,
        };
        let client = CoreClient::new(
            ClientId::new(cfg.client_id.clone()),
            None,
            IssuerUrl::new(cfg.issuer.clone()).unwrap(),
            openidconnect::AuthUrl::new(
                "https://idp.example/authorize".into(),
            )
            .unwrap(),
            None,
            None,
            openidconnect::JsonWebKeySet::new(vec![]),
        )
        .set_redirect_uri(RedirectUrl::new(cfg.redirect_uri.clone()).unwrap());
        Arc::new(OidcProvider {
            client,
            state_ttl: Duration::from_secs(cfg.state_ttl_secs),
            refresh_ttl: ttl,
            cfg,
            states: Mutex::new(HashMap::new()),
            refreshes: Mutex::new(HashMap::new()),
            end_session_url: None,
        })
    }

    #[test]
    fn refresh_store_evicts_expired_entries() {
        let p = provider_for_store(Duration::from_millis(1));
        p.refreshes.lock().unwrap().insert(
            "sid".into(),
            RefreshEntry {
                refresh_token: RefreshToken::new("rt".into()),
                // Already in the past.
                expires_at: Instant::now() - Duration::from_secs(1),
                id_token: "test".into(),
            },
        );
        assert_eq!(p.refresh_count(), 1);
        p.evict_expired();
        assert_eq!(p.refresh_count(), 0);
    }

    #[test]
    fn take_logout_session_returns_stored_id_token() {
        let p = provider_for_store(Duration::from_secs(60));
        p.refreshes.lock().unwrap().insert(
            "sid".into(),
            RefreshEntry {
                refresh_token: RefreshToken::new("rt".into()),
                expires_at: Instant::now() + Duration::from_secs(60),
                id_token: "the-id-token".into(),
            },
        );
        assert_eq!(
            p.take_logout_session("sid").as_deref(),
            Some("the-id-token"),
        );
        // Second call returns None: pop semantics.
        assert!(p.take_logout_session("sid").is_none());
        assert_eq!(p.refresh_count(), 0);
    }

    #[test]
    fn refresh_store_keeps_live_entries() {
        let p = provider_for_store(Duration::from_secs(60));
        p.refreshes.lock().unwrap().insert(
            "sid".into(),
            RefreshEntry {
                refresh_token: RefreshToken::new("rt".into()),
                expires_at: Instant::now() + Duration::from_secs(60),
                id_token: "test".into(),
            },
        );
        p.evict_expired();
        assert_eq!(p.refresh_count(), 1);
    }
}
