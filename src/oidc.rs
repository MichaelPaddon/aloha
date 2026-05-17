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
use crate::metrics::Metrics;
use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwap;
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
    AccessToken, AdditionalProviderMetadata, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, ProviderMetadata, RedirectUrl,
    RefreshToken, Scope, TokenResponse, UserInfoClaims,
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
///
/// `client` and `end_session_url` are wrapped in `ArcSwap` so they
/// can be hot-swapped by the background refresh task without
/// requiring callers to hold a lock.  When discovery has not yet
/// completed (or has not yet succeeded), `client` is `None` and the
/// hot-path methods return a "not ready" error.
pub struct OidcProvider {
    client: ArcSwap<Option<Arc<CoreClient>>>,
    cfg: OidcConfig,
    metrics: Arc<Metrics>,
    states: Mutex<HashMap<String, StateEntry>>,
    state_ttl: Duration,
    // Refresh sessions; only populated when `cfg.refresh` is true.
    refreshes: Mutex<HashMap<String, RefreshEntry>>,
    refresh_ttl: Duration,
    // IdP's `end_session_endpoint` if exposed during discovery.
    // Without this, RP-initiated logout falls back to a local-only
    // cookie clear and a redirect to `post_logout_uri`.
    end_session_url: ArcSwap<Option<url::Url>>,
}

/// Single discovery attempt: build a fresh `CoreClient` and pluck
/// the optional `end_session_endpoint`.  Factored out so the
/// bootstrap path and the periodic-refresh path share exactly the
/// same construction logic.
async fn run_discovery(
    cfg: &OidcConfig,
) -> Result<(CoreClient, Option<url::Url>)> {
    let issuer_url = IssuerUrl::new(cfg.issuer.clone())
        .with_context(|| format!("invalid OIDC issuer URL: {}", cfg.issuer))?;
    let metadata = AlohaProviderMetadata::discover_async(
        issuer_url,
        async_http_client,
    )
    .await
    .with_context(|| format!("OIDC discovery failed for {}", cfg.issuer))?;

    let end_session_url =
        metadata.additional_metadata().end_session_endpoint.clone();

    // Build the client from individual endpoints rather than
    // CoreClient::from_provider_metadata so we stay independent of
    // any future Core/Aloha-metadata divergence.
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

    Ok((client, end_session_url))
}

impl OidcProvider {
    /// Construct an OIDC provider in a not-ready state and spawn
    /// background tasks for (1) initial discovery with retry and
    /// (2) periodic re-discovery for JWKS hot-swap.  Returns
    /// immediately; the provider becomes ready once the bootstrap
    /// task completes its first successful discovery.
    ///
    /// When `discovery-retry` is `#false` and the bootstrap call
    /// fails, the provider stays in the not-ready state and all
    /// endpoints serve 503.  This matches the user's explicit
    /// fail-fast request without crashing aloha; restart picks up
    /// the new IdP state.
    pub fn new(cfg: OidcConfig, metrics: Arc<Metrics>) -> Arc<Self> {
        let provider = Arc::new(Self {
            client: ArcSwap::new(Arc::new(None)),
            state_ttl: Duration::from_secs(cfg.state_ttl_secs),
            refresh_ttl: Duration::from_secs(cfg.refresh_ttl_secs),
            metrics,
            end_session_url: ArcSwap::new(Arc::new(None)),
            states: Mutex::new(HashMap::new()),
            refreshes: Mutex::new(HashMap::new()),
            cfg,
        });

        // Background discovery: exponential-backoff bootstrap, then
        // periodic refresh to pick up JWKS rotation at the IdP.
        let weak = Arc::downgrade(&provider);
        tokio::spawn(async move {
            let mut attempt: u32 = 0;
            // Bootstrap loop.
            loop {
                let Some(p) = weak.upgrade() else { return };
                match run_discovery(&p.cfg).await {
                    Ok((client, end_session)) => {
                        p.client.store(Arc::new(Some(Arc::new(client))));
                        p.end_session_url.store(Arc::new(end_session));
                        p.metrics.oidc_discoveries.fetch_add(
                            1,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        tracing::info!(
                            issuer = %p.cfg.issuer,
                            "oidc: discovery succeeded"
                        );
                        break;
                    }
                    Err(e) => {
                        p.metrics.oidc_discovery_failures.fetch_add(
                            1,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        if !p.cfg.discovery_retry {
                            tracing::error!(
                                issuer = %p.cfg.issuer,
                                error = %format!("{e:#}"),
                                "oidc: discovery failed (retry disabled); \
                                 provider will remain unavailable"
                            );
                            return;
                        }
                        // Cap backoff at 5 minutes.
                        let secs = std::cmp::min(1u64 << attempt.min(8), 300);
                        tracing::warn!(
                            issuer = %p.cfg.issuer,
                            retry_in = secs,
                            error = %format!("{e:#}"),
                            "oidc: discovery failed; retrying"
                        );
                        drop(p);
                        tokio::time::sleep(Duration::from_secs(secs)).await;
                        attempt = attempt.saturating_add(1);
                    }
                }
            }

            // Periodic refresh loop -- only runs after a successful
            // bootstrap, so failures here are silent and leave the
            // last-known-good client in place.  refresh=0 disables
            // the periodic path entirely.
            let Some(p) = weak.upgrade() else { return };
            let interval_secs = p.cfg.discovery_refresh_secs;
            drop(p);
            if interval_secs == 0 {
                return;
            }
            let mut ticker = tokio::time::interval(
                Duration::from_secs(interval_secs),
            );
            // Skip the immediate tick: we just completed discovery.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(p) = weak.upgrade() else { return };
                match run_discovery(&p.cfg).await {
                    Ok((client, end_session)) => {
                        p.client.store(Arc::new(Some(Arc::new(client))));
                        p.end_session_url.store(Arc::new(end_session));
                        p.metrics.oidc_discoveries.fetch_add(
                            1,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        tracing::debug!(
                            issuer = %p.cfg.issuer,
                            "oidc: discovery refreshed"
                        );
                    }
                    Err(e) => {
                        p.metrics.oidc_discovery_failures.fetch_add(
                            1,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        tracing::warn!(
                            issuer = %p.cfg.issuer,
                            error = %format!("{e:#}"),
                            "oidc: periodic discovery failed; \
                             keeping previous client"
                        );
                    }
                }
            }
        });

        // Periodic eviction of unfinished logins and expired refresh
        // entries.  Spawned separately from the discovery task so
        // their cadences are independent (eviction needs to run on
        // the order of state-ttl, discovery on the order of an hour).
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

        provider
    }

    /// Current OIDC client, if discovery has completed.  Hot-path
    /// methods bail with a "not ready" error when this returns
    /// `None`; the listener turns that into a 503 + `Retry-After`.
    pub fn client(&self) -> Option<Arc<CoreClient>> {
        self.client.load().as_ref().clone()
    }

    /// True when the OIDC provider has completed at least one
    /// successful discovery and is ready to handle login flows.
    pub fn is_ready(&self) -> bool {
        self.client.load().is_some()
    }

    /// Optionally fetch the IdP's `/userinfo` endpoint and merge its
    /// claims with the ones we already extracted from the ID token.
    /// UserInfo wins on non-empty values: the OIDC spec calls it the
    /// canonical source for non-essential claims.  A failed UserInfo
    /// request degrades to the ID-token values and logs a warning so
    /// login still succeeds.
    async fn merge_userinfo(
        &self,
        client: &CoreClient,
        access_token: &AccessToken,
        id_token_username: &str,
        id_token_groups: Vec<String>,
    ) -> (String, Vec<String>) {
        if !self.cfg.userinfo {
            return (id_token_username.to_owned(), id_token_groups);
        }
        let request = match client
            .user_info(access_token.clone(), None)
        {
            Ok(r) => r,
            Err(e) => {
                // Configuration-level error (no userinfo endpoint in
                // discovery, etc.).  Distinct from a network/HTTP
                // failure below; log once but don't keep retrying.
                tracing::warn!(
                    error = %format!("{e:#}"),
                    "oidc: userinfo not configurable for this IdP"
                );
                return (id_token_username.to_owned(), id_token_groups);
            }
        };
        let info: UserInfoClaims<
            openidconnect::EmptyAdditionalClaims,
            openidconnect::core::CoreGenderClaim,
        > = match request.request_async(async_http_client).await {
            Ok(c) => c,
            Err(e) => {
                self.metrics.oidc_userinfo_failures.fetch_add(
                    1,
                    std::sync::atomic::Ordering::Relaxed,
                );
                tracing::warn!(
                    error = %format!("{e:#}"),
                    "oidc: userinfo request failed; falling back \
                     to ID-token claims"
                );
                return (id_token_username.to_owned(), id_token_groups);
            }
        };

        // UserInfoClaims doesn't expose its extra fields directly;
        // round-trip through JSON, which is cheap and gives us the
        // same dynamic-claim access we already use on the ID token.
        let json = match serde_json::to_value(&info) {
            Ok(v) => v,
            Err(_) => return (id_token_username.to_owned(), id_token_groups),
        };
        // Reuse the same claim-extraction logic so configured
        // username-claim / groups-claim names work identically on
        // both surfaces.
        let username = match json
            .get(&self.cfg.username_claim)
            .and_then(|v| v.as_str())
        {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => id_token_username.to_owned(),
        };
        let groups = extract_groups_claim_from_json(
            &self.cfg.groups_claim,
            &json,
        );
        let groups = if groups.is_empty() {
            id_token_groups
        } else {
            groups
        };
        (username, groups)
    }

    /// Build the authorisation URL the browser should be
    /// redirected to.  Returns `None` when discovery has not yet
    /// completed; otherwise the URL plus the CSRF state id (mirrored
    /// back in the callback's query string).
    pub fn begin_login(
        &self,
        return_to: String,
    ) -> Option<(url::Url, String)> {
        let client = self.client()?;
        let (pkce_challenge, pkce_verifier) =
            PkceCodeChallenge::new_random_sha256();

        let mut req = client.authorize_url(
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

        Some((auth_url, state_id))
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
    /// Returned by value because the ArcSwap-backed storage rules out
    /// borrowing a stable reference; cloning a small `url::Url` is
    /// cheap and the call site happens once per logout request.
    pub fn end_session_url(&self) -> Option<url::Url> {
        (*self.end_session_url.load_full()).clone()
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
        let client = self
            .client()
            .ok_or_else(|| anyhow!("OIDC provider not ready"))?;

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

        let token_response = client
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
            .claims(&client.id_token_verifier(), &entry.nonce)
            .context("ID token validation failed")?;

        // The OIDC `sub` claim is always present and uniquely
        // identifies the user at this issuer.  When the operator
        // configures a different username claim (e.g.
        // `preferred_username`), we look it up via the additional
        // claims map — falling back to `sub` if absent.
        let extra = claims.additional_claims();
        let id_username = extract_string_claim(
            &self.cfg.username_claim,
            extra,
            claims.subject().as_str(),
        );
        let id_groups =
            extract_groups_claim(&self.cfg.groups_claim, extra);

        // UserInfo merge -- noop when the feature is off.  When on,
        // /userinfo claims take precedence on non-empty values.
        let (username, groups) = self
            .merge_userinfo(
                &client,
                token_response.access_token(),
                &id_username,
                id_groups,
            )
            .await;

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
        let client = self
            .client()
            .ok_or_else(|| anyhow!("OIDC provider not ready"))?;
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

        let token_response = client
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
            .claims(&client.id_token_verifier(), |_: Option<&Nonce>| Ok(()))
            .context("refreshed ID token validation failed")?;

        let extra = claims.additional_claims();
        let id_username = extract_string_claim(
            &self.cfg.username_claim,
            extra,
            claims.subject().as_str(),
        );
        let id_groups =
            extract_groups_claim(&self.cfg.groups_claim, extra);

        // UserInfo merge against the freshly-issued access token.
        let (username, groups) = self
            .merge_userinfo(
                &client,
                token_response.access_token(),
                &id_username,
                id_groups,
            )
            .await;

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
    extract_groups_claim_from_json(name, &json)
}

/// Same as `extract_groups_claim` but reads directly from a
/// serialised JSON value.  Used by the UserInfo merge path which
/// already has the full claim document in hand.
fn extract_groups_claim_from_json(
    name: &str,
    json: &serde_json::Value,
) -> Vec<String> {
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
        p.end_session_url.store(Arc::new(Some(end_session)));
        p
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
            userinfo: false,
            discovery_refresh_secs: 0,
            discovery_retry: true,
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
            client: ArcSwap::new(Arc::new(Some(Arc::new(client)))),
            state_ttl: Duration::from_secs(cfg.state_ttl_secs),
            refresh_ttl: ttl,
            metrics: Arc::new(Metrics::new()),
            cfg,
            states: Mutex::new(HashMap::new()),
            refreshes: Mutex::new(HashMap::new()),
            end_session_url: ArcSwap::new(Arc::new(None)),
        })
    }

    #[test]
    fn provider_new_starts_in_not_ready_state() {
        // Issuer points at a non-routable address so background
        // discovery cannot succeed before this synchronous assert
        // runs.  The contract under test: new() is synchronous and
        // returns a provider that is_ready() == false until the
        // background bootstrap completes.
        let cfg = crate::config::OidcConfig {
            issuer: "https://127.0.0.1:1/".into(),
            client_id: "id".into(),
            client_secret: None,
            redirect_uri: "https://app.example/cb".into(),
            scopes: vec!["openid".into()],
            username_claim: "sub".into(),
            groups_claim: "groups".into(),
            login_path: "/.aloha/oidc/login".into(),
            callback_path: "/.aloha/oidc/callback".into(),
            state_ttl_secs: 60,
            refresh: false,
            refresh_ttl_secs: 60,
            refresh_cookie_name: "__aloha_oidc_refresh".into(),
            logout_path: "/.aloha/oidc/logout".into(),
            post_logout_uri: "/".into(),
            idp_logout: false,
            userinfo: false,
            discovery_refresh_secs: 0,
            // Disable retry so the background task exits promptly
            // when discovery fails -- prevents the test runtime
            // from spinning on retries.
            discovery_retry: false,
        };
        // OidcProvider::new spawns a tokio task, so we need a runtime.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let p = OidcProvider::new(cfg, Arc::new(Metrics::new()));
            assert!(!p.is_ready());
            assert!(p.client().is_none());
        });
    }

    #[test]
    fn userinfo_merge_disabled_returns_id_token_values() {
        // With userinfo off, the helper must short-circuit before
        // touching the network -- the dummy CoreClient stored on
        // provider_for_store would fail any real call.
        let p = provider_for_store(Duration::from_secs(60));
        let client = p.client().expect("test provider has a client");
        let access = openidconnect::AccessToken::new("at".into());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (user, groups) = rt.block_on(p.merge_userinfo(
            &client,
            &access,
            "alice",
            vec!["devs".into()],
        ));
        assert_eq!(user, "alice");
        assert_eq!(groups, vec!["devs".to_string()]);
    }

    #[test]
    fn extract_groups_claim_from_json_array_and_string() {
        // Array form (Keycloak/Authelia).
        let v = serde_json::json!({"groups": ["admins", "devs"]});
        assert_eq!(
            extract_groups_claim_from_json("groups", &v),
            vec!["admins", "devs"],
        );
        // Space-delimited string form (some SAML-style IdPs).
        let v = serde_json::json!({"groups": "admins devs"});
        assert_eq!(
            extract_groups_claim_from_json("groups", &v),
            vec!["admins", "devs"],
        );
        // Missing.
        let v = serde_json::json!({});
        assert!(extract_groups_claim_from_json("groups", &v).is_empty());
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
