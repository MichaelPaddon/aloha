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
    CoreAuthenticationFlow, CoreClient, CoreProviderMetadata,
};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A pending login waiting for the IdP to redirect back to the
/// callback endpoint.
struct StateEntry {
    pkce_verifier: PkceCodeVerifier,
    nonce: Nonce,
    return_to: String,
    created: Instant,
}

/// Runtime handle for the configured OIDC IdP.  Constructed once at
/// startup; cloned via `Arc` into `AppState`.
pub struct OidcProvider {
    client: CoreClient,
    cfg: OidcConfig,
    states: Mutex<HashMap<String, StateEntry>>,
    state_ttl: Duration,
}

impl OidcProvider {
    /// Run OIDC discovery and build the runtime client.  Network
    /// failures bubble up; the caller decides whether to abort startup
    /// or retry in the background.
    pub async fn discover(cfg: OidcConfig) -> Result<Arc<Self>> {
        let issuer_url = IssuerUrl::new(cfg.issuer.clone())
            .with_context(|| format!("invalid OIDC issuer URL: {}", cfg.issuer))?;
        let metadata =
            CoreProviderMetadata::discover_async(issuer_url, async_http_client)
                .await
                .with_context(|| {
                    format!("OIDC discovery failed for {}", cfg.issuer)
                })?;

        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(cfg.client_id.clone()),
            cfg.client_secret.clone().map(ClientSecret::new),
        )
        .set_redirect_uri(
            RedirectUrl::new(cfg.redirect_uri.clone()).with_context(|| {
                format!("invalid redirect-uri: {}", cfg.redirect_uri)
            })?,
        );

        let provider = Arc::new(Self {
            client,
            state_ttl: Duration::from_secs(cfg.state_ttl_secs),
            cfg,
            states: Mutex::new(HashMap::new()),
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

    /// Exchange the authorisation code returned by the IdP for an ID
    /// token and verify it.  Returns the authenticated identity and
    /// the saved `return_to` URL.
    pub async fn complete_login(
        &self,
        code: String,
        state_id: &str,
    ) -> Result<(Identity, String)> {
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

        Ok((Identity { username, groups }, entry.return_to))
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
        let mut map = self.states.lock().unwrap();
        map.retain(|_, e| now.duration_since(e.created) <= ttl);
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
mod tests {
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
}
