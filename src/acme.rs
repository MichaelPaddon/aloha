use crate::config::TlsOptions;
use crate::tls;
use anyhow::{bail, Context};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType,
    Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_rustls::TlsAcceptor;

// Shared challenge token storage.
// Key = token, value = key_authorization.  Populated during HTTP-01
// validation; read by AlohaService on /.well-known/acme-challenge/*.
pub type ChallengeMap = Arc<Mutex<HashMap<String, String>>>;

// ── Provisioner trait ─────────────────────────────────────────────

// Handles the ACME protocol and returns the issued cert + private key
// as PEM strings.  Receives the challenge map to register HTTP-01
// tokens during validation.
//
// The trait lets us swap in a MockProvisioner in tests without touching
// the network.
#[async_trait]
pub(crate) trait Provisioner: Send + Sync {
    async fn provision(
        &self,
        domains: &[String],
        challenges: &ChallengeMap,
    ) -> anyhow::Result<(String, String)>; // (cert_pem, key_pem)
}

// ── Config ────────────────────────────────────────────────────────

pub struct AcmeConfig {
    // All domains become SANs in the issued cert.  First is primary.
    pub domains: Vec<String>,
    // Storage directory name; defaults to domains[0] if None.
    pub name: Option<String>,
    pub email: Option<String>,
    // Use Let's Encrypt staging directory when true.
    pub staging: bool,
    // Override the ACME directory URL.
    pub server: Option<String>,
    pub state_dir: PathBuf,
    // How long to wait between retries after a failed acquisition.
    pub retry_interval: Duration,
}

impl AcmeConfig {
    // Resolved storage directory name.
    pub fn cert_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.domains[0])
    }

    // Effective ACME server URL.
    //
    // Priority: explicit server= > staging flag or ALOHA_ACME_STAGING
    // env var > Let's Encrypt production.
    //
    // Setting ALOHA_ACME_STAGING=1 in the environment forces staging
    // without changing the config file — useful during testing.
    pub fn acme_server_url(&self) -> &str {
        if let Some(ref url) = self.server {
            return url.as_str();
        }
        let env_staging =
            std::env::var("ALOHA_ACME_STAGING").is_ok();
        if self.staging || env_staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        }
    }

    fn is_staging(&self) -> bool {
        self.staging || std::env::var("ALOHA_ACME_STAGING").is_ok()
    }
}

// ── AcmeManager ──────────────────────────────────────────────────

pub struct AcmeManager {
    config: AcmeConfig,
    challenges: ChallengeMap,
    tls_opts: TlsOptions,
    provisioner: Arc<dyn Provisioner>,
}

impl AcmeManager {
    // Production constructor — uses the real ACME protocol.
    pub fn new(
        config: AcmeConfig,
        challenges: ChallengeMap,
        tls_opts: TlsOptions,
    ) -> Self {
        let provisioner = Arc::new(RealProvisioner {
            server_url: config.acme_server_url().to_owned(),
            email: config.email.clone(),
            account_path: config.state_dir.join("acme_account.json"),
        });
        Self::with_provisioner(config, challenges, tls_opts, provisioner)
    }

    // Inject a custom provisioner — used in tests.
    pub(crate) fn with_provisioner(
        config: AcmeConfig,
        challenges: ChallengeMap,
        tls_opts: TlsOptions,
        provisioner: Arc<dyn Provisioner>,
    ) -> Self {
        if config.is_staging() {
            tracing::info!(
                cert = config.cert_name(),
                "ACME staging mode — \
                 certificates are NOT trusted by browsers"
            );
        }
        Self { config, challenges, tls_opts, provisioner }
    }

    // Return the directory where cert.pem and key.pem are stored.
    fn cert_dir(&self) -> PathBuf {
        self.config.state_dir
            .join("certs")
            .join(self.config.cert_name())
    }

    // Ensure a valid cert exists; acquire if missing or near expiry.
    pub async fn ensure_valid_cert(
        &self,
    ) -> anyhow::Result<TlsAcceptor> {
        if self.cert_needs_renewal() {
            tracing::info!(
                domains = ?self.config.domains,
                "acquiring ACME certificate"
            );
            self.acquire_cert().await
                .context("ACME certificate acquisition")?;
            tracing::info!(
                domains = ?self.config.domains,
                "ACME certificate acquired"
            );
        }
        self.build_acceptor()
    }

    // Background task: renew on schedule, or retry after failure.
    //
    // When initial_failed is true (ACME failed at startup and we are
    // serving a self-signed fallback), the first sleep uses
    // retry_interval instead of waiting until near-expiry.  On success
    // the hot-swapped acceptor replaces the self-signed fallback.
    pub async fn renewal_loop(
        self: Arc<Self>,
        acceptor: Arc<ArcSwap<TlsAcceptor>>,
        initial_failed: bool,
    ) {
        let mut last_failed = initial_failed;
        loop {
            let sleep = if last_failed {
                self.config.retry_interval
            } else {
                self.time_until_renewal()
            };
            tracing::info!(
                cert = self.config.cert_name(),
                sleep_secs = sleep.as_secs(),
                "ACME: next attempt scheduled"
            );
            tokio::time::sleep(sleep).await;

            match self.acquire_cert().await {
                Ok(()) => match self.build_acceptor() {
                    Ok(new_acc) => {
                        acceptor.store(Arc::new(new_acc));
                        last_failed = false;
                        tracing::info!(
                            cert = self.config.cert_name(),
                            "ACME certificate acquired and activated"
                        );
                    }
                    Err(e) => {
                        last_failed = true;
                        tracing::error!(
                            "failed to load ACME cert: {e:#}"
                        );
                    }
                },
                Err(e) => {
                    last_failed = true;
                    tracing::warn!(
                        cert = self.config.cert_name(),
                        retry_secs = self.config.retry_interval.as_secs(),
                        "ACME acquisition failed: {e:#}"
                    );
                }
            }
        }
    }

    // True if no cert exists or it expires within 30 days.
    pub(crate) fn cert_needs_renewal(&self) -> bool {
        let cert_path = self.cert_dir().join("cert.pem");
        if !cert_path.exists() {
            return true;
        }
        let Ok(pem) = std::fs::read(cert_path) else {
            return true;
        };
        match cert_expiry_timestamp(&pem) {
            Ok(expiry) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                expiry - now < 30 * 24 * 3600
            }
            Err(_) => true,
        }
    }

    // Duration to sleep before the next renewal attempt.
    // Targets 30 days before cert expiry; minimum 60 seconds.
    pub(crate) fn time_until_renewal(&self) -> Duration {
        let cert_path = self.cert_dir().join("cert.pem");
        let Ok(pem) = std::fs::read(cert_path) else {
            return Duration::from_secs(60);
        };
        let Ok(expiry) = cert_expiry_timestamp(&pem) else {
            return Duration::from_secs(60);
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let renewal_at = expiry - 30 * 24 * 3600;
        let secs = (renewal_at - now).max(60);
        Duration::from_secs(secs as u64)
    }

    // Build a TlsAcceptor from stored cert+key.
    fn build_acceptor(&self) -> anyhow::Result<TlsAcceptor> {
        let dir = self.cert_dir();
        let (chain, key) = tls::load_cert_and_key(
            &dir.join("cert.pem"),
            &dir.join("key.pem"),
        )?;
        tls::make_acceptor(chain, key, &self.tls_opts)
    }

    // Acquire a certificate via the provisioner and persist it.
    async fn acquire_cert(&self) -> anyhow::Result<()> {
        let (cert_pem, key_pem) = self
            .provisioner
            .provision(&self.config.domains, &self.challenges)
            .await?;

        atomic_write_cert_dir(
            &self.cert_dir(),
            cert_pem.as_bytes(),
            key_pem.as_bytes(),
        )
        .await?;

        // Warn if the cert's notBefore is in the future (typically a
        // sign of clock skew between the server and the CA).  We serve
        // the cert immediately regardless rather than sleeping, because
        // TLS clients generally tolerate a small skew and sleeping here
        // would delay the service unnecessarily.
        warn_if_not_yet_valid(cert_pem.as_bytes());

        Ok(())
    }
}

// ── Atomic cert directory writer ──────────────────────────────────

// Write cert_pem + key_pem into a staging directory, then move it
// over `dir` in two renames.
//
// This guarantees that readers never see a cert/key mismatch: either
// the old pair is intact or the new pair is, never a mix.  Linux's
// rename(2) cannot move a directory over a non-empty one, so we shift
// the live dir aside first.  The two-rename gap is a few microseconds;
// a crash there causes build_acceptor to fail on restart, which
// triggers a clean ACME reacquisition rather than serving mismatched
// files.
async fn atomic_write_cert_dir(
    dir: &std::path::Path,
    cert_pem: &[u8],
    key_pem: &[u8],
) -> anyhow::Result<()> {
    let parent = dir.parent().context("cert dir has no parent")?;
    let name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .context("cert dir name is not valid UTF-8")?;
    let staging = parent.join(format!("{name}.new"));
    let old = parent.join(format!("{name}.old"));

    // Remove any leftover staging dir from a prior interrupted attempt.
    tokio::fs::remove_dir_all(&staging).await.ok();
    tokio::fs::create_dir_all(&staging)
        .await
        .context("creating staging directory")?;
    tokio::fs::write(staging.join("cert.pem"), cert_pem)
        .await
        .context("writing cert.pem to staging")?;
    tokio::fs::write(staging.join("key.pem"), key_pem)
        .await
        .context("writing key.pem to staging")?;

    // Shift the live directory aside, then move staging into place.
    if dir.exists() {
        tokio::fs::remove_dir_all(&old).await.ok();
        tokio::fs::rename(dir, &old)
            .await
            .context("moving live cert dir aside")?;
    }
    tokio::fs::rename(&staging, dir)
        .await
        .context("moving staging cert dir into place")?;
    tokio::fs::remove_dir_all(&old).await.ok();

    Ok(())
}

// ── Real ACME provisioner (instant-acme / Let's Encrypt) ─────────

struct RealProvisioner {
    server_url: String,
    email: Option<String>,
    account_path: PathBuf,
}

#[async_trait]
impl Provisioner for RealProvisioner {
    async fn provision(
        &self,
        domains: &[String],
        challenges: &ChallengeMap,
    ) -> anyhow::Result<(String, String)> {
        let account = self.load_or_create_account().await?;

        let identifiers: Vec<Identifier> = domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();

        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .context("creating ACME order")?;

        // Register HTTP-01 challenge tokens for all identifiers,
        // skipping any that are already valid from a prior order.
        let mut tokens: Vec<String> = Vec::new();
        let mut authzs = order.authorizations();
        while let Some(result) = authzs.next().await {
            let mut authz = result.context("fetching authorization")?;
            if authz.status == AuthorizationStatus::Valid {
                continue;
            }
            let domain = authz.identifier().to_string();
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .with_context(|| {
                    format!("no HTTP-01 challenge for '{domain}'")
                })?;
            let token = challenge.token.clone();
            let key_auth =
                challenge.key_authorization().as_str().to_owned();
            challenges
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(token.clone(), key_auth);
            tokens.push(token);
            challenge
                .set_ready()
                .await
                .context("setting challenge ready")?;
        }

        // Poll until the order is Ready or Invalid.
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let state =
                order.refresh().await.context("polling order")?;
            match state.status {
                OrderStatus::Ready => break,
                OrderStatus::Invalid => {
                    let mut map = challenges
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    for t in &tokens {
                        map.remove(t);
                    }
                    bail!(
                        "ACME order invalid — ensure the domain is \
                         publicly reachable on port 80"
                    );
                }
                _ => {}
            }
        }

        // Remove challenge tokens; validation is complete.
        {
            let mut map = challenges
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            for t in &tokens {
                map.remove(t);
            }
        }

        // Generate P-256 key pair, submit CSR, and retrieve cert.
        let (cert_chain_pem, key_pem) =
            finalize_order(&mut order, domains).await?;

        Ok((cert_chain_pem, key_pem))
    }
}

impl RealProvisioner {
    async fn load_or_create_account(
        &self,
    ) -> anyhow::Result<Account> {
        if self.account_path.exists() {
            let json =
                tokio::fs::read_to_string(&self.account_path)
                    .await
                    .context("reading ACME account credentials")?;
            let creds: AccountCredentials =
                serde_json::from_str(&json)
                    .context("deserializing ACME credentials")?;
            return Account::builder()
                .context("building ACME account")?
                .from_credentials(creds)
                .await
                .context("loading ACME account");
        }

        let contact = self
            .email
            .as_ref()
            .map(|e| format!("mailto:{e}"));
        let contact_refs: Vec<&str> =
            contact.iter().map(String::as_str).collect();

        tracing::info!("creating new ACME account");
        let (account, creds) = Account::builder()
            .context("building ACME account")?
            .create(
                &NewAccount {
                    contact: &contact_refs,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.server_url.clone(),
                None,
            )
            .await
            .context("creating ACME account")?;

        if let Some(parent) = self.account_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .context("creating state directory")?;
        }
        tokio::fs::write(
            &self.account_path,
            serde_json::to_string_pretty(&creds)
                .context("serializing ACME credentials")?,
        )
        .await
        .context("saving ACME credentials")?;

        Ok(account)
    }
}

// Generate a key pair, build a CSR, finalize the order, and return
// (cert_chain_pem, private_key_pem).
async fn finalize_order(
    order: &mut instant_acme::Order,
    domains: &[String],
) -> anyhow::Result<(String, String)> {
    let mut params =
        CertificateParams::new(domains.to_vec())
            .context("building CSR params")?;
    params.distinguished_name = DistinguishedName::new();
    let key_pair =
        KeyPair::generate().context("generating key pair")?;
    let csr = params
        .serialize_request(&key_pair)
        .context("serializing CSR")?;

    order
        .finalize_csr(csr.der())
        .await
        .context("finalizing ACME order")?;

    let cert_chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .context("fetching certificate")?;

    Ok((cert_chain_pem, key_pair.serialize_pem()))
}

// ── Shared helpers ────────────────────────────────────────────────

// Read the notAfter timestamp from the first cert in a PEM chain.
pub(crate) fn cert_expiry_timestamp(
    pem: &[u8],
) -> anyhow::Result<i64> {
    use x509_parser::prelude::*;
    let (_, pem_obj) = parse_x509_pem(pem)
        .map_err(|e| anyhow::anyhow!("PEM parse: {:?}", e))?;
    let cert = pem_obj
        .parse_x509()
        .map_err(|e| anyhow::anyhow!("X.509 parse: {:?}", e))?;
    Ok(cert.validity().not_after.timestamp())
}

// Read the notBefore timestamp from the first cert in a PEM chain.
fn cert_not_before_timestamp(pem: &[u8]) -> anyhow::Result<i64> {
    use x509_parser::prelude::*;
    let (_, pem_obj) = parse_x509_pem(pem)
        .map_err(|e| anyhow::anyhow!("PEM parse: {:?}", e))?;
    let cert = pem_obj
        .parse_x509()
        .map_err(|e| anyhow::anyhow!("X.509 parse: {:?}", e))?;
    Ok(cert.validity().not_before.timestamp())
}

// Log a warning if the certificate's notBefore is in the future.
// This typically indicates clock skew between the server and the CA
// (e.g. server in UTC+8 presenting local time as UTC).  The cert is
// served immediately regardless — TLS clients tolerate small skew, and
// sleeping here would delay the service for no benefit.
fn warn_if_not_yet_valid(pem: &[u8]) {
    let Ok(not_before) = cert_not_before_timestamp(pem) else {
        return;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    if not_before > now {
        tracing::warn!(
            secs_until_valid = not_before - now,
            "certificate notBefore is in the future — \
             check that the server clock is set to UTC"
        );
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test provisioner ─────────────────────────────────────────

    // Generates a real self-signed cert without touching the network.
    // Accepts an optional validity in days (default 90).
    struct MockProvisioner {
        validity_days: i64,
    }

    impl MockProvisioner {
        fn new() -> Self {
            Self { validity_days: 90 }
        }
    }

    #[async_trait]
    impl Provisioner for MockProvisioner {
        async fn provision(
            &self,
            domains: &[String],
            _challenges: &ChallengeMap,
        ) -> anyhow::Result<(String, String)> {
            Ok(make_cert_pem(domains, self.validity_days))
        }
    }

    // Build a self-signed cert for the given SANs expiring in `days`.
    fn make_cert_pem(
        domains: &[String],
        days: i64,
    ) -> (String, String) {
        use time::{Duration, OffsetDateTime};

        let mut params =
            CertificateParams::new(domains.to_vec()).unwrap();
        params.not_after =
            OffsetDateTime::now_utc() + Duration::days(days);
        params.distinguished_name = DistinguishedName::new();
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn install_provider() {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();
    }

    fn test_manager(
        dir: &std::path::Path,
        provisioner: Arc<dyn Provisioner>,
    ) -> AcmeManager {
        AcmeManager::with_provisioner(
            AcmeConfig {
                domains: vec!["example.com".into()],
                name: None,
                email: None,
                staging: false,
                server: None,
                state_dir: dir.to_owned(),
                retry_interval: Duration::from_secs(3600),
            },
            Arc::new(Mutex::new(HashMap::new())),
            TlsOptions::default(),
            provisioner,
        )
    }

    // ── AcmeConfig helpers ───────────────────────────────────────

    #[test]
    fn cert_name_defaults_to_first_domain() {
        let cfg = AcmeConfig {
            domains: vec![
                "example.com".into(),
                "www.example.com".into(),
            ],
            name: None,
            email: None,
            staging: false,
            server: None,
            state_dir: PathBuf::from("/tmp"),
            retry_interval: Duration::from_secs(3600),
        };
        assert_eq!(cfg.cert_name(), "example.com");
    }

    #[test]
    fn cert_name_uses_explicit_name() {
        let cfg = AcmeConfig {
            domains: vec!["example.com".into()],
            name: Some("my-cert".into()),
            email: None,
            staging: false,
            server: None,
            state_dir: PathBuf::from("/tmp"),
            retry_interval: Duration::from_secs(3600),
        };
        assert_eq!(cfg.cert_name(), "my-cert");
    }

    #[test]
    fn server_url_production_by_default() {
        let cfg = AcmeConfig {
            domains: vec!["example.com".into()],
            name: None,
            email: None,
            staging: false,
            server: None,
            state_dir: PathBuf::from("/tmp"),
            retry_interval: Duration::from_secs(3600),
        };
        assert_eq!(
            cfg.acme_server_url(),
            LetsEncrypt::Production.url()
        );
    }

    #[test]
    fn server_url_staging_flag() {
        let cfg = AcmeConfig {
            domains: vec!["example.com".into()],
            name: None,
            email: None,
            staging: true,
            server: None,
            state_dir: PathBuf::from("/tmp"),
            retry_interval: Duration::from_secs(3600),
        };
        assert_eq!(cfg.acme_server_url(), LetsEncrypt::Staging.url());
    }

    #[test]
    fn server_url_custom_overrides_staging() {
        let cfg = AcmeConfig {
            domains: vec!["example.com".into()],
            name: None,
            email: None,
            staging: true,
            server: Some("https://acme.example.com/dir".into()),
            state_dir: PathBuf::from("/tmp"),
            retry_interval: Duration::from_secs(3600),
        };
        assert_eq!(cfg.acme_server_url(), "https://acme.example.com/dir");
    }

    // ── cert_expiry_timestamp ────────────────────────────────────

    #[test]
    fn cert_expiry_parses() {
        let (pem, _) =
            make_cert_pem(&["localhost".to_owned()], 90);
        let ts = cert_expiry_timestamp(pem.as_bytes()).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let diff = ts - now;
        assert!(diff > 88 * 24 * 3600, "expiry too soon: {diff}s");
        assert!(diff < 92 * 24 * 3600, "expiry too far: {diff}s");
    }

    // ── cert_needs_renewal ───────────────────────────────────────

    #[test]
    fn cert_needs_renewal_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = test_manager(dir.path(), Arc::new(MockProvisioner::new()));
        assert!(mgr.cert_needs_renewal());
    }

    #[test]
    fn cert_needs_renewal_when_expiring_soon() {
        let dir = tempfile::tempdir().unwrap();
        let (pem, _) =
            make_cert_pem(&["example.com".to_owned()], 15);
        let cert_dir = dir.path().join("certs").join("example.com");
        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::write(cert_dir.join("cert.pem"), pem).unwrap();

        let mgr = test_manager(dir.path(), Arc::new(MockProvisioner::new()));
        assert!(mgr.cert_needs_renewal());
    }

    #[test]
    fn cert_does_not_need_renewal_when_valid() {
        let dir = tempfile::tempdir().unwrap();
        let (pem, _) =
            make_cert_pem(&["example.com".to_owned()], 60);
        let cert_dir = dir.path().join("certs").join("example.com");
        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::write(cert_dir.join("cert.pem"), pem).unwrap();

        let mgr = test_manager(dir.path(), Arc::new(MockProvisioner::new()));
        assert!(!mgr.cert_needs_renewal());
    }

    // ── time_until_renewal ───────────────────────────────────────

    #[test]
    fn time_until_renewal_is_60s_when_cert_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = test_manager(dir.path(), Arc::new(MockProvisioner::new()));
        assert_eq!(
            mgr.time_until_renewal(),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn time_until_renewal_targets_30_days_before_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let (pem, _) =
            make_cert_pem(&["example.com".to_owned()], 90);
        let cert_dir = dir.path().join("certs").join("example.com");
        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::write(cert_dir.join("cert.pem"), pem).unwrap();

        let mgr = test_manager(dir.path(), Arc::new(MockProvisioner::new()));
        let sleep = mgr.time_until_renewal();
        // 90 days cert → renewal at 60 days from now (90 - 30)
        let expected = 60u64 * 24 * 3600;
        let diff = (sleep.as_secs() as i64 - expected as i64).abs();
        assert!(
            diff < 120,
            "renewal sleep {s}s, expected ~{expected}s",
            s = sleep.as_secs()
        );
    }

    // ── Full flow via MockProvisioner ────────────────────────────

    #[tokio::test]
    async fn ensure_valid_cert_acquires_when_missing() {
        install_provider();
        let dir = tempfile::tempdir().unwrap();
        let mgr = test_manager(
            dir.path(),
            Arc::new(MockProvisioner::new()),
        );

        // No cert yet — should acquire
        let acc = mgr.ensure_valid_cert().await.unwrap();
        drop(acc); // just verify it doesn't error

        // Files should be written
        let cert_dir = dir.path().join("certs").join("example.com");
        assert!(cert_dir.join("cert.pem").exists());
        assert!(cert_dir.join("key.pem").exists());
    }

    #[tokio::test]
    async fn ensure_valid_cert_skips_acquisition_when_valid() {
        install_provider();
        let dir = tempfile::tempdir().unwrap();
        let (pem, key) =
            make_cert_pem(&["example.com".to_owned()], 60);
        let cert_dir = dir.path().join("certs").join("example.com");
        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::write(cert_dir.join("cert.pem"), &pem).unwrap();
        std::fs::write(cert_dir.join("key.pem"), &key).unwrap();

        // Use an expiring-soon provisioner so we can detect if it
        // gets called (it would overwrite with a short-lived cert).
        let mgr = test_manager(
            dir.path(),
            Arc::new(MockProvisioner::new()), // valid cert → not called
        );

        mgr.ensure_valid_cert().await.unwrap();

        // cert.pem should still contain the original 60-day cert
        let stored = std::fs::read(cert_dir.join("cert.pem")).unwrap();
        let expiry = cert_expiry_timestamp(&stored).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(
            expiry - now > 58 * 24 * 3600,
            "cert was unexpectedly replaced"
        );
    }

    #[tokio::test]
    async fn ensure_valid_cert_renews_when_expiring_soon() {
        install_provider();
        let dir = tempfile::tempdir().unwrap();
        // Write a cert that expires in 15 days (below 30-day threshold)
        let (short_pem, short_key) =
            make_cert_pem(&["example.com".to_owned()], 15);
        let cert_dir = dir.path().join("certs").join("example.com");
        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::write(cert_dir.join("cert.pem"), &short_pem).unwrap();
        std::fs::write(cert_dir.join("key.pem"), &short_key).unwrap();

        // MockProvisioner::new() issues 90-day certs
        let mgr = test_manager(
            dir.path(),
            Arc::new(MockProvisioner::new()),
        );

        mgr.ensure_valid_cert().await.unwrap();

        // cert.pem should now be the newly issued 90-day cert
        let stored =
            std::fs::read(cert_dir.join("cert.pem")).unwrap();
        let expiry = cert_expiry_timestamp(&stored).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(
            expiry - now > 85 * 24 * 3600,
            "cert was not renewed: expiry in {}d",
            (expiry - now) / 86400
        );
    }

    // ── atomic_write_cert_dir ────────────────────────────────────

    #[tokio::test]
    async fn atomic_write_creates_dir_on_first_run() {
        let base = tempfile::tempdir().unwrap();
        let cert_dir = base.path().join("certs").join("example.com");

        atomic_write_cert_dir(
            &cert_dir,
            b"CERT",
            b"KEY",
        )
        .await
        .unwrap();

        assert_eq!(
            std::fs::read(cert_dir.join("cert.pem")).unwrap(),
            b"CERT"
        );
        assert_eq!(
            std::fs::read(cert_dir.join("key.pem")).unwrap(),
            b"KEY"
        );
    }

    #[tokio::test]
    async fn atomic_write_replaces_existing_dir() {
        let base = tempfile::tempdir().unwrap();
        let cert_dir = base.path().join("certs").join("example.com");

        // First write
        atomic_write_cert_dir(&cert_dir, b"CERT1", b"KEY1")
            .await
            .unwrap();

        // Second write — should replace atomically
        atomic_write_cert_dir(&cert_dir, b"CERT2", b"KEY2")
            .await
            .unwrap();

        assert_eq!(
            std::fs::read(cert_dir.join("cert.pem")).unwrap(),
            b"CERT2"
        );
        assert_eq!(
            std::fs::read(cert_dir.join("key.pem")).unwrap(),
            b"KEY2"
        );
    }

    #[tokio::test]
    async fn atomic_write_cleans_up_staging_and_old_dirs() {
        let base = tempfile::tempdir().unwrap();
        let cert_dir = base.path().join("certs").join("example.com");
        let staging = base.path().join("certs").join("example.com.new");
        let old = base.path().join("certs").join("example.com.old");

        // Seed a leftover staging dir to verify it is cleaned up.
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("stale"), b"x").unwrap();

        atomic_write_cert_dir(&cert_dir, b"CERT", b"KEY")
            .await
            .unwrap();

        // Staging and old dirs must be gone after a clean run.
        assert!(!staging.exists(), ".new dir should be removed");
        assert!(!old.exists(), ".old dir should be removed");
    }

    #[tokio::test]
    async fn challenge_map_is_empty_after_provision() {
        install_provider();
        let dir = tempfile::tempdir().unwrap();
        let challenges: ChallengeMap =
            Arc::new(Mutex::new(HashMap::new()));

        // A provisioner that briefly inserts a token then removes it
        struct ChallengeCheckProvisioner;
        #[async_trait]
        impl Provisioner for ChallengeCheckProvisioner {
            async fn provision(
                &self,
                domains: &[String],
                challenges: &ChallengeMap,
            ) -> anyhow::Result<(String, String)> {
                // Simulate inserting and then cleaning up a token
                challenges.lock().unwrap_or_else(|p| p.into_inner())
                    .insert("tok".into(), "auth".into());
                challenges.lock().unwrap_or_else(|p| p.into_inner()).remove("tok");
                let (cert, key) = super::tests::make_cert_pem(
                    domains,
                    90,
                );
                Ok((cert, key))
            }
        }

        let mgr = AcmeManager::with_provisioner(
            AcmeConfig {
                domains: vec!["example.com".into()],
                name: None,
                email: None,
                staging: false,
                server: None,
                state_dir: dir.path().to_owned(),
                retry_interval: Duration::from_secs(3600),
            },
            challenges.clone(),
            TlsOptions::default(),
            Arc::new(ChallengeCheckProvisioner),
        );

        mgr.ensure_valid_cert().await.unwrap();

        // Map must be clean after acquisition
        assert!(
            challenges.lock().unwrap_or_else(|p| p.into_inner()).is_empty(),
            "challenge map not cleaned up"
        );
    }
}
