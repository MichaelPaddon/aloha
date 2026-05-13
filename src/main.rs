// Server entry point: parse config, bind sockets, drop privileges, then
// spawn listener tasks.  Sockets are bound while still root (for ports
// below 1024); all further work runs as the configured unprivileged user.

mod access;
mod acme;
mod auth;
mod cert_state;
mod compress;
mod config;
mod error;
mod geoip;
mod handler;
mod headers;
#[cfg(unix)]
mod inherit;
mod jwt;
mod listener;
mod metrics;
#[cfg(unix)]
mod privdrop;
mod proxy_proto;
mod router;
#[cfg(test)]
mod test;
mod tls;

use acme::{AcmeConfig, AcmeManager, ChallengeMap};
use anyhow::Context;
use arc_swap::ArcSwap;
use clap::Parser;
use config::{
    CertificateDef, ErrorPageDef, StreamMode, TlsConfig, TlsListenerConfig,
};
use error::{ErrorPageEntry, ErrorPages};
use listener::{AppState, BoundSocket};
use router::Router;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinSet;

/// Registry of named certificate acceptors, populated before any TLS
/// listener spawns.  Each entry's `Arc<ArcSwap<TlsAcceptor>>` is shared
/// among all listeners that reference the cert by name; for ACME,
/// renewal swaps the inner `TlsAcceptor` and all listeners observe it
/// atomically.
type CertRegistry =
    HashMap<String, Arc<ArcSwap<tokio_rustls::TlsAcceptor>>>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Must be installed before any TLS work, including rcgen's
    // self-signed cert generation which also calls into rustls.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok(); // Err just means it was already installed.

    // Disable ANSI escapes unconditionally: journald and fail2ban need
    // plain text; journalctl adds its own colour when viewed in a terminal.
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aloha=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();
    let config_path = args.config;
    let config = config::Config::load(&config_path).with_context(|| {
        format!("loading config from {}", config_path.display())
    })?;

    let stream_count = config
        .listeners
        .iter()
        .filter(|l| l.stream.is_some())
        .count();
    tracing::info!(
        path = %config_path.display(),
        listeners = config.listeners.len() - stream_count,
        stream_listeners = stream_count,
        vhosts = config.vhosts.len(),
        "config loaded"
    );

    let tls_defaults = config.server.tls_defaults.clone();
    let state_dir = config.server.state_dir.clone().map(PathBuf::from);

    // -- Bind all sockets before dropping privileges ----------------
    //
    // Ports < 1024 (80, 443) require root on Linux.  We bind them all
    // here, then drop to an unprivileged user before accepting any
    // connections or running application code.
    //
    // Inherited sockets (passed from a parent process) are matched by
    // address and reused rather than rebound, enabling seamless upgrades.
    #[cfg(unix)]
    let mut inherited = inherit::InheritedSockets::scan();

    let bound: Vec<(config::ListenerConfig, BoundSocket)> = config
        .listeners
        .iter()
        .map(|cfg| {
            listener::bind_socket(
                cfg,
                #[cfg(unix)]
                &mut inherited,
            )
            .with_context(|| format!("binding {}", cfg.local_name()))
            .map(|sock| (cfg.clone(), sock))
        })
        .collect::<anyhow::Result<_>>()?;

    #[cfg(unix)]
    inherited.warn_unclaimed();

    // -- Privilege drop ---------------------------------------------
    #[cfg(unix)]
    {
        if let Some(ref user) = config.server.user {
            // Create and chown the state directory before dropping
            // privileges -- StateDirectory= in the systemd unit creates
            // it owned by root, and the unprivileged process cannot
            // write ACME certificates there without this step.
            if let Some(ref sd) = state_dir {
                privdrop::prepare_state_dir(
                    sd,
                    user,
                    config.server.group.as_deref(),
                )?;
            }
            privdrop::drop_privileges(
                user,
                config.server.group.as_deref(),
                config.server.inherit_supplementary_groups,
            )?;
        } else if nix::unistd::getuid().is_root() {
            tracing::warn!(
                "running as root with no server.user configured; \
                 set server user=\"nobody\" to drop privileges \
                 after binding"
            );
        }
    }

    // Create metrics before the router so StatusHandler can hold a
    // clone of the Arc, and AppState can record per-request data.
    let metrics = Arc::new(metrics::Metrics::new());

    let summary =
        Arc::new(handler::status::ServerSummary::from_config(&config));

    // Shared certificate state: written by each AcmeManager after
    // renewal, read by StatusHandler for countdown timers.
    let cert_state = cert_state::new_shared();

    let router = Router::new(&config, &metrics, &summary, Some(&cert_state))
        .context("building router")?;

    // Phase 1: create shared ACME challenge map and app state.
    let challenges: ChallengeMap = Arc::new(Mutex::new(HashMap::new()));

    // When auth is `jwt`, the inner back-end (if any) becomes the
    // credential authenticator; JWT issuance and validation are
    // handled by the JwtManager in listener.rs.
    let (authenticator, jwt_manager): (
        Arc<dyn auth::Authenticator>,
        Option<Arc<jwt::JwtManager>>,
    ) = if let Some(config::AuthBackend::Jwt {
        ref cookie_name,
        validity_secs,
        ref inner,
    }) = config.server.auth
    {
        let inner_auth: Option<Arc<dyn auth::Authenticator>> = inner
            .as_deref()
            .map(|b| build_authenticator(&Some(b.clone())))
            .transpose()
            .context("building jwt inner authenticator")?;
        let sd = state_dir
            .as_deref()
            .expect("state_dir required for jwt (validated earlier)");
        let mgr = jwt::JwtManager::load_or_generate(
            sd,
            jwt::JwtConfig {
                cookie_name: cookie_name.clone(),
                validity_secs,
            },
            inner_auth,
        )
        .context("initialising jwt manager")?;
        tracing::info!(
            kid = %mgr.kid,
            session_mode = mgr.is_session_mode(),
            "jwt: key loaded"
        );
        (Arc::new(auth::AnonymousAuthenticator), Some(Arc::new(mgr)))
    } else {
        (
            build_authenticator(&config.server.auth)
                .context("building authenticator")?,
            None,
        )
    };

    let geoip: Option<Arc<geoip::CountryReader>> = config
        .server
        .geoip
        .as_ref()
        .map(|g| geoip::open(&g.db))
        .transpose()
        .context("opening GeoIP database")?
        .map(Arc::new);

    if let Some(ref g) = config.server.geoip {
        tracing::info!(db = %g.db, "geoip: database loaded");
    }

    // Retain a clone for stream proxy listeners, which don't share AppState.
    let tcp_geoip = geoip.clone();

    // Build custom error pages map from config.
    let mut ep_map = HashMap::new();
    for (code, def) in &config.server.error_pages {
        let entry = match def {
            ErrorPageDef::File(path) => {
                ErrorPageEntry::File(PathBuf::from(path))
            }
            ErrorPageDef::Inline(html) => {
                ErrorPageEntry::Inline(bytes::Bytes::from(html.clone()))
            }
        };
        ep_map.insert(*code, entry);
    }
    let error_pages = Arc::new(ErrorPages::new(ep_map));

    let router = Arc::new(router);

    let state = Arc::new(AppState {
        router: router.clone(),
        acme_challenges: challenges.clone(),
        authenticator,
        metrics: metrics.clone(),
        geoip,
        health_enabled: config.server.health.enabled,
        error_pages,
        jwt_manager,
    });

    // Background task: advance the request-rate ring buffer every 5 s.
    // Not tracked in `handles` -- it carries no state worth draining.
    tokio::spawn(metrics.clone().tick_loop());

    // Shutdown channel: false = running, true = drain and exit.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut handles: JoinSet<()> = JoinSet::new();

    // Partition listeners into four buckets by (tls, stream) combination.
    // Plain stream listeners start first so ACME HTTP-01 challenges can
    // be served before ACME flows begin.
    let mut plain_http = Vec::new();
    let mut tls_http = Vec::new();
    let mut plain_stream = Vec::new();
    let mut tls_stream = Vec::new();
    for (cfg, socket) in bound {
        match (cfg.tls.is_some(), cfg.stream.is_some()) {
            (false, false) => plain_http.push((cfg, socket)),
            (true, false) => tls_http.push((cfg, socket)),
            (false, true) => plain_stream.push((cfg, socket)),
            (true, true) => tls_stream.push((cfg, socket)),
        }
    }

    // Build the named-certificate registry before any TLS listener
    // spawns: one AcmeManager and one acceptor per top-level
    // `certificate` definition, regardless of how many listeners refer
    // to it.  This is the single change that turns "each listener
    // races on its own ACME directory" into "one shared renewal loop".
    let cert_key_mode = config.server.cert_key_mode.unwrap_or(0o600);

    let cert_registry = build_cert_registry(
        &config.certificates,
        &tls_defaults,
        state_dir.as_ref(),
        &challenges,
        &cert_state,
        cert_key_mode,
    )
    .await
    .context("building certificate registry")?;

    // Phase 2a: plain stream listeners (no TLS, no ACME dependency).
    for (cfg, socket) in plain_stream {
        let stream_mode = cfg.stream.as_ref().unwrap();
        let access = stream_mode
            .policy
            .as_ref()
            .map(|defs| {
                router
                    .resolve_block(defs, true)
                    .map(Arc::new)
                    .context("resolving stream listener access block")
            })
            .transpose()?;
        let upstream_tls = build_upstream_tls(stream_mode)?;
        let geo = tcp_geoip.clone();
        let rx = shutdown_rx.clone();
        handles.spawn(async move {
            if let Err(e) = listener::run_stream_proxy(
                cfg,
                socket,
                None,
                upstream_tls,
                rx,
                access,
                geo,
            )
            .await
            {
                tracing::error!("stream listener error: {e:#}");
            }
        });
    }

    // Phase 2b: plain HTTP listeners first so that ACME HTTP-01
    // challenge requests can be served before we start ACME flows.
    for (cfg, socket) in plain_http {
        let state = state.clone();
        let rx = shutdown_rx.clone();
        handles.spawn(async move {
            if let Err(e) = listener::run_plain(cfg, socket, state, rx).await {
                tracing::error!("HTTP listener error: {e:#}");
            }
        });
    }

    // Phase 3: build TLS acceptors (ACME may do network I/O here)
    // then spawn TLS HTTP listeners.
    for (cfg, socket) in tls_http {
        let tls_cfg = cfg.tls.as_ref().unwrap();
        let acceptor = build_tls_acceptor(
            tls_cfg,
            &tls_defaults,
            state_dir.as_ref(),
            &challenges,
            &cert_state,
            &cert_registry,
            cert_key_mode,
        )
        .await?;
        let rx = shutdown_rx.clone();
        let state = state.clone();
        handles.spawn(async move {
            if let Err(e) =
                listener::run_tls(cfg, socket, state, acceptor, rx).await
            {
                tracing::error!("TLS listener error: {e:#}");
            }
        });
    }

    // Phase 3b: TLS-terminating stream listeners.
    for (cfg, socket) in tls_stream {
        let tls_cfg = cfg.tls.as_ref().unwrap();
        let acceptor = build_tls_acceptor(
            tls_cfg,
            &tls_defaults,
            state_dir.as_ref(),
            &challenges,
            &cert_state,
            &cert_registry,
            cert_key_mode,
        )
        .await?;
        let stream_mode = cfg.stream.as_ref().unwrap();
        let access = stream_mode
            .policy
            .as_ref()
            .map(|defs| {
                router
                    .resolve_block(defs, true)
                    .map(Arc::new)
                    .context("resolving stream listener access block")
            })
            .transpose()?;
        let upstream_tls = build_upstream_tls(stream_mode)?;
        let geo = tcp_geoip.clone();
        let rx = shutdown_rx.clone();
        handles.spawn(async move {
            if let Err(e) = listener::run_stream_proxy(
                cfg,
                socket,
                Some(acceptor),
                upstream_tls,
                rx,
                access,
                geo,
            )
            .await
            {
                tracing::error!("TLS stream listener error: {e:#}");
            }
        });
    }

    // -- Wait for a shutdown signal ---------------------------------
    //
    // On Unix we handle both SIGTERM (systemd stop) and SIGINT (ctrl-c).
    // On other platforms only ctrl-c is available.
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate())
            .context("failed to install SIGTERM handler")?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await.context("ctrl-c signal")?;

    tracing::info!("shutdown: signalling listeners");
    let _ = shutdown_tx.send(true);

    // Wait for all listener tasks (each drains its own connections).
    let drain_secs = 30u64;
    tracing::info!("shutdown: draining (up to {drain_secs} s)");
    let drain = async { while handles.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(drain_secs), drain)
        .await
        .is_err()
    {
        tracing::warn!("shutdown: drain timeout; exiting");
    }
    tracing::info!("shutdown: complete");
    Ok(())
}

#[derive(Parser)]
#[command(about = "HTTP server and reverse proxy")]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "aloha.kdl")]
    config: PathBuf,
}

fn build_authenticator(
    backend: &Option<config::AuthBackend>,
) -> anyhow::Result<Arc<dyn auth::Authenticator>> {
    match backend {
        #[cfg(unix)]
        Some(config::AuthBackend::Pam { service }) => {
            tracing::info!(service, "auth: PAM");
            Ok(Arc::new(auth::PamAuthenticator::new(service.clone())))
        }
        Some(config::AuthBackend::Ldap(cfg)) => {
            tracing::info!(url = %cfg.url, "auth: LDAP");
            Ok(Arc::new(auth::LdapAuthenticator::new(cfg.clone())))
        }
        Some(config::AuthBackend::Subrequest(cfg)) => {
            tracing::info!(url = %cfg.url, "auth: subrequest");
            Ok(Arc::new(auth::SubrequestAuthenticator::new(cfg)?))
        }
        None => Ok(Arc::new(auth::AnonymousAuthenticator)),
        // On non-Unix builds, PAM is unavailable; fall through to anonymous.
        #[cfg(not(unix))]
        Some(config::AuthBackend::Pam { .. }) => {
            tracing::warn!(
                "PAM auth configured but not supported on this \
                 platform; falling back to anonymous"
            );
            Ok(Arc::new(auth::AnonymousAuthenticator))
        }
        // Jwt is handled before this function is called; the inner
        // back-end (if any) is built via a recursive call from main.
        Some(config::AuthBackend::Jwt { .. }) => {
            Ok(Arc::new(auth::AnonymousAuthenticator))
        }
    }
}

/// Build a TLS acceptor for a listener or stream-proxy.
///
/// - `TlsConfig::Ref` is resolved by looking up the named entry in
///   `registry` and cloning the shared `Arc<ArcSwap<...>>` so multiple
///   listeners terminate with the same cert.
/// - Inline ACME builds its own AcmeManager and spawns a per-listener
///   renewal loop (the historical behavior; deduplication of inline
///   blocks across listeners is rejected at validation time).
/// - Inline files/self-signed are built once and wrapped in ArcSwap.
async fn build_tls_acceptor(
    tls_cfg: &TlsListenerConfig,
    tls_defaults: &config::TlsOptions,
    state_dir: Option<&PathBuf>,
    challenges: &ChallengeMap,
    cert_state: &cert_state::SharedCertState,
    registry: &CertRegistry,
    cert_key_mode: u32,
) -> anyhow::Result<Arc<ArcSwap<tokio_rustls::TlsAcceptor>>> {
    if let TlsConfig::Ref(name) = &tls_cfg.cert {
        return registry
            .get(name)
            .cloned()
            .with_context(|| format!("unknown certificate '{name}'"));
    }
    build_acceptor_from_source(
        &tls_cfg.cert,
        &tls_cfg.options,
        tls_defaults,
        state_dir,
        challenges,
        cert_state,
        cert_key_mode,
    )
    .await
}

/// Build an acceptor for a single concrete certificate source
/// (`Files`, `SelfSigned`, or `Acme`).  Shared by the named-cert
/// registry and the inline path in `build_tls_acceptor`.
async fn build_acceptor_from_source(
    cert: &TlsConfig,
    options: &config::TlsOptions,
    tls_defaults: &config::TlsOptions,
    state_dir: Option<&PathBuf>,
    challenges: &ChallengeMap,
    cert_state: &cert_state::SharedCertState,
    cert_key_mode: u32,
) -> anyhow::Result<Arc<ArcSwap<tokio_rustls::TlsAcceptor>>> {
    match cert {
        TlsConfig::Acme {
            domains,
            name,
            email,
            staging,
            server,
            retry_interval_secs,
        } => {
            let sd = state_dir
                .expect("state_dir required for ACME (validated earlier)");
            let resolved = options.resolve(tls_defaults);
            let mgr = Arc::new(
                AcmeManager::new(
                    AcmeConfig {
                        domains: domains.clone(),
                        name: name.clone(),
                        email: email.clone(),
                        staging: *staging,
                        server: server.clone(),
                        state_dir: sd.clone(),
                        retry_interval: Duration::from_secs(
                            *retry_interval_secs,
                        ),
                        cert_key_mode,
                    },
                    challenges.clone(),
                    resolved,
                )
                .with_cert_state(cert_state.clone()),
            );
            // Try to get an initial cert.  If ACME fails, fall back to
            // self-signed and keep retrying in the background --
            // crashing here causes systemd to restart us rapidly,
            // exhausting Let's Encrypt rate limits.
            let (initial, initial_failed) = match mgr.ensure_valid_cert().await
            {
                Ok(acc) => (acc, false),
                Err(e) => {
                    tracing::warn!(
                        domains = ?domains,
                        retry_secs = retry_interval_secs,
                        "ACME initial acquisition failed: {e:#}; \
                         serving self-signed certificate while \
                         retrying"
                    );
                    let fallback = tls::build_acceptor(
                        &TlsListenerConfig {
                            cert: TlsConfig::SelfSigned,
                            options: options.clone(),
                        },
                        tls_defaults,
                    )
                    .context("building self-signed fallback")?;
                    (fallback, true)
                }
            };
            let acc = Arc::new(ArcSwap::new(Arc::new(initial)));
            tokio::spawn({
                let mgr = mgr.clone();
                let acc = acc.clone();
                async move { mgr.renewal_loop(acc, initial_failed).await }
            });
            Ok(acc)
        }
        TlsConfig::Files { .. } | TlsConfig::SelfSigned => {
            let tls_cfg = TlsListenerConfig {
                cert: cert.clone(),
                options: options.clone(),
            };
            let initial = tls::build_acceptor(&tls_cfg, tls_defaults)?;
            Ok(Arc::new(ArcSwap::new(Arc::new(initial))))
        }
        TlsConfig::Ref(_) => {
            unreachable!("Ref resolved by caller before this point")
        }
    }
}

/// Build the registry of named certificate acceptors.  Each top-level
/// `certificate` definition yields one entry, regardless of how many
/// listeners later reference it.
///
/// Per-cert TLS options (cipher/version) fall back to the global
/// `tls-defaults` block here.  Listener-level overrides apply only to
/// the inline path; named certs intentionally do not carry their own
/// options because the same cert may be terminated by listeners with
/// differing TLS profiles.
async fn build_cert_registry(
    defs: &[CertificateDef],
    tls_defaults: &config::TlsOptions,
    state_dir: Option<&PathBuf>,
    challenges: &ChallengeMap,
    cert_state: &cert_state::SharedCertState,
    cert_key_mode: u32,
) -> anyhow::Result<CertRegistry> {
    let mut registry = HashMap::new();
    for def in defs {
        let acceptor = build_acceptor_from_source(
            &def.source,
            &Default::default(),
            tls_defaults,
            state_dir,
            challenges,
            cert_state,
            cert_key_mode,
        )
        .await
        .with_context(|| {
            format!("building certificate '{}'", def.name)
        })?;
        registry.insert(def.name.clone(), acceptor);
    }
    Ok(registry)
}

/// Build a rustls `ClientConfig` for upstream TLS connections in stream
/// listeners.  Returns `None` when the stream mode has no `upstream_tls`.
fn build_upstream_tls(
    stream: &StreamMode,
) -> anyhow::Result<Option<Arc<rustls::ClientConfig>>> {
    let utls = match &stream.upstream_tls {
        Some(u) => u,
        None => return Ok(None),
    };
    let cfg = if utls.skip_verify {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    Ok(Some(Arc::new(cfg)))
}

/// A rustls certificate verifier that accepts any server certificate.
/// Only used when `tls { skip-verify }` is set on a stream listener.
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
