// Server entry point: parse config, bind sockets, drop privileges, then
// spawn listener tasks.  Sockets are bound while still root (for ports
// below 1024); all further work runs as the configured unprivileged user.

mod access;
mod acme;
mod auth;
mod compress;
mod config;
mod error;
mod geoip;
mod handler;
mod headers;
mod listener;
mod metrics;
#[cfg(unix)]
mod privdrop;
mod proxy_proto;
mod router;
mod tls;

use acme::{AcmeConfig, AcmeManager, ChallengeMap};
use anyhow::Context;
use arc_swap::ArcSwap;
use config::{TlsConfig, TlsListenerConfig};
use std::time::Duration;
use listener::AppState;
use router::Router;
use std::collections::HashMap;
use clap::Parser;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Must be installed before any TLS work, including rcgen's
    // self-signed cert generation which also calls into rustls.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok(); // Err just means it was already installed.

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aloha=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();
    let config_path = args.config;
    let config = config::Config::load(&config_path)
        .with_context(|| {
            format!("loading config from {}", config_path.display())
        })?;

    tracing::info!(
        path = %config_path.display(),
        listeners = config.listeners.len(),
        vhosts = config.vhosts.len(),
        "config loaded"
    );

    let tls_defaults = config.server.tls_defaults.clone();
    let state_dir = config.server.state_dir.clone()
        .map(PathBuf::from);

    // -- Bind all sockets before dropping privileges ----------------
    //
    // Ports < 1024 (80, 443) require root on Linux.  We bind them all
    // here, then drop to an unprivileged user before accepting any
    // connections or running application code.
    let bound: Vec<(config::ListenerConfig, TcpListener)> = config
        .listeners
        .iter()
        .map(|cfg| {
            listener::bind_tcp(cfg)
                .with_context(|| {
                    format!("binding {}", cfg.local_name())
                })
                .map(|sock| (cfg.clone(), sock))
        })
        .collect::<anyhow::Result<_>>()?;

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
                config.server.keep_groups,
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

    let summary = Arc::new(
        handler::status::ServerSummary::from_config(&config)
    );

    let router = Arc::new(
        Router::new(&config, &metrics, &summary)
            .context("building router")?,
    );

    // Phase 1: create shared ACME challenge map and app state.
    let challenges: ChallengeMap =
        Arc::new(Mutex::new(HashMap::new()));

    let authenticator: Arc<dyn auth::Authenticator> =
        build_authenticator(&config.server.auth);

    let geoip: Option<Arc<geoip::CountryReader>> =
        config.server.geoip.as_ref()
            .map(|g| geoip::open(&g.db))
            .transpose()
            .context("opening GeoIP database")?
            .map(Arc::new);

    if let Some(ref g) = config.server.geoip {
        tracing::info!(db = %g.db, "geoip: database loaded");
    }

    // Retain a clone for TCP proxy listeners, which don't share AppState.
    let tcp_geoip = geoip.clone();

    let state = Arc::new(AppState {
        router,
        acme_challenges: challenges.clone(),
        authenticator,
        metrics: metrics.clone(),
        geoip,
    });

    // Background task: advance the request-rate ring buffer every 5 s.
    // Not tracked in `handles` -- it carries no state worth draining.
    tokio::spawn(metrics.clone().tick_loop());

    // Shutdown channel: false = running, true = drain and exit.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut handles: JoinSet<()> = JoinSet::new();

    // Split pre-bound sockets into three groups.
    // TLS TCP proxies go into tls_bound so they share the acceptor-building
    // path; the spawned task dispatches to run_tcp_proxy rather than run_tls.
    let mut tcp_proxy_plain_bound = Vec::new();
    let mut plain_bound = Vec::new();
    let mut tls_bound = Vec::new();
    for (cfg, socket) in bound {
        if cfg.tcp_proxy.is_some() && cfg.tls.is_none() {
            tcp_proxy_plain_bound.push((cfg, socket));
        } else if cfg.tls.is_some() {
            tls_bound.push((cfg, socket));
        } else {
            plain_bound.push((cfg, socket));
        }
    }

    // Phase 2a: plain TCP proxy listeners (no TLS, no HTTP, no ACME dependency).
    for (cfg, socket) in tcp_proxy_plain_bound {
        let proxy = cfg.tcp_proxy.clone().unwrap();
        let access = proxy.access.as_ref().map(|p| Arc::new(p.clone()));
        let geo = tcp_geoip.clone();
        let rx = shutdown_rx.clone();
        handles.spawn(async move {
            if let Err(e) =
                listener::run_tcp_proxy(
                    cfg, proxy, socket, None, rx, access, geo,
                ).await
            {
                tracing::error!("TCP proxy error: {e:#}");
            }
        });
    }

    // Phase 2b: plain HTTP listeners first so that ACME HTTP-01
    // challenge requests can be served before we start ACME flows.
    for (cfg, socket) in plain_bound {
        let state = state.clone();
        let rx = shutdown_rx.clone();
        handles.spawn(async move {
            if let Err(e) =
                listener::run_plain(cfg, socket, state, rx).await
            {
                tracing::error!("HTTP listener error: {e:#}");
            }
        });
    }

    // Phase 3: build TLS acceptors (ACME may do network I/O here)
    // then spawn TLS listeners.
    for (cfg, socket) in tls_bound {
        // Safe: tls_bound was partitioned to contain only TLS listeners.
        let tls_cfg = cfg.tls.as_ref().unwrap();
        let resolved = tls_cfg.options.resolve(&tls_defaults);

        let acceptor: Arc<ArcSwap<tokio_rustls::TlsAcceptor>> =
            match &tls_cfg.cert {
                TlsConfig::Acme {
                    domains,
                    name,
                    email,
                    staging,
                    server,
                    retry_interval_secs,
                } => {
                    let sd = state_dir.as_ref().expect(
                        "state_dir required for ACME \
                         (validated earlier)",
                    );
                    let mgr = Arc::new(AcmeManager::new(
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
                        },
                        challenges.clone(),
                        resolved,
                    ));
                    // Try to get an initial cert.  If ACME fails,
                    // fall back to self-signed and keep retrying in
                    // the background rather than crashing -- crashing
                    // causes systemd to restart us rapidly, which can
                    // exhaust Let's Encrypt rate limits.
                    let (initial, initial_failed) =
                        match mgr.ensure_valid_cert().await {
                            Ok(acc) => (acc, false),
                            Err(e) => {
                                tracing::warn!(
                                    domains = ?domains,
                                    retry_secs = retry_interval_secs,
                                    "ACME initial acquisition failed: \
                                     {e:#}; serving self-signed \
                                     certificate while retrying"
                                );
                                let fallback = tls::build_acceptor(
                                    &TlsListenerConfig {
                                        cert: TlsConfig::SelfSigned,
                                        options: tls_cfg.options.clone(),
                                    },
                                    &tls_defaults,
                                ).context(
                                    "building self-signed fallback"
                                )?;
                                (fallback, true)
                            }
                        };
                    let acc = Arc::new(ArcSwap::new(Arc::new(initial)));
                    // Background renewal / retry task.
                    tokio::spawn({
                        let mgr = mgr.clone();
                        let acc = acc.clone();
                        async move {
                            mgr.renewal_loop(acc, initial_failed).await
                        }
                    });
                    acc
                }
                _ => {
                    let initial =
                        tls::build_acceptor(tls_cfg, &tls_defaults)?;
                    Arc::new(ArcSwap::new(Arc::new(initial)))
                }
            };

        let rx = shutdown_rx.clone();
        if let Some(proxy) = cfg.tcp_proxy.clone() {
            // TLS-terminating TCP proxy: accept TLS, forward plaintext.
            let access = proxy.access.as_ref().map(|p| Arc::new(p.clone()));
            let geo = tcp_geoip.clone();
            handles.spawn(async move {
                if let Err(e) = listener::run_tcp_proxy(
                    cfg, proxy, socket, Some(acceptor), rx, access, geo,
                )
                .await
                {
                    tracing::error!("TLS TCP proxy error: {e:#}");
                }
            });
        } else {
            let state = state.clone();
            handles.spawn(async move {
                if let Err(e) =
                    listener::run_tls(cfg, socket, state, acceptor, rx)
                        .await
                {
                    tracing::error!("TLS listener error: {e:#}");
                }
            });
        }
    }

    // -- Wait for a shutdown signal ---------------------------------
    //
    // On Unix we handle both SIGTERM (systemd stop) and SIGINT (ctrl-c).
    // On other platforms only ctrl-c is available.
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
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
) -> Arc<dyn auth::Authenticator> {
    match backend {
        #[cfg(unix)]
        Some(config::AuthBackend::Pam { service }) => {
            tracing::info!(service, "auth: PAM");
            Arc::new(auth::PamAuthenticator::new(service.clone()))
        }
        Some(config::AuthBackend::Ldap(cfg)) => {
            tracing::info!(url = %cfg.url, "auth: LDAP");
            Arc::new(auth::LdapAuthenticator::new(cfg.clone()))
        }
        None => Arc::new(auth::AnonymousAuthenticator),
        // On non-Unix builds, PAM is unavailable; fall through to anonymous.
        #[cfg(not(unix))]
        Some(config::AuthBackend::Pam { .. }) => {
            tracing::warn!(
                "PAM auth configured but not supported on this \
                 platform; falling back to anonymous"
            );
            Arc::new(auth::AnonymousAuthenticator)
        }
    }
}
