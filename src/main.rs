mod acme;
mod config;
mod error;
mod handler;
mod listener;
#[cfg(unix)]
mod privdrop;
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

    // ── Bind all sockets before dropping privileges ────────────────
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

    // ── Privilege drop ─────────────────────────────────────────────
    #[cfg(unix)]
    {
        if let Some(ref user) = config.server.user {
            // Create and chown the state directory before dropping
            // privileges — StateDirectory= in the systemd unit creates
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
            )?;
        } else if nix::unistd::getuid().is_root() {
            tracing::warn!(
                "running as root with no server.user configured; \
                 set server user=\"nobody\" to drop privileges \
                 after binding"
            );
        }
    }

    let router = Arc::new(
        Router::new(&config).context("building router")?,
    );

    // Phase 1: create shared ACME challenge map and app state.
    let challenges: ChallengeMap =
        Arc::new(Mutex::new(HashMap::new()));
    let state = Arc::new(AppState {
        router,
        acme_challenges: challenges.clone(),
    });

    let mut handles = Vec::new();

    // Split pre-bound sockets into plain-HTTP and TLS groups.
    let (plain_bound, tls_bound): (Vec<_>, Vec<_>) =
        bound.into_iter().partition(|(cfg, _)| cfg.tls.is_none());

    // Phase 2: spawn plain HTTP listeners first so that ACME HTTP-01
    // challenge requests can be served before we start ACME flows.
    for (cfg, socket) in plain_bound {
        let state = state.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) =
                listener::run_plain(cfg, socket, state).await
            {
                tracing::error!("HTTP listener error: {e:#}");
            }
        }));
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
                    // the background rather than crashing — crashing
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

        let state = state.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) =
                listener::run_tls(cfg, socket, state, acceptor)
                    .await
            {
                tracing::error!("TLS listener error: {e:#}");
            }
        }));
    }

    tokio::signal::ctrl_c().await.context("ctrl-c signal")?;
    tracing::info!("shutting down");
    for h in handles {
        h.abort();
    }
    Ok(())
}

#[derive(Parser)]
#[command(about = "HTTP server and reverse proxy")]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "aloha.kdl")]
    config: PathBuf,
}
