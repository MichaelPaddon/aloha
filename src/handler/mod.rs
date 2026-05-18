// Handler enum dispatcher: routes a matched request to the appropriate
// back-end (static files, reverse proxy, FastCGI, SCGI, CGI, redirect,
// or the built-in status page).

pub mod auth_request;
#[cfg(unix)]
pub mod cgi;
pub mod cgi_util;
pub mod fcgi;
pub mod health;
pub mod proxy;
pub mod scgi;
pub mod static_files;
pub mod status;

use crate::config::HandlerConfig;
use crate::error::{HttpResponse, ReqBody, response_redirect};
use crate::headers::{RequestContext, Template};
use crate::metrics::Metrics;
use hyper::Request;
use std::sync::Arc;

pub enum Handler {
    Static(static_files::StaticHandler),
    Proxy(Box<proxy::ProxyHandler>),
    Redirect {
        to: Template,
        code: u16,
    },
    FastCgi(fcgi::FcgiHandler),
    Scgi(scgi::ScgiHandler),
    Status(status::StatusHandler),
    AuthRequest(auth_request::AuthRequestHandler),
    #[cfg(unix)]
    Cgi(cgi::CgiHandler),
}

impl Handler {
    pub fn from_config(
        cfg: &HandlerConfig,
        metrics: &Arc<Metrics>,
        summary: &Arc<status::ServerSummary>,
        cert_state: Option<&crate::cert_state::SharedCertState>,
    ) -> anyhow::Result<Self> {
        match cfg {
            HandlerConfig::Static {
                root,
                index_files,
                strip_prefix,
            } => Ok(Handler::Static(static_files::StaticHandler::new(
                root,
                index_files.clone(),
                *strip_prefix,
            ))),
            HandlerConfig::Proxy {
                upstreams,
                lb_policy,
                lb_hash_header,
                active_health,
                passive_health,
                retry,
                strip_prefix,
                proxy_protocol,
                scheme,
                pool_idle_timeout_secs,
                pool_max_idle,
                upstream_tls,
                connect_timeout_secs,
            } => {
                let skip_verify = upstream_tls
                    .as_ref()
                    .map(|t| t.skip_verify)
                    .unwrap_or(false);
                let h = proxy::ProxyHandler::new_pool(
                    upstreams,
                    lb_policy.clone(),
                    lb_hash_header.clone(),
                    passive_health.clone(),
                    retry.clone(),
                    *strip_prefix,
                    *proxy_protocol,
                    *scheme,
                    *pool_idle_timeout_secs,
                    *pool_max_idle,
                    skip_verify,
                    *connect_timeout_secs,
                    metrics.clone(),
                )?;
                // Active health-check task: spawn one per pool when
                // configured.  Probes use a minimal hyper-util client
                // (separate from the pooled request-path client) so a
                // probe stall can never wedge real traffic.
                if let Some(hc) = active_health {
                    let prober: Arc<dyn crate::lb::HealthProber> =
                        Arc::new(proxy::HttpHealthProber::new(
                            skip_verify,
                        )?);
                    crate::lb::spawn_active_health_task(
                        h.pool().clone(),
                        hc.clone(),
                        prober,
                        Some(metrics.clone()),
                    );
                }
                Ok(Handler::Proxy(Box::new(h)))
            }
            HandlerConfig::Redirect { to, code } => Ok(Handler::Redirect {
                to: Template::parse(to),
                code: *code,
            }),
            HandlerConfig::FastCgi {
                socket,
                root,
                index,
            } => Ok(Handler::FastCgi(fcgi::FcgiHandler::new(
                socket,
                root,
                index.clone(),
            ))),
            HandlerConfig::Scgi {
                socket,
                root,
                index,
            } => Ok(Handler::Scgi(scgi::ScgiHandler::new(
                socket,
                root,
                index.clone(),
            ))),
            HandlerConfig::Status => {
                let mut h = status::StatusHandler::new(
                    metrics.clone(),
                    summary.clone(),
                );
                if let Some(cs) = cert_state {
                    h = h.with_cert_state(cs.clone());
                }
                Ok(Handler::Status(h))
            }
            HandlerConfig::AuthRequest => Ok(Handler::AuthRequest(
                auth_request::AuthRequestHandler::new(),
            )),
            HandlerConfig::Cgi { root } => {
                #[cfg(unix)]
                return Ok(Handler::Cgi(cgi::CgiHandler::new(root)));
                #[cfg(not(unix))]
                anyhow::bail!("cgi handler is only supported on Unix")
            }
        }
    }

    pub async fn serve(
        &self,
        req: Request<ReqBody>,
        matched_prefix: &str,
        ctx: &RequestContext<'_>,
    ) -> HttpResponse {
        match self {
            Handler::Static(h) => h.serve(req, matched_prefix).await,
            Handler::Proxy(h) => h.serve(req, matched_prefix).await,
            Handler::Redirect { to, code } => {
                response_redirect(&to.render(ctx), *code)
            }
            Handler::FastCgi(h) => h.serve(req, matched_prefix).await,
            Handler::Scgi(h) => h.serve(req, matched_prefix).await,
            Handler::Status(h) => h.serve(req, matched_prefix).await,
            Handler::AuthRequest(h) => h.serve(req, matched_prefix, ctx).await,
            #[cfg(unix)]
            Handler::Cgi(h) => h.serve(req, matched_prefix).await,
        }
    }
}
