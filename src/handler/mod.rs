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
                lb_policy: _,
                lb_hash_header: _,
                health_check: _,
                passive_health: _,
                retry: _,
                strip_prefix,
                proxy_protocol,
                scheme,
                pool_idle_timeout_secs,
                pool_max_idle,
                upstream_tls,
                connect_timeout_secs,
            } => {
                // Step-1 wiring: build only the first upstream and call
                // the existing single-upstream ProxyHandler.  The LB
                // pool and retry/health logic land in a later commit;
                // until then a multi-upstream configuration falls back
                // to the first entry so existing single-upstream behavior
                // is preserved byte-for-byte.
                let primary = upstreams.first().ok_or_else(|| {
                    anyhow::anyhow!("proxy handler has no upstreams")
                })?;
                let skip_verify = upstream_tls
                    .as_ref()
                    .map(|t| t.skip_verify)
                    .unwrap_or(false);
                let mut h = proxy::ProxyHandler::new(
                    &primary.url,
                    *strip_prefix,
                    *proxy_protocol,
                    *scheme,
                    *pool_idle_timeout_secs,
                    *pool_max_idle,
                    skip_verify,
                    *connect_timeout_secs,
                )?;
                h.set_metrics(metrics.clone());
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
