// Handler enum dispatcher: routes a matched request to the appropriate
// back-end (static files, reverse proxy, FastCGI, SCGI, CGI, redirect,
// or the built-in status page).

pub mod cgi_util;
pub mod fcgi;
pub mod health;
pub mod proxy;
pub mod scgi;
pub mod static_files;
pub mod status;
#[cfg(unix)]
pub mod cgi;

use crate::config::HandlerConfig;
use crate::error::{response_redirect, HttpResponse};
use crate::metrics::Metrics;
use hyper::body::Incoming;
use hyper::Request;
use std::sync::Arc;

pub enum Handler {
    Static(static_files::StaticHandler),
    Proxy(proxy::ProxyHandler),
    Redirect { to: String, code: u16 },
    FastCgi(fcgi::FcgiHandler),
    Scgi(scgi::ScgiHandler),
    Status(status::StatusHandler),
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
            } => Ok(Handler::Static(
                static_files::StaticHandler::new(
                    root,
                    index_files.clone(),
                    *strip_prefix,
                ),
            )),
            HandlerConfig::Proxy { upstream, strip_prefix } => {
                Ok(Handler::Proxy(
                    proxy::ProxyHandler::new(
                        upstream, *strip_prefix,
                    )?,
                ))
            }
            HandlerConfig::Redirect { to, code } => {
                Ok(Handler::Redirect {
                    to: to.clone(),
                    code: *code,
                })
            }
            HandlerConfig::FastCgi { socket, root, index } => {
                Ok(Handler::FastCgi(fcgi::FcgiHandler::new(
                    socket,
                    root,
                    index.clone(),
                )))
            }
            HandlerConfig::Scgi { socket, root, index } => {
                Ok(Handler::Scgi(scgi::ScgiHandler::new(
                    socket,
                    root,
                    index.clone(),
                )))
            }
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
            HandlerConfig::Cgi { root } => {
                #[cfg(unix)]
                return Ok(Handler::Cgi(cgi::CgiHandler::new(root)));
                #[cfg(not(unix))]
                anyhow::bail!(
                    "cgi handler is only supported on Unix"
                )
            }
        }
    }

    pub async fn serve(
        &self,
        req: Request<Incoming>,
        matched_prefix: &str,
    ) -> HttpResponse {
        match self {
            Handler::Static(h) => h.serve(req, matched_prefix).await,
            Handler::Proxy(h)  => h.serve(req, matched_prefix).await,
            Handler::Redirect { to, code } => response_redirect(to, *code),
            Handler::FastCgi(h) => h.serve(req, matched_prefix).await,
            Handler::Scgi(h)    => h.serve(req, matched_prefix).await,
            Handler::Status(h)  => h.serve(req, matched_prefix).await,
            #[cfg(unix)]
            Handler::Cgi(h) => h.serve(req, matched_prefix).await,
        }
    }
}
