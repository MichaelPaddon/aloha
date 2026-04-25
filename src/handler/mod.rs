pub mod fcgi;
pub mod proxy;
pub mod static_files;

use crate::config::HandlerConfig;
use crate::error::{response_redirect, HttpResponse};
use hyper::body::Incoming;
use hyper::Request;

pub enum Handler {
    Static(static_files::StaticHandler),
    Proxy(proxy::ProxyHandler),
    Redirect { to: String, code: u16 },
    FastCgi(fcgi::FcgiHandler),
}

impl Handler {
    pub fn from_config(
        cfg: &HandlerConfig,
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
            HandlerConfig::Proxy { upstream } => {
                Ok(Handler::Proxy(proxy::ProxyHandler::new(upstream)))
            }
            HandlerConfig::Redirect { to, code } => {
                Ok(Handler::Redirect {
                    to: to.clone(),
                    code: *code,
                })
            }
            HandlerConfig::FastCgi { socket, index } => {
                Ok(Handler::FastCgi(
                    fcgi::FcgiHandler::new(socket, index.clone()),
                ))
            }
        }
    }

    pub async fn serve(
        &self,
        req: &Request<Incoming>,
        matched_prefix: &str,
    ) -> HttpResponse {
        match self {
            Handler::Static(h) => h.serve(req, matched_prefix).await,
            Handler::Proxy(h) => h.serve(req, matched_prefix).await,
            Handler::Redirect { to, code } => {
                response_redirect(to, *code)
            }
            Handler::FastCgi(h) => {
                h.serve(req, matched_prefix).await
            }
        }
    }
}
