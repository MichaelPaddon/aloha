use crate::auth::AuthPolicy;
use crate::config::{Config, ListenerConfig, VHostConfig};
use crate::handler::Handler;
use hyper::Request;
use hyper::body::Incoming;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;

pub struct Route {
    pub handler: Arc<Handler>,
    pub matched_prefix: String,
    pub auth_policy: Option<AuthPolicy>,
}

// Runtime representation of a virtual host, with handlers pre-built.
struct VHost {
    locations: Vec<Location>,
}

struct Location {
    path: String,
    handler: Arc<Handler>,
    auth_policy: Option<AuthPolicy>,
}

pub struct Router {
    // Literal hostname → vhost; checked first at request time.
    vhosts: HashMap<String, Arc<VHost>>,
    // Regex patterns in config order; checked when the literal
    // lookup produces no match.  Anchored at both ends.
    patterns: Vec<(Regex, Arc<VHost>)>,
    // Maps each listener's local name to its default vhost (if any).
    defaults: HashMap<String, Option<Arc<VHost>>>,
}

impl Router {
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        let mut vhosts: HashMap<String, Arc<VHost>> = HashMap::new();
        let mut patterns: Vec<(Regex, Arc<VHost>)> = Vec::new();
        // Keyed by raw config string (including `~` for regex names);
        // used below to resolve default-vhost references.
        let mut by_config_key: HashMap<String, Arc<VHost>> =
            HashMap::new();

        for vcfg in &config.vhosts {
            let vhost = Arc::new(build_vhost(vcfg)?);

            let all_names =
                std::iter::once(&vcfg.name).chain(vcfg.aliases.iter());
            for name in all_names {
                by_config_key.insert(name.clone(), vhost.clone());

                if let Some(pat) = name.strip_prefix('~') {
                    // Anchor the pattern so it must match the whole host.
                    let re = Regex::new(&format!("^(?:{pat})$"))
                        .expect("regex validated at config load");
                    patterns.push((re, vhost.clone()));
                } else {
                    vhosts.insert(name.clone(), vhost.clone());
                }
            }
        }

        let defaults: HashMap<String, Option<Arc<VHost>>> = config
            .listeners
            .iter()
            .map(|l: &ListenerConfig| {
                let vhost = l
                    .default_vhost
                    .as_ref()
                    .and_then(|name| by_config_key.get(name))
                    .cloned();
                (l.local_name(), vhost)
            })
            .collect();

        Ok(Self { vhosts, patterns, defaults })
    }

    pub fn route(
        &self,
        req: &Request<Incoming>,
        listener_bind: &str,
    ) -> Option<Route> {
        let host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(strip_port);
        let vhost = self.resolve_vhost(host.as_deref(), listener_bind)?;
        let path = req.uri().path();
        // Locations are ordered; first prefix match wins.
        for loc in &vhost.locations {
            if path.starts_with(loc.path.as_str()) {
                return Some(Route {
                    handler: loc.handler.clone(),
                    matched_prefix: loc.path.clone(),
                    auth_policy: loc.auth_policy.clone(),
                });
            }
        }
        None
    }

    // Resolve the virtual host for a request.  `host` is the value of
    // the Host header with the port already stripped; None means the
    // header was absent or unparseable.
    //
    // Matching order:
    //   1. Exact literal match (O(1) HashMap lookup).
    //   2. Regex patterns in config declaration order.
    //   3. Listener default (if configured).
    fn resolve_vhost(
        &self,
        host: Option<&str>,
        listener_bind: &str,
    ) -> Option<Arc<VHost>> {
        if let Some(host) = host {
            if let Some(vhost) = self.vhosts.get(host) {
                return Some(vhost.clone());
            }
            for (re, vhost) in &self.patterns {
                if re.is_match(host) {
                    return Some(vhost.clone());
                }
            }
        }
        self.defaults.get(listener_bind).and_then(|v| v.clone())
    }
}

// Strip the port suffix from a Host header value.
// Handles IPv6 bracket notation: [::1]:8080 → [::1].
fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            return &host[..=end];
        }
    }
    host.split(':').next().unwrap_or(host)
}

fn build_vhost(vcfg: &VHostConfig) -> anyhow::Result<VHost> {
    let mut locations = Vec::with_capacity(vcfg.locations.len());
    for loc in &vcfg.locations {
        let handler = Arc::new(Handler::from_config(&loc.handler)?);
        locations.push(Location {
            path: loc.path.clone(),
            handler,
            auth_policy: loc.auth.clone(),
        });
    }
    Ok(VHost { locations })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(kdl: &str) -> Config {
        Config::parse(kdl).unwrap()
    }

    // Route a synthetic request and return the matched location prefix,
    // or None.  Uses Request<()> to avoid needing a real hyper body.
    fn route_str(
        router: &Router,
        host: &str,
        path: &str,
        bind: &str,
    ) -> Option<String> {
        use hyper::http::Request;
        let req = Request::builder()
            .uri(path)
            .header("host", host)
            .body(())
            .unwrap();

        let host_stripped = strip_port(host);
        let vhost =
            router.resolve_vhost(Some(host_stripped), bind)?;

        for loc in &vhost.locations {
            if req.uri().path().starts_with(loc.path.as_str()) {
                return Some(loc.path.clone());
            }
        }
        None
    }

    #[test]
    fn routes_by_host() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
                default-vhost "a.com"
            }
            vhost "a.com" {
                location "/" {
                    static { root "/var/www/a"; }
                }
            }
            vhost "b.com" {
                location "/docs/" {
                    static { root "/var/www/b"; }
                }
            }
            "#,
        );
        let router = Router::new(&config).unwrap();
        assert_eq!(
            route_str(&router, "a.com", "/index.html", "0.0.0.0:80"),
            Some("/".into())
        );
        assert_eq!(
            route_str(
                &router,
                "b.com",
                "/docs/readme.txt",
                "0.0.0.0:80"
            ),
            Some("/docs/".into())
        );
        assert_eq!(
            route_str(&router, "b.com", "/other", "0.0.0.0:80"),
            None
        );
    }

    #[test]
    fn falls_back_to_default_vhost() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
                default-vhost "a.com"
            }
            vhost "a.com" {
                location "/" {
                    static { root "/var/www/a"; }
                }
            }
            "#,
        );
        let router = Router::new(&config).unwrap();
        assert_eq!(
            route_str(&router, "unknown.com", "/", "0.0.0.0:80"),
            Some("/".into())
        );
    }

    // ── regex vhost matching ───────────────────────────────────────

    #[test]
    fn regex_vhost_matches_by_pattern() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost r"~.+\.example\.com" {
                location "/" {
                    static { root "/var/www/example"; }
                }
            }
            "#,
        );
        let router = Router::new(&config).unwrap();
        assert_eq!(
            route_str(&router, "foo.example.com", "/", "0.0.0.0:80"),
            Some("/".into())
        );
        assert_eq!(
            route_str(&router, "bar.example.com", "/", "0.0.0.0:80"),
            Some("/".into())
        );
    }

    #[test]
    fn regex_vhost_does_not_match_unrelated_host() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
                default-vhost null
            }
            vhost r"~.+\.example\.com" {
                location "/" {
                    static { root "/var/www/example"; }
                }
            }
            "#,
        );
        let router = Router::new(&config).unwrap();
        assert_eq!(
            route_str(
                &router,
                "notexample.org",
                "/",
                "0.0.0.0:80"
            ),
            None
        );
    }

    #[test]
    fn literal_takes_priority_over_regex() {
        // A literal vhost "a.example.com" should win over a regex that
        // also matches "a.example.com".
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "a.example.com" {
                location "/exact/" {
                    static { root "/exact"; }
                }
            }
            vhost r"~.+\.example\.com" {
                location "/wild/" {
                    static { root "/wild"; }
                }
            }
            "#,
        );
        let router = Router::new(&config).unwrap();
        // Literal match wins.
        assert_eq!(
            route_str(
                &router,
                "a.example.com",
                "/exact/page",
                "0.0.0.0:80"
            ),
            Some("/exact/".into())
        );
        // Other subdomain falls through to regex.
        assert_eq!(
            route_str(
                &router,
                "b.example.com",
                "/wild/page",
                "0.0.0.0:80"
            ),
            Some("/wild/".into())
        );
    }

    #[test]
    fn regex_patterns_checked_in_config_order() {
        // Two overlapping patterns; the first one in config wins.
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
                default-vhost null
            }
            vhost r"~.*\.com" {
                location "/first/" {
                    static { root "/first"; }
                }
            }
            vhost r"~.+\.example\.com" {
                location "/second/" {
                    static { root "/second"; }
                }
            }
            "#,
        );
        let router = Router::new(&config).unwrap();
        assert_eq!(
            route_str(
                &router,
                "foo.example.com",
                "/first/",
                "0.0.0.0:80"
            ),
            Some("/first/".into())
        );
    }

    #[test]
    fn regex_alias_matches() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
                default-vhost null
            }
            vhost "example.com" {
                alias r"~.+\.example\.com"
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        );
        let router = Router::new(&config).unwrap();
        assert_eq!(
            route_str(&router, "sub.example.com", "/", "0.0.0.0:80"),
            Some("/".into())
        );
        assert_eq!(
            route_str(&router, "example.com", "/", "0.0.0.0:80"),
            Some("/".into())
        );
    }

    #[test]
    fn invalid_regex_vhost_is_config_error() {
        let result = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "~[invalid" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn strip_port_ipv4() {
        assert_eq!(strip_port("example.com:8080"), "example.com");
        assert_eq!(strip_port("example.com"), "example.com");
    }

    #[test]
    fn strip_port_ipv6() {
        assert_eq!(strip_port("[::1]:8080"), "[::1]");
        assert_eq!(strip_port("[::1]"), "[::1]");
    }
}
