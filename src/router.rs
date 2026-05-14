// Virtual host resolution and location prefix matching.
//
// Vhosts are resolved in order: exact hostname (O(1) HashMap), then
// regex patterns in config order, then the listener default.  Within
// a vhost, the longest matching location prefix wins.

use crate::access::{PolicyBlock, PolicyRule, Predicate};
use crate::config::{
    BasicAuthConfig, Config, HeaderOpConfig, ListenerConfig, PolicyRuleDef,
    VHostConfig,
};
use crate::handler::Handler;
use crate::handler::status::ServerSummary;
use crate::headers::{HeaderOp, HeaderRules, Template};
use crate::metrics::Metrics;
use anyhow::bail;
use hyper::Request;
use hyper::header::HeaderName;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;

pub struct Route {
    pub handler: Arc<Handler>,
    pub matched_prefix: String,
    pub policy: Option<Arc<PolicyBlock>>,
    pub basic_auth: Option<Arc<BasicAuthConfig>>,
    pub header_rules: Option<Arc<HeaderRules>>,
}

// Runtime representation of a virtual host, with handlers pre-built.
struct VHost {
    locations: Vec<Location>,
}

struct Location {
    path: String,
    handler: Arc<Handler>,
    policy: Option<Arc<PolicyBlock>>,
    basic_auth: Option<Arc<BasicAuthConfig>>,
    header_rules: Option<Arc<HeaderRules>>,
}

pub struct Router {
    // Literal hostname -> vhost; checked first at request time.
    vhosts: HashMap<String, Arc<VHost>>,
    // Regex patterns in config order; checked when the literal
    // lookup produces no match.  Anchored at both ends.
    patterns: Vec<(Regex, Arc<VHost>)>,
    // Maps each listener's local name to its default vhost (if any).
    defaults: HashMap<String, Option<Arc<VHost>>>,
    // Pre-inlined named policy rule lists for stream-listener use.
    named_policies: HashMap<String, Vec<PolicyRule>>,
}

impl Router {
    pub fn new(
        config: &Config,
        metrics: &Arc<Metrics>,
        summary: &Arc<ServerSummary>,
        cert_state: Option<&crate::cert_state::SharedCertState>,
    ) -> anyhow::Result<Self> {
        // Inline all named policies first so location blocks can reference
        // them via apply.
        let named_policies = resolve_named_policies(&config.server.policies)?;

        let mut vhosts: HashMap<String, Arc<VHost>> = HashMap::new();
        let mut patterns: Vec<(Regex, Arc<VHost>)> = Vec::new();
        // Keyed by the raw config string, including the `~` prefix for
        // regex names.  Regex names are never inserted into the `vhosts`
        // literal map, so this is the only place they can be found when
        // resolving a `default-vhost` reference at construction time.
        let mut by_config_key: HashMap<String, Arc<VHost>> = HashMap::new();

        for vcfg in &config.vhosts {
            let vhost = Arc::new(build_vhost(
                vcfg,
                metrics,
                summary,
                cert_state,
                &named_policies,
            )?);

            let all_names =
                std::iter::once(&vcfg.name).chain(vcfg.aliases.iter());
            for n in all_names {
                by_config_key.insert(n.value.clone(), vhost.clone());

                if n.regex {
                    // Anchor the pattern so it must match the whole host.
                    let re = Regex::new(&format!("^(?:{})$", n.value))
                        .expect("regex validated at config load");
                    patterns.push((re, vhost.clone()));
                } else {
                    vhosts.insert(n.value.clone(), vhost.clone());
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

        Ok(Self {
            vhosts,
            patterns,
            defaults,
            named_policies,
        })
    }

    pub fn route<B>(
        &self,
        req: &Request<B>,
        listener_bind: &str,
    ) -> Option<Route> {
        let host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(strip_port);
        let vhost = self.resolve_vhost(host, listener_bind)?;
        let path = req.uri().path();
        // Longest prefix match: the most specific location wins.
        vhost
            .locations
            .iter()
            .filter(|loc| path.starts_with(loc.path.as_str()))
            .max_by_key(|loc| loc.path.len())
            .map(|loc| Route {
                handler: loc.handler.clone(),
                matched_prefix: loc.path.clone(),
                policy: loc.policy.clone(),
                basic_auth: loc.basic_auth.clone(),
                header_rules: loc.header_rules.clone(),
            })
    }

    // Resolve the virtual host for a request.
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

    /// Inline a list of PolicyRuleDef into a PolicyBlock using the named
    /// policies in this router.  `tcp_only` rejects blocks that contain
    /// identity predicates.
    pub fn resolve_block(
        &self,
        defs: &[PolicyRuleDef],
        tcp_only: bool,
    ) -> anyhow::Result<PolicyBlock> {
        let rules = inline_rules(defs, &self.named_policies, tcp_only)?;
        Ok(PolicyBlock::new(rules))
    }
}

// -- Named policy resolution ---------------------------------------

// Resolve all named policies, detecting circular apply references.
// Returns a map from policy name to its fully-inlined rule list.
fn resolve_named_policies(
    defs: &HashMap<String, Vec<PolicyRuleDef>>,
) -> anyhow::Result<HashMap<String, Vec<PolicyRule>>> {
    let mut resolved: HashMap<String, Vec<PolicyRule>> = HashMap::new();
    for name in defs.keys() {
        let mut visiting = Vec::new();
        resolve_one(name, defs, &mut resolved, &mut visiting)?;
    }
    Ok(resolved)
}

// Resolve a single named policy, recursing through apply references.
fn resolve_one(
    name: &str,
    defs: &HashMap<String, Vec<PolicyRuleDef>>,
    resolved: &mut HashMap<String, Vec<PolicyRule>>,
    visiting: &mut Vec<String>,
) -> anyhow::Result<Vec<PolicyRule>> {
    if let Some(rules) = resolved.get(name) {
        return Ok(rules.clone());
    }
    if visiting.iter().any(|v| v == name) {
        bail!(
            "circular reference in policy '{name}' (chain: {})",
            visiting.join(" → ")
        );
    }
    let rule_defs = defs
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("undefined policy '{name}'"))?;
    visiting.push(name.to_string());
    let rules = resolve_rule_defs(rule_defs, defs, resolved, visiting)?;
    visiting.pop();
    resolved.insert(name.to_string(), rules.clone());
    Ok(rules)
}

// Recursively resolve PolicyRuleDef list, inlining apply references.
fn resolve_rule_defs(
    rule_defs: &[PolicyRuleDef],
    raw_defs: &HashMap<String, Vec<PolicyRuleDef>>,
    resolved: &mut HashMap<String, Vec<PolicyRule>>,
    visiting: &mut Vec<String>,
) -> anyhow::Result<Vec<PolicyRule>> {
    let mut result = Vec::new();
    for def in rule_defs {
        match def {
            PolicyRuleDef::Rule { predicate, action } => {
                result.push(PolicyRule {
                    predicate: predicate.clone(),
                    action: action.clone(),
                });
            }
            PolicyRuleDef::Apply { name } => {
                let inlined = resolve_one(name, raw_defs, resolved, visiting)?;
                result.extend(inlined);
            }
        }
    }
    Ok(result)
}

// Inline a PolicyRuleDef list using already-resolved named policies.
// Used for location blocks after named policies have been resolved.
fn inline_rules(
    defs: &[PolicyRuleDef],
    named_policies: &HashMap<String, Vec<PolicyRule>>,
    tcp_only: bool,
) -> anyhow::Result<Vec<PolicyRule>> {
    let mut result = Vec::new();
    for def in defs {
        match def {
            PolicyRuleDef::Rule { predicate, action } => {
                check_tcp_predicate(predicate, tcp_only)?;
                result.push(PolicyRule {
                    predicate: predicate.clone(),
                    action: action.clone(),
                });
            }
            PolicyRuleDef::Apply { name } => {
                let rules =
                    named_policies.get(name.as_str()).ok_or_else(|| {
                        anyhow::anyhow!("undefined policy '{name}'")
                    })?;
                if tcp_only {
                    check_tcp_block_rules(rules, name)?;
                }
                result.extend_from_slice(rules);
            }
        }
    }
    Ok(result)
}

fn check_tcp_predicate(
    predicate: &Option<Predicate>,
    tcp_only: bool,
) -> anyhow::Result<()> {
    if !tcp_only {
        return Ok(());
    }
    if predicate.as_ref().is_some_and(|p| p.needs_auth()) {
        bail!(
            "policy used in a stream listener context contains \
             identity predicates, which require HTTP authentication"
        );
    }
    Ok(())
}

fn check_tcp_block_rules(
    rules: &[PolicyRule],
    name: &str,
) -> anyhow::Result<()> {
    for rule in rules {
        if rule.predicate.as_ref().is_some_and(|p| p.needs_auth()) {
            bail!(
                "policy '{name}' contains identity predicates and \
                 cannot be used in a stream listener policy block"
            );
        }
    }
    Ok(())
}

// Strip the port suffix from a Host header value.
// Handles IPv6 bracket notation: [::1]:8080 -> [::1].
fn strip_port(host: &str) -> &str {
    if host.starts_with('[')
        && let Some(end) = host.find(']')
    {
        return &host[..=end];
    }
    host.split(':').next().unwrap_or(host)
}

fn build_vhost(
    vcfg: &VHostConfig,
    metrics: &Arc<Metrics>,
    summary: &Arc<ServerSummary>,
    cert_state: Option<&crate::cert_state::SharedCertState>,
    named_policies: &HashMap<String, Vec<PolicyRule>>,
) -> anyhow::Result<VHost> {
    let mut locations = Vec::with_capacity(vcfg.locations.len());
    for loc in &vcfg.locations {
        let handler = Arc::new(Handler::from_config(
            &loc.handler,
            metrics,
            summary,
            cert_state,
        )?);
        let header_rules = if loc.request_headers.is_empty()
            && loc.response_headers.is_empty()
        {
            None
        } else {
            let req = loc
                .request_headers
                .iter()
                .map(op_from_config)
                .collect::<anyhow::Result<Vec<_>>>()?;
            let resp = loc
                .response_headers
                .iter()
                .map(op_from_config)
                .collect::<anyhow::Result<Vec<_>>>()?;
            Some(Arc::new(HeaderRules::new(req, resp)))
        };
        let policy = if let Some(defs) = &loc.policy {
            let rules = inline_rules(defs, named_policies, false)?;
            Some(Arc::new(PolicyBlock::new(rules)))
        } else {
            None
        };
        locations.push(Location {
            path: loc.path.clone(),
            handler,
            policy,
            basic_auth: loc.auth.as_ref().map(|a| Arc::new(a.clone())),
            header_rules,
        });
    }
    Ok(VHost { locations })
}

fn op_from_config(cfg: &HeaderOpConfig) -> anyhow::Result<HeaderOp> {
    use crate::config::HeaderOpConfig as C;
    Ok(match cfg {
        C::Set { name, value } => HeaderOp::Set {
            name: HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| anyhow::anyhow!("invalid header name '{name}'"))?,
            template: Template::parse(value),
        },
        C::Add { name, value } => HeaderOp::Add {
            name: HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| anyhow::anyhow!("invalid header name '{name}'"))?,
            template: Template::parse(value),
        },
        C::Remove { name } => HeaderOp::Remove {
            name: HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| anyhow::anyhow!("invalid header name '{name}'"))?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(kdl: &str) -> Config {
        Config::parse(kdl).unwrap()
    }

    fn make_router(config: &Config) -> Router {
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let summary = Arc::new(
            crate::handler::status::ServerSummary::from_config(config),
        );
        Router::new(config, &metrics, &summary, None).unwrap()
    }

    // Route a synthetic request and return the matched location prefix,
    // or None.
    fn route_str(
        router: &Router,
        host: &str,
        path: &str,
        bind: &str,
    ) -> Option<String> {
        let host_stripped = strip_port(host);
        let vhost = router.resolve_vhost(Some(host_stripped), bind)?;

        vhost
            .locations
            .iter()
            .filter(|loc| path.starts_with(loc.path.as_str()))
            .max_by_key(|loc| loc.path.len())
            .map(|loc| loc.path.clone())
    }

    type RouteMeta = (
        Option<Arc<PolicyBlock>>,
        Option<Arc<BasicAuthConfig>>,
        Option<Arc<HeaderRules>>,
    );

    // Return the matched location's metadata fields.
    fn route_meta(
        router: &Router,
        host: &str,
        path: &str,
        bind: &str,
    ) -> Option<RouteMeta> {
        let host_stripped = strip_port(host);
        let vhost = router.resolve_vhost(Some(host_stripped), bind)?;
        vhost
            .locations
            .iter()
            .filter(|loc| path.starts_with(loc.path.as_str()))
            .max_by_key(|loc| loc.path.len())
            .map(|loc| {
                (
                    loc.policy.clone(),
                    loc.basic_auth.clone(),
                    loc.header_rules.clone(),
                )
            })
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
        let router = make_router(&config);
        assert_eq!(
            route_str(&router, "a.com", "/index.html", "0.0.0.0:80"),
            Some("/".into())
        );
        assert_eq!(
            route_str(&router, "b.com", "/docs/readme.txt", "0.0.0.0:80"),
            Some("/docs/".into())
        );
        assert_eq!(route_str(&router, "b.com", "/other", "0.0.0.0:80"), None);
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
        let router = make_router(&config);
        assert_eq!(
            route_str(&router, "unknown.com", "/", "0.0.0.0:80"),
            Some("/".into())
        );
    }

    // -- regex vhost matching --------------------------------------

    #[test]
    fn regex_vhost_matches_by_pattern() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost ".+\\.example\\.com" regex=#true {
                location "/" {
                    static { root "/var/www/example"; }
                }
            }
            "#,
        );
        let router = make_router(&config);
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
                default-vhost #null
            }
            vhost ".+\\.example\\.com" regex=#true {
                location "/" {
                    static { root "/var/www/example"; }
                }
            }
            "#,
        );
        let router = make_router(&config);
        assert_eq!(
            route_str(&router, "notexample.org", "/", "0.0.0.0:80"),
            None
        );
    }

    #[test]
    fn literal_takes_priority_over_regex() {
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
            vhost ".+\\.example\\.com" regex=#true {
                location "/wild/" {
                    static { root "/wild"; }
                }
            }
            "#,
        );
        let router = make_router(&config);
        assert_eq!(
            route_str(&router, "a.example.com", "/exact/page", "0.0.0.0:80"),
            Some("/exact/".into())
        );
        assert_eq!(
            route_str(&router, "b.example.com", "/wild/page", "0.0.0.0:80"),
            Some("/wild/".into())
        );
    }

    #[test]
    fn regex_patterns_checked_in_config_order() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
                default-vhost #null
            }
            vhost ".*\\.com" regex=#true {
                location "/first/" {
                    static { root "/first"; }
                }
            }
            vhost ".+\\.example\\.com" regex=#true {
                location "/second/" {
                    static { root "/second"; }
                }
            }
            "#,
        );
        let router = make_router(&config);
        assert_eq!(
            route_str(&router, "foo.example.com", "/first/", "0.0.0.0:80"),
            Some("/first/".into())
        );
    }

    #[test]
    fn regex_alias_matches() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
                default-vhost #null
            }
            vhost "example.com" {
                alias ".+\\.example\\.com" regex=#true
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        );
        let router = make_router(&config);
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
    fn regex_vhost_as_implicit_default() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost ".+\\.example\\.com" regex=#true {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        );
        let router = make_router(&config);
        assert_eq!(
            route_str(&router, "other.org", "/", "0.0.0.0:80"),
            Some("/".into())
        );
        assert_eq!(
            route_str(&router, "sub.example.com", "/", "0.0.0.0:80"),
            Some("/".into())
        );
    }

    #[test]
    fn regex_vhost_as_explicit_default() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
                default-vhost ".+\\.example\\.com"
            }
            vhost "exact.com" {
                location "/exact/" {
                    static { root "/exact"; }
                }
            }
            vhost ".+\\.example\\.com" regex=#true {
                location "/wild/" {
                    static { root "/wild"; }
                }
            }
            "#,
        );
        let router = make_router(&config);
        assert_eq!(
            route_str(&router, "exact.com", "/exact/", "0.0.0.0:80"),
            Some("/exact/".into())
        );
        assert_eq!(
            route_str(&router, "foo.example.com", "/wild/", "0.0.0.0:80"),
            Some("/wild/".into())
        );
        assert_eq!(
            route_str(&router, "other.org", "/wild/", "0.0.0.0:80"),
            Some("/wild/".into())
        );
    }

    #[test]
    fn invalid_regex_vhost_is_config_error() {
        let result = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "[invalid" regex=#true {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn longer_prefix_wins_regardless_of_declaration_order() {
        let config_catchall_first = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "example.com" {
                location "/" {
                    static { root "/www"; }
                }
                location "/docs/" {
                    static { root "/docs"; }
                }
            }
            "#,
        );
        let config_specific_first = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "example.com" {
                location "/docs/" {
                    static { root "/docs"; }
                }
                location "/" {
                    static { root "/www"; }
                }
            }
            "#,
        );
        for config in [config_catchall_first, config_specific_first] {
            let router = make_router(&config);
            assert_eq!(
                route_str(&router, "example.com", "/docs/readme", "0.0.0.0:80"),
                Some("/docs/".into()),
                "longer prefix /docs/ should win"
            );
            assert_eq!(
                route_str(&router, "example.com", "/index.html", "0.0.0.0:80"),
                Some("/".into()),
                "catch-all / should win when no longer match"
            );
        }
    }

    #[test]
    fn absent_host_header_uses_default_vhost() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
                default-vhost "fallback.com"
            }
            vhost "fallback.com" {
                location "/" {
                    static { root "/var/www/fallback"; }
                }
            }
            "#,
        );
        let router = make_router(&config);
        let vhost = router.resolve_vhost(None, "0.0.0.0:80");
        assert!(
            vhost.is_some(),
            "no Host header should fall back to default"
        );
        let path = vhost.and_then(|vh| {
            vh.locations
                .iter()
                .find(|l| "/".starts_with(l.path.as_str()))
                .map(|l| l.path.clone())
        });
        assert_eq!(path, Some("/".into()));
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

    // -- basic_auth / policy propagation ---------------------------

    #[test]
    fn basic_auth_realm_propagates_to_route() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/secure/" {
                    basic-auth realm="Secret Zone"
                    static { root "."; }
                }
            }
            "#,
        );
        let router = make_router(&config);
        let (_, auth, _) =
            route_meta(&router, "h", "/secure/", "0.0.0.0:80").unwrap();
        assert_eq!(auth.unwrap().realm, "Secret Zone");
    }

    #[test]
    fn basic_auth_absent_when_no_auth_block() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        );
        let router = make_router(&config);
        let (_, auth, _) = route_meta(&router, "h", "/", "0.0.0.0:80").unwrap();
        assert!(auth.is_none());
    }

    #[test]
    fn basic_auth_per_location_independent() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/public/" {
                    static { root "."; }
                }
                location "/private/" {
                    basic-auth realm="Members Only"
                    static { root "."; }
                }
            }
            "#,
        );
        let router = make_router(&config);
        let (_, pub_auth, _) =
            route_meta(&router, "h", "/public/x", "0.0.0.0:80").unwrap();
        let (_, priv_auth, _) =
            route_meta(&router, "h", "/private/x", "0.0.0.0:80").unwrap();
        assert!(pub_auth.is_none());
        assert_eq!(priv_auth.unwrap().realm, "Members Only");
    }

    #[test]
    fn policy_propagates_to_route() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/admin/" {
                    policy {
                        deny code=403
                    }
                    static { root "."; }
                }
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        );
        let router = make_router(&config);
        let (policy, _, _) =
            route_meta(&router, "h", "/admin/x", "0.0.0.0:80").unwrap();
        assert!(policy.is_some(), "/admin/ should have a policy");
        let (policy, _, _) =
            route_meta(&router, "h", "/index.html", "0.0.0.0:80").unwrap();
        assert!(policy.is_none(), "/ should have no policy");
    }

    #[test]
    fn basic_auth_and_policy_coexist() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/members/" {
                    basic-auth realm="Club"
                    policy {
                        allow { authenticated }
                        deny code=401
                    }
                    static { root "."; }
                }
            }
            "#,
        );
        let router = make_router(&config);
        let (policy, auth, _) =
            route_meta(&router, "h", "/members/", "0.0.0.0:80").unwrap();
        assert!(policy.is_some());
        assert_eq!(auth.unwrap().realm, "Club");
    }

    // -- header_rules propagation ----------------------------------

    #[test]
    fn header_rules_propagate_to_route() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/api/" {
                    request-headers {
                        set "X-Client-IP" "{client_ip}"
                    }
                    static { root "."; }
                }
            }
        "#,
        );
        let router = make_router(&config);
        let (_, _, rules) =
            route_meta(&router, "h", "/api/x", "0.0.0.0:80").unwrap();
        assert!(rules.is_some());
        let rules = rules.unwrap();
        assert_eq!(rules.request.len(), 1);
        assert!(!rules.needs_principal);
    }

    #[test]
    fn header_rules_none_when_no_blocks() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
        "#,
        );
        let router = make_router(&config);
        let (_, _, rules) =
            route_meta(&router, "h", "/", "0.0.0.0:80").unwrap();
        assert!(rules.is_none());
    }

    #[test]
    fn needs_principal_propagated_for_username_var() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    request-headers {
                        set "X-User" "{username}"
                    }
                    static { root "."; }
                }
            }
        "#,
        );
        let router = make_router(&config);
        let (_, _, rules) =
            route_meta(&router, "h", "/", "0.0.0.0:80").unwrap();
        assert!(
            rules.unwrap().needs_principal,
            "{{username}} should set needs_principal"
        );
    }

    #[test]
    fn basic_auth_default_realm_is_restricted() {
        let config = make_config(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/x/" {
                    basic-auth
                    static { root "."; }
                }
            }
            "#,
        );
        let router = make_router(&config);
        let (_, auth, _) =
            route_meta(&router, "h", "/x/", "0.0.0.0:80").unwrap();
        assert_eq!(auth.unwrap().realm, "Restricted");
    }

    // -- named policy resolution -----------------------------------

    #[test]
    fn named_policy_inlined_in_location() {
        let config = make_config(
            r#"
            server {
                policy "allow-all" {
                    allow
                }
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    policy {
                        apply "allow-all"
                    }
                    static { root "."; }
                }
            }
            "#,
        );
        let router = make_router(&config);
        let (policy, _, _) =
            route_meta(&router, "h", "/", "0.0.0.0:80").unwrap();
        // After inlining, the block contains a flat unconditional allow.
        let block = policy.unwrap();
        assert_eq!(block.rules.len(), 1);
        assert!(
            matches!(
                &block.rules[0].action,
                crate::access::PolicyAction::Allow
            ),
            "inlined rule must be Allow"
        );
        assert!(
            block.rules[0].predicate.is_none(),
            "unconditional allow has no predicate"
        );
    }

    #[test]
    fn unknown_named_policy_in_location_is_error() {
        let config_result = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    policy {
                        apply "does-not-exist"
                    }
                    static { root "."; }
                }
            }
            "#,
        );
        if let Ok(config) = config_result {
            let metrics = Arc::new(crate::metrics::Metrics::new());
            let summary = Arc::new(
                crate::handler::status::ServerSummary::from_config(&config),
            );
            let result = Router::new(&config, &metrics, &summary, None);
            assert!(
                result.is_err(),
                "unknown policy reference should error at router build"
            );
        }
    }

    #[test]
    fn circular_named_policy_is_error() {
        let mut policies = HashMap::new();
        policies.insert(
            "a".to_string(),
            vec![PolicyRuleDef::Apply {
                name: "b".to_string(),
            }],
        );
        policies.insert(
            "b".to_string(),
            vec![PolicyRuleDef::Apply {
                name: "a".to_string(),
            }],
        );
        let result = resolve_named_policies(&policies);
        assert!(
            result.is_err(),
            "circular policy reference should be detected"
        );
    }
}
