// KDL configuration file parsing and validation.
//
// Config::load() reads a .kdl file; Config::parse() accepts a string
// (used in tests).  All fields are resolved to concrete values before
// validate() is called so downstream code never sees partial state.

use crate::access::{AccessAction, AccessCondition};
use anyhow::{anyhow, bail, Context};
use hyper::header::HeaderName;
use kdl::{KdlDocument, KdlNode};
use miette::Diagnostic as _;
use std::collections::HashMap;
use std::path::Path;
use regex::Regex;

// -- Public types --------------------------------------------------

/// Unresolved access statement as parsed from KDL.  Named `apply`
/// references are resolved to `Arc<AccessBlock>` in router.rs.
#[derive(Debug, Clone)]
pub enum AccessStatementDef {
    Rule {
        conditions: Vec<AccessCondition>,
        action: AccessAction,
    },
    Apply { name: String },
}

/// Source for a custom error page HTML body.
#[derive(Debug, Clone)]
pub enum ErrorPageDef {
    /// File path; contents are read from disk on each error response.
    File(String),
    /// Inline HTML stored directly in the config.
    Inline(String),
}

#[derive(Debug, Default)]
pub struct Config {
    pub server: ServerConfig,
    pub listeners: Vec<ListenerConfig>,
    // Ordered; the router builds an index keyed by name + aliases.
    pub vhosts: Vec<VHostConfig>,
}

#[derive(Debug, Default)]
pub struct ServerConfig {
    pub state_dir: Option<String>,
    // Default TLS options applied to every listener that
    // does not supply its own.
    pub tls_defaults: TlsOptions,
    // Unix user to switch to after binding sockets (privilege drop).
    // Only effective when the process starts as root.
    pub user: Option<String>,
    // Unix group to switch to; defaults to the user's primary group.
    pub group: Option<String>,
    // When true, skip setgroups() so supplementary groups inherited at
    // startup (e.g. from podman --keep-groups) survive the privilege
    // drop.  Only set this in controlled container environments where
    // the inherited groups are known and intentional.
    pub keep_groups: bool,
    // Authentication back-end; None means anonymous-only.
    pub auth: Option<AuthBackend>,
    // GeoIP database configuration; None means no geo conditions can be used.
    pub geoip: Option<GeoIpConfig>,
    pub health: HealthConfig,
    // Named access-policy blocks available to all vhosts/locations.
    pub access_policies: HashMap<String, Vec<AccessStatementDef>>,
    // Per-status-code custom error pages.
    pub error_pages: Vec<(u16, ErrorPageDef)>,
}

/// Built-in health endpoint configuration.
///
/// When enabled (the default), GET/HEAD requests to `/healthz`,
/// `/livez`, and `/readyz` are intercepted before vhost routing and
/// answered with a lightweight JSON response.  Disable only if you
/// need those paths for application traffic.
#[derive(Debug, Clone)]
pub struct HealthConfig {
    pub enabled: bool,
}

impl Default for HealthConfig {
    fn default() -> Self {
        HealthConfig { enabled: true }
    }
}

/// Path to a MaxMind MMDB database used for country lookups.
#[derive(Debug, Clone)]
pub struct GeoIpConfig {
    /// Filesystem path to the MMDB file
    /// (e.g. `/etc/aloha/GeoLite2-Country.mmdb`).
    pub db: String,
}

/// Authentication back-end activated at the server level.
#[derive(Debug, Clone)]
pub enum AuthBackend {
    /// Validate HTTP Basic credentials against the PAM stack.
    /// `service` is the PAM service name, e.g. `"login"`.
    Pam { service: String, cache_ttl_secs: u64 },
    /// Validate HTTP Basic credentials via an LDAP simple bind.
    Ldap(LdapAuthConfig),
}

/// Configuration for the LDAP authentication back-end.
///
/// Supports `ldap://`, `ldaps://`, and `ldapi://` (Unix socket) URLs.
/// The `bind_dn` and `group_filter` fields accept a `{user}` placeholder
/// that is substituted with the escaped username at authentication time.
#[derive(Debug, Clone)]
pub struct LdapAuthConfig {
    /// LDAP server URL.  TCP: `ldap://host:389` or `ldaps://host:636`.
    /// Unix socket: `ldapi:///var/run/slapd/ldapi` (plain path, preferred)
    /// or `ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi` (pre-encoded, also accepted).
    pub url: String,
    /// DN template used for the simple bind, e.g.
    /// `uid={user},ou=people,dc=example,dc=com`.
    pub bind_dn: String,
    /// Base DN for the group membership search.
    pub base_dn: String,
    /// LDAP filter for finding a user's groups.
    /// Defaults to `(memberUid={user})` (RFC 2307 posixGroup).
    pub group_filter: String,
    /// Entry attribute whose value becomes the group name.
    /// Defaults to `cn`.
    pub group_attr: String,
    /// Upgrade a plain `ldap://` connection to TLS via STARTTLS.
    pub starttls: bool,
    /// Seconds before an LDAP operation is abandoned.
    pub timeout_secs: u64,
    /// Seconds to cache a successful credential before re-validating.
    /// `0` disables caching.  Defaults to 60.
    pub cache_ttl_secs: u64,
}

/// Per-location HTTP Basic auth settings (realm for WWW-Authenticate).
#[derive(Debug, Clone)]
pub struct BasicAuthConfig {
    pub realm: String,
}

/// Per-listener connection and request timeout configuration.
/// All durations are in whole seconds.  `None` means no limit.
#[derive(Debug, Clone, Default)]
pub struct Timeouts {
    // Maximum seconds to wait for a complete request-line + headers.
    // Connections that don't send headers in time are closed.
    // Protects against Slowloris-style attacks.
    pub request_header_secs: Option<u64>,
    // Maximum seconds a handler may run before the request is
    // cancelled and a 408 is returned to the client.
    pub handler_secs: Option<u64>,
    // Seconds an idle HTTP/1.1 keep-alive connection is kept open
    // before it is closed.  Set to 0 to disable keep-alive entirely.
    pub keepalive_secs: Option<u64>,
}

/// Which version of the HAProxy PROXY protocol to prepend.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProxyProtocolVersion { V1, V2 }

/// TCP-proxy mode: forward raw bytes to an upstream address.
/// When present on a listener, HTTP processing is bypassed entirely.
#[derive(Debug, Clone)]
pub struct TcpProxyConfig {
    /// Upstream address, e.g. `"db.internal:5432"`.
    pub upstream: String,
    /// Prepend a PROXY protocol header so the backend sees the real
    /// client IP even though it only sees aloha's connection.
    pub proxy_protocol: Option<ProxyProtocolVersion>,
    /// Optional IP/country-based access control.  User, group, and
    /// `authenticated` conditions are rejected at resolve time because
    /// TCP proxies have no HTTP authentication layer.
    pub access: Option<Vec<AccessStatementDef>>,
}

#[derive(Debug, Clone)]
pub struct ListenerConfig {
    // Exactly one of bind or fd must be set (enforced by validate).
    pub bind: Option<String>,
    // Raw file descriptor -- used for systemd socket activation.
    pub fd: Option<i32>,
    pub tls: Option<TlsListenerConfig>,
    pub default_vhost: Option<String>,
    pub timeouts: Timeouts,
    // When set, the listener forwards raw TCP instead of speaking HTTP.
    pub tcp_proxy: Option<TcpProxyConfig>,
}

impl ListenerConfig {
    // Canonical string identifier used as the router key and in logs.
    // Returns the bind address, or "fd:N" for fd-based listeners.
    pub fn local_name(&self) -> String {
        match (&self.bind, self.fd) {
            (Some(addr), _) => addr.clone(),
            (_, Some(n))    => format!("fd:{n}"),
            _               => unreachable!("validated"),
        }
    }
}

/// Per-listener TLS configuration: certificate source + options.
#[derive(Debug, Clone)]
pub struct TlsListenerConfig {
    pub cert: TlsConfig,
    pub options: TlsOptions,
}

/// How a TLS listener obtains its certificate and private key.
///
/// The default when a `tls` node is present but carries no properties
/// is `SelfSigned` -- an ephemeral certificate generated at startup,
/// useful for development without any configuration.
#[derive(Debug, Clone)]
pub enum TlsConfig {
    /// Cert and key loaded from PEM files at startup.
    Files { cert: String, key: String },
    /// Ephemeral self-signed certificate generated in memory.
    /// Regenerated on every server start; not for production.
    SelfSigned,
    /// ACME-managed certificate (Let's Encrypt / HTTP-01).
    Acme {
        // All domains become SANs in the issued certificate.
        // At least one is required.
        domains: Vec<String>,
        // Storage directory name; defaults to domains[0] if None.
        name: Option<String>,
        email: Option<String>,
        // Use Let's Encrypt staging server when true.
        staging: bool,
        // Override ACME directory URL; defaults to Let's Encrypt.
        server: Option<String>,
        // Seconds to wait between retries after a failed acquisition.
        // Default 3600 keeps well within Let's Encrypt rate limits.
        retry_interval_secs: u64,
    },
}

/// TLS protocol constraints.  Empty / None fields mean "use defaults".
/// Per-listener options are merged over global defaults via `resolve`.
#[derive(Debug, Clone, Default)]
pub struct TlsOptions {
    // Minimum protocol version; None means "allow TLS 1.2 and above".
    pub min_version: Option<TlsVersion>,
    // Allowed cipher suites by name.  Empty means "provider defaults".
    pub ciphers: Vec<String>,
}

impl TlsOptions {
    // Merge: self wins where values are present; falls back to defaults.
    pub fn resolve(&self, defaults: &Self) -> Self {
        TlsOptions {
            min_version: self.min_version.or(defaults.min_version),
            ciphers: if !self.ciphers.is_empty() {
                self.ciphers.clone()
            } else {
                defaults.ciphers.clone()
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

#[derive(Debug)]
pub struct VHostConfig {
    // Primary hostname; also used as the map key in the router.
    pub name: String,
    pub aliases: Vec<String>,
    pub locations: Vec<LocationConfig>,
}

/// Config-level header operation: raw strings before name validation.
/// Converted to `headers::HeaderOp` (validated) in `router.rs`.
#[derive(Debug, Clone)]
pub enum HeaderOpConfig {
    Set    { name: String, value: String },
    Add    { name: String, value: String },
    Remove { name: String },
}

impl HeaderOpConfig {
    pub fn header_name(&self) -> &str {
        match self {
            HeaderOpConfig::Set    { name, .. }
            | HeaderOpConfig::Add    { name, .. }
            | HeaderOpConfig::Remove { name }    => name,
        }
    }
}

#[derive(Debug)]
pub struct LocationConfig {
    // URL path prefix; locations are tested in config order.
    pub path: String,
    pub handler: HandlerConfig,
    // Firewall-style access policy (unresolved; resolved in router.rs).
    pub access: Option<Vec<AccessStatementDef>>,
    // HTTP Basic auth realm; None means no WWW-Authenticate challenge.
    pub auth: Option<BasicAuthConfig>,
    // Header rules applied before the handler sees the request.
    pub request_headers:  Vec<HeaderOpConfig>,
    // Header rules applied to the response before it reaches the client.
    pub response_headers: Vec<HeaderOpConfig>,
}

#[derive(Debug)]
pub enum HandlerConfig {
    Static {
        root: String,
        index_files: Vec<String>,
        strip_prefix: bool,
    },
    Proxy {
        upstream: String,
        strip_prefix: bool,
    },
    Redirect {
        to: String,
        code: u16,
    },
    FastCgi {
        socket: String,
        root: String,
        index: Option<String>,
    },
    Scgi {
        socket: String,
        root: String,
        index: Option<String>,
    },
    Cgi {
        root: String,
    },
    Status,
}

// -- Config loading ------------------------------------------------

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let name = path.display().to_string();
        Self::parse_named(&text, &name)
    }

    #[cfg(test)]
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        Self::parse_named(text, "")
    }

    fn parse_named(text: &str, name: &str) -> anyhow::Result<Self> {
        let doc: KdlDocument = text.parse().map_err(|e: kdl::KdlError| {
            // KDL's own error message is a generic placeholder ("An
            // unspecified error occurred.").  Extract the byte offset
            // from the miette label instead and compute a line number.
            let offset = e
                .labels()
                .and_then(|mut it| it.next())
                .map(|l| l.offset())
                .unwrap_or(0)
                .min(text.len());
            let line = text[..offset]
                .bytes()
                .filter(|&b| b == b'\n')
                .count()
                + 1;
            let snippet = text
                .lines()
                .nth(line.saturating_sub(1))
                .unwrap_or("")
                .trim();
            if name.is_empty() {
                anyhow!("line {line}: syntax error -- `{snippet}`")
            } else {
                anyhow!("{name}:{line}: syntax error -- `{snippet}`")
            }
        })?;
        let mut config = Config::default();
        // Raw default-vhost specs, one per listener, in order:
        //   None          - child node absent; resolved to first vhost
        //   Some(None)    - explicit null; no fallback vhost
        //   Some(Some(s)) - named vhost
        let mut raw_defaults: Vec<Option<Option<String>>> = Vec::new();
        for node in doc.nodes() {
            let line = node_line(text, node);
            match node.name().value() {
                "server" => {
                    config.server = parse_server(node, text, name)?;
                }
                "listener" => {
                    let (listener, raw) =
                        parse_listener(node, text, name)?;
                    config.listeners.push(listener);
                    raw_defaults.push(raw);
                }
                "vhost" => {
                    config.vhosts.push(parse_vhost(node, text, name)?);
                }
                other => bail!(
                    "{name}:{line}: unknown top-level node '{other}'"
                ),
            }
        }
        // Resolve: absent -> first vhost name, null -> None, named -> Some(s).
        // tcp-proxy listeners bypass HTTP entirely; leave default_vhost = None.
        let first = config.vhosts.first().map(|v| v.name.clone());
        for (listener, raw) in
            config.listeners.iter_mut().zip(raw_defaults)
        {
            if listener.tcp_proxy.is_some() {
                continue;
            }
            listener.default_vhost = match raw {
                None             => first.clone(),
                Some(None)       => None,
                Some(Some(name)) => Some(name),
            };
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.listeners.is_empty() {
            bail!("config must define at least one listener");
        }
        // Vhosts are only required when at least one listener speaks HTTP.
        let has_http_listener = self.listeners.iter()
            .any(|l| l.tcp_proxy.is_none());
        if has_http_listener && self.vhosts.is_empty() {
            bail!("config must define at least one vhost");
        }
        // Verify each listener has exactly one socket source.
        for (i, l) in self.listeners.iter().enumerate() {
            match (&l.bind, l.fd) {
                (Some(_), None) | (None, Some(_)) => {}
                (Some(_), Some(_)) => bail!(
                    "listener[{i}] has both 'bind' and 'fd'; \
                     specify only one"
                ),
                (None, None) => bail!(
                    "listener[{i}] needs either 'bind' or 'fd'"
                ),
            }
        }
        // ACME mode requires a state_dir for cert/account storage.
        let uses_acme = self.listeners.iter()
            .filter_map(|l| l.tls.as_ref())
            .any(|t| matches!(t.cert, TlsConfig::Acme { .. }));
        if uses_acme && self.server.state_dir.is_none() {
            bail!(
                "server.state-dir is required when any listener \
                 uses tls mode=acme"
            );
        }
        // Validate regex syntax for any vhost name or alias that
        // starts with `~`.  Compile errors are caught here rather
        // than at the first incoming request.
        for v in &self.vhosts {
            let names = std::iter::once(&v.name)
                .chain(v.aliases.iter());
            for name in names {
                if let Some(pat) = name.strip_prefix('~') {
                    Regex::new(pat).with_context(|| {
                        format!("invalid regex in vhost name '{name}'")
                    })?;
                }
            }
        }
        // Verify every default-vhost reference resolves.
        let known = self.vhost_names();
        for (i, l) in self.listeners.iter().enumerate() {
            if let Some(ref name) = l.default_vhost {
                if !known.contains(name.as_str()) {
                    bail!(
                        "listener[{i}] default-vhost '{name}' \
                         not found in vhosts"
                    );
                }
            }
        }
        // Validate header names in request-headers and response-headers.
        for v in &self.vhosts {
            for loc in &v.locations {
                for ops in
                    [&loc.request_headers, &loc.response_headers]
                {
                    for op in ops.iter() {
                        let n = op.header_name();
                        HeaderName::from_bytes(n.as_bytes())
                        .map_err(|_| {
                            anyhow!(
                                "invalid header name '{n}' in \
                                 location '{}'",
                                loc.path
                            )
                        })?;
                    }
                }
            }
        }
        // If any access policy uses country conditions, a geoip db
        // must be configured.  Check all locations, TCP proxies, and
        // named policies (Apply references are resolved later and do
        // not need checking here).
        let uses_country =
            self.vhosts.iter().any(|v| {
                v.locations.iter().any(|loc| {
                    loc.access.as_ref()
                        .map(|s| stmts_have_country(s))
                        .unwrap_or(false)
                })
            })
            || self.listeners.iter().any(|l| {
                l.tcp_proxy.as_ref()
                    .and_then(|p| p.access.as_ref())
                    .map(|s| stmts_have_country(s))
                    .unwrap_or(false)
            })
            || self.server.access_policies.values().any(|s| {
                stmts_have_country(s)
            });
        if uses_country && self.server.geoip.is_none() {
            bail!(
                "access 'country' conditions require \
                 server {{ geoip {{ db \"...\" }} }}"
            );
        }
        Ok(())
    }

    // Returns the set of all known hostnames (names + aliases).
    pub fn vhost_names(&self) -> std::collections::HashSet<&str> {
        self.vhosts
            .iter()
            .flat_map(|v| {
                std::iter::once(v.name.as_str())
                    .chain(v.aliases.iter().map(String::as_str))
            })
            .collect()
    }
}

// Returns true iff any statement (non-recursively) contains a Country
// condition.  Apply references are not followed; they are checked when
// the policy is resolved in router.rs.
fn stmts_have_country(stmts: &[AccessStatementDef]) -> bool {
    stmts.iter().any(|s| match s {
        AccessStatementDef::Rule { conditions, .. } => {
            conditions.iter().any(|c| {
                matches!(c, AccessCondition::Country(_))
            })
        }
        AccessStatementDef::Apply { .. } => false,
    })
}

// -- Node parsers --------------------------------------------------

fn node_line(src: &str, node: &KdlNode) -> usize {
    src[..node.span().offset()]
        .bytes()
        .filter(|&b| b == b'\n')
        .count()
        + 1
}

fn parse_server(node: &KdlNode, src: &str, name: &str) -> anyhow::Result<ServerConfig> {
    let tls_defaults = node
        .children()
        .and_then(|doc| {
            doc.nodes().iter().find(|n| n.name().value() == "tls")
        })
        .map(|n| parse_tls_options(n, src, name))
        .transpose()?
        .unwrap_or_default();
    let auth = node
        .children()
        .and_then(|doc| {
            doc.nodes().iter().find(|n| n.name().value() == "auth")
        })
        .map(|n| parse_auth_backend(n, src, name))
        .transpose()?;
    let geoip = node
        .children()
        .and_then(|doc| {
            doc.nodes().iter().find(|n| n.name().value() == "geoip")
        })
        .map(|n| parse_geoip(n, src, name))
        .transpose()?;
    let health = node
        .children()
        .and_then(|doc| {
            doc.nodes()
                .iter()
                .find(|n| n.name().value() == "health")
        })
        .map(|n| HealthConfig {
            enabled: child_bool(n, "enabled").unwrap_or(true),
        })
        .unwrap_or_default();
    // Collect named access-policy blocks defined in the server node.
    let mut access_policies = HashMap::new();
    for child in node.children()
        .map(|d| d.nodes())
        .unwrap_or_default()
    {
        if child.name().value() == "access-policy" {
            let child_line = node_line(src, child);
            let policy_name = arg_str(child, 0)
                .ok_or_else(|| anyhow!(
                    "{name}:{child_line}: 'access-policy' requires \
                     a name argument"
                ))?;
            let stmts = parse_access_statements(
                child, src, name, false,
            )?;
            if access_policies
                .insert(policy_name.clone(), stmts)
                .is_some()
            {
                bail!(
                    "{name}:{child_line}: duplicate access-policy \
                     name '{policy_name}'"
                );
            }
        }
    }

    // Collect error-page entries from the server node.
    let mut error_pages = Vec::new();
    for child in node.children()
        .map(|d| d.nodes())
        .unwrap_or_default()
    {
        if child.name().value() == "error-page" {
            let child_line = node_line(src, child);
            let code = child
                .entries()
                .iter()
                .find(|e| e.name().is_none())
                .and_then(|e| e.value().as_i64())
                .map(|n| n as u16)
                .ok_or_else(|| anyhow!(
                    "{name}:{child_line}: 'error-page' requires a \
                     numeric status code as first argument"
                ))?;
            let def = if let Some(html) = child.get("html")
                .and_then(|e| e.value().as_string())
            {
                ErrorPageDef::Inline(html.to_owned())
            } else if let Some(path) = arg_str(child, 1) {
                ErrorPageDef::File(path)
            } else {
                bail!(
                    "{name}:{child_line}: 'error-page' requires \
                     either a file path argument or html=... property"
                );
            };
            error_pages.push((code, def));
        }
    }

    Ok(ServerConfig {
        state_dir: child_str(node, "state-dir"),
        tls_defaults,
        user:  child_str(node, "user"),
        group: child_str(node, "group"),
        keep_groups: child_bool(node, "keep-groups").unwrap_or(false),
        auth,
        geoip,
        health,
        access_policies,
        error_pages,
    })
}

fn parse_geoip(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<GeoIpConfig> {
    let line = node_line(src, node);
    let db = req_child_str(node, "db")
        .with_context(|| {
            format!("{name}:{line}: geoip block requires a 'db' child")
        })?;
    Ok(GeoIpConfig { db })
}

// Parse an `auth "pam" { ... }` or `auth "ldap" { ... }` node inside
// `server { }`.
fn parse_auth_backend(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<AuthBackend> {
    let line = node_line(src, node);
    let kind = arg_str(node, 0).unwrap_or_default();
    match kind.as_str() {
        "pam" => {
            let service = child_str(node, "service")
                .unwrap_or_else(|| "login".to_owned());
            let cache_ttl_secs = child_i64(node, "cache-ttl")
                .map(|n| n as u64)
                .unwrap_or(60);
            Ok(AuthBackend::Pam { service, cache_ttl_secs })
        }
        "ldap" => {
            let url = req_child_str(node, "url")
                .with_context(|| format!("{name}:{line}"))?;
            let bind_dn = req_child_str(node, "bind-dn")
                .with_context(|| format!("{name}:{line}"))?;
            let base_dn = req_child_str(node, "base-dn")
                .with_context(|| format!("{name}:{line}"))?;

            // Validate URL scheme.
            let scheme = url.split("://").next().unwrap_or("");
            if !matches!(scheme, "ldap" | "ldaps" | "ldapi") {
                bail!(
                    "{name}:{line}: auth ldap: url must use \
                     ldap://, ldaps://, or ldapi:// scheme"
                );
            }
            // Placeholder is required so bind-dn is username-specific.
            if !bind_dn.contains("{user}") {
                bail!(
                    "{name}:{line}: auth ldap: bind-dn must contain \
                     the {{user}} placeholder"
                );
            }

            let group_filter = child_str(node, "group-filter")
                .unwrap_or_else(|| "(memberUid={user})".to_owned());
            let group_attr = child_str(node, "group-attr")
                .unwrap_or_else(|| "cn".to_owned());
            let starttls =
                child_bool(node, "starttls").unwrap_or(false);
            let timeout_secs = child_i64(node, "timeout")
                .map(|n| n as u64)
                .unwrap_or(5);
            let cache_ttl_secs = child_i64(node, "cache-ttl")
                .map(|n| n as u64)
                .unwrap_or(60);

            Ok(AuthBackend::Ldap(LdapAuthConfig {
                url,
                bind_dn,
                base_dn,
                group_filter,
                group_attr,
                starttls,
                timeout_secs,
                cache_ttl_secs,
            }))
        }
        other => bail!(
            "{name}:{line}: unknown auth backend '{other}'; \
             expected 'pam' or 'ldap'"
        ),
    }
}

// Returns (config, raw_default_vhost) where raw_default_vhost is:
//   None          - child node absent; resolved to first vhost
//   Some(None)    - explicitly set to null
//   Some(Some(s)) - explicitly set to a hostname string
fn parse_listener(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<(ListenerConfig, Option<Option<String>>)> {
    let bind = child_str(node, "bind");
    let children = node.children()
        .map(|d| d.nodes())
        .unwrap_or_default();
    let fd = children
        .iter()
        .find(|n| n.name().value() == "fd")
        .and_then(|n| n.get(0)?.value().as_i64())
        .map(|n| n as i32);
    let raw_default_vhost = child_null_or_str(node, "default-vhost");
    let tls = children
        .iter()
        .find(|n| n.name().value() == "tls")
        .map(|n| parse_tls(n, src, name))
        .transpose()?;
    let timeouts = children
        .iter()
        .find(|n| n.name().value() == "timeouts")
        .map(parse_timeouts)
        .unwrap_or_default();
    let tcp_proxy = children
        .iter()
        .find(|n| n.name().value() == "tcp-proxy")
        .map(|n| parse_tcp_proxy(n, src, name))
        .transpose()?;
    // bind/fd mutual-exclusion is checked in Config::validate.
    // default_vhost is resolved later in Config::parse.
    Ok((
        ListenerConfig { bind, fd, tls, default_vhost: None, timeouts, tcp_proxy },
        raw_default_vhost,
    ))
}

fn parse_tcp_proxy(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<TcpProxyConfig> {
    let line = node_line(src, node);
    let upstream = req_child_str(node, "upstream")
        .with_context(|| format!("{name}:{line}"))?;
    let proxy_protocol = child_str(node, "proxy-protocol")
        .map(|v| match v.as_str() {
            "v1" | "1" => Ok(ProxyProtocolVersion::V1),
            "v2" | "2" => Ok(ProxyProtocolVersion::V2),
            other => bail!(
                "{name}:{line}: unknown proxy-protocol '{other}'; \
                 expected 'v1' or 'v2'"
            ),
        })
        .transpose()?;
    let access = node
        .children()
        .and_then(|d| d.nodes().iter().find(|n| n.name().value() == "access"))
        .map(|n| parse_access_statements(n, src, name, true))
        .transpose()?;
    Ok(TcpProxyConfig { upstream, proxy_protocol, access })
}

fn parse_timeouts(node: &KdlNode) -> Timeouts {
    Timeouts {
        request_header_secs: child_i64(node, "request-header")
            .map(|n| n as u64),
        handler_secs: child_i64(node, "handler").map(|n| n as u64),
        keepalive_secs: child_i64(node, "keepalive").map(|n| n as u64),
    }
}

fn parse_tls(node: &KdlNode, src: &str, name: &str) -> anyhow::Result<TlsListenerConfig> {
    let cert = parse_tls_cert(node, src, name)?;
    let options = parse_tls_options(node, src, name)?;
    Ok(TlsListenerConfig { cert, options })
}

fn parse_tls_cert(node: &KdlNode, src: &str, name: &str) -> anyhow::Result<TlsConfig> {
    let line = node_line(src, node);
    let mode = arg_str(node, 0);
    let cert = child_str(node, "cert");
    let key  = child_str(node, "key");

    match mode.as_deref() {
        Some("acme") => {
            // domain children list all SANs; first is the primary.
            let domains: Vec<String> = node
                .children()
                .map(|doc| {
                    doc.nodes()
                        .iter()
                        .filter(|n| n.name().value() == "domain")
                        .filter_map(|n| arg_str(n, 0))
                        .collect()
                })
                .unwrap_or_default();
            if domains.is_empty() {
                bail!(
                    "{name}:{line}: tls \"acme\" requires at least \
                     one 'domain' child node"
                );
            }
            Ok(TlsConfig::Acme {
                domains,
                name:    child_str(node, "name"),
                email:   child_str(node, "email"),
                staging: child_bool(node, "staging").unwrap_or(false),
                server:  child_str(node, "server"),
                retry_interval_secs: child_i64(node, "retry-interval")
                    .map(|n| n as u64)
                    .unwrap_or(3600),
            })
        }
        Some("self-signed") => Ok(TlsConfig::SelfSigned),
        Some("file") => Ok(TlsConfig::Files {
            cert: cert.ok_or_else(|| {
                anyhow!("{name}:{line}: tls \"file\" requires a 'cert' child node")
            })?,
            key: key.ok_or_else(|| {
                anyhow!("{name}:{line}: tls \"file\" requires a 'key' child node")
            })?,
        }),
        None => match (cert, key) {
            (Some(cert), Some(key)) => Ok(TlsConfig::Files { cert, key }),
            (None, None) => Ok(TlsConfig::SelfSigned),
            _ => bail!(
                "{name}:{line}: tls requires both 'cert' and 'key' \
                 child nodes, or neither"
            ),
        },
        Some(other) => bail!(
            "{name}:{line}: unknown tls mode \"{other}\"; \
             expected \"file\", \"self-signed\", or \"acme\""
        ),
    }
}

// Parse TLS version/cipher options from any tls node (server or
// listener).  Used for both global defaults and per-listener overrides.
fn parse_tls_options(node: &KdlNode, src: &str, name: &str) -> anyhow::Result<TlsOptions> {
    let line = node_line(src, node);
    let min_version = child_str(node, "min-version")
        .map(|s| parse_tls_version(&s, name, line))
        .transpose()?;
    let ciphers = node
        .children()
        .map(|doc| {
            doc.nodes()
                .iter()
                .filter(|n| n.name().value() == "cipher")
                .filter_map(|n| arg_str(n, 0))
                .collect()
        })
        .unwrap_or_default();
    Ok(TlsOptions { min_version, ciphers })
}

fn parse_tls_version(s: &str, name: &str, line: usize) -> anyhow::Result<TlsVersion> {
    match s {
        "1.2" => Ok(TlsVersion::Tls12),
        "1.3" => Ok(TlsVersion::Tls13),
        other => bail!(
            "{name}:{line}: unknown TLS version '{other}'; \
             expected '1.2' or '1.3'"
        ),
    }
}

fn parse_vhost(node: &KdlNode, src: &str, name: &str) -> anyhow::Result<VHostConfig> {
    let vhost_name = req_arg_str(node, 0)?;
    let children =
        node.children().map(|d| d.nodes()).unwrap_or_default();
    let mut aliases = Vec::new();
    let mut locations = Vec::new();
    for child in children {
        let line = node_line(src, child);
        match child.name().value() {
            "alias" => aliases.push(req_arg_str(child, 0)?),
            "location" => locations.push(parse_location(child, src, name)?),
            other => bail!(
                "{name}:{line}: unknown node '{other}' \
                 in vhost '{vhost_name}'"
            ),
        }
    }
    Ok(VHostConfig { name: vhost_name, aliases, locations })
}

fn parse_location(node: &KdlNode, src: &str, name: &str) -> anyhow::Result<LocationConfig> {
    let line = node_line(src, node);
    let path = req_arg_str(node, 0)?;
    let children =
        node.children().map(|d| d.nodes()).unwrap_or_default();
    // The first recognised handler node wins.
    let handler_node = children
        .iter()
        .find(|n| {
            matches!(
                n.name().value(),
                "static" | "proxy" | "redirect"
                | "fastcgi" | "scgi" | "cgi" | "status"
            )
        })
        .ok_or_else(|| {
            anyhow!("{name}:{line}: location '{path}' has no handler node")
        })?;
    let handler = parse_handler(handler_node, src, name, &path)?;
    let access = children
        .iter()
        .find(|n| n.name().value() == "access")
        .map(|n| parse_access_statements(n, src, name, false))
        .transpose()?;
    let auth = children
        .iter()
        .find(|n| n.name().value() == "auth")
        .map(|n| {
            let realm = child_str(n, "realm")
                .unwrap_or_else(|| "Restricted".to_owned());
            Ok::<_, anyhow::Error>(BasicAuthConfig { realm })
        })
        .transpose()?;
    let request_headers = children
        .iter()
        .find(|n| n.name().value() == "request-headers")
        .map(|n| parse_header_ops(n, src, name))
        .transpose()?
        .unwrap_or_default();
    let response_headers = children
        .iter()
        .find(|n| n.name().value() == "response-headers")
        .map(|n| parse_header_ops(n, src, name))
        .transpose()?
        .unwrap_or_default();
    Ok(LocationConfig {
        path, handler, access, auth,
        request_headers, response_headers,
    })
}

// Parse a `request-headers { }` or `response-headers { }` block.
//
//   request-headers {
//       set "X-Client-IP" "{client_ip}"
//       add "Vary"        "accept"
//       remove "Authorization"
//   }
fn parse_header_ops(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<Vec<HeaderOpConfig>> {
    let children =
        node.children().map(|d| d.nodes()).unwrap_or_default();
    let mut ops = Vec::new();
    for child in children {
        let child_line = node_line(src, child);
        match child.name().value() {
            "set" => {
                let hname = req_arg_str(child, 0)
                    .with_context(|| format!("{name}:{child_line}"))?;
                let value = req_arg_str(child, 1)
                    .with_context(|| {
                        anyhow!(
                            "{name}:{child_line}: 'set' requires a \
                             header name and a value"
                        )
                    })?;
                ops.push(HeaderOpConfig::Set { name: hname, value });
            }
            "add" => {
                let hname = req_arg_str(child, 0)
                    .with_context(|| format!("{name}:{child_line}"))?;
                let value = req_arg_str(child, 1)
                    .with_context(|| {
                        anyhow!(
                            "{name}:{child_line}: 'add' requires a \
                             header name and a value"
                        )
                    })?;
                ops.push(HeaderOpConfig::Add { name: hname, value });
            }
            "remove" => {
                let hname = req_arg_str(child, 0)
                    .with_context(|| format!("{name}:{child_line}"))?;
                ops.push(HeaderOpConfig::Remove { name: hname });
            }
            other => bail!(
                "{name}:{child_line}: unknown header operation \
                 '{other}'; expected 'set', 'add', or 'remove'"
            ),
        }
    }
    Ok(ops)
}

// Parse an `access { }` or `access-policy "name" { }` block into a
// list of unresolved AccessStatementDef values.
//
// Syntax for each statement:
//   <action> [<cond-type> <value>...] [code=N] [to=<url>]
//   apply "<policy-name>"
//
// Where <action> is: allow | deny | pass | redirect
// And <cond-type> (first positional arg) is:
//   ip | country | user | group | authenticated
//
// Multiple values after the condition type are OR within that type.
// AND across types requires a child block:
//   allow { ip "10.0.0.0/8"; authenticated }
//
// When `tcp_only` is true, identity conditions (user, group,
// authenticated) are rejected at parse time, since TCP proxies have
// no HTTP authentication layer.  `apply` references in tcp_only blocks
// are checked at resolve time in router.rs.
fn parse_access_statements(
    node: &KdlNode,
    src: &str,
    name: &str,
    tcp_only: bool,
) -> anyhow::Result<Vec<AccessStatementDef>> {
    let children =
        node.children().map(|d| d.nodes()).unwrap_or_default();
    let mut stmts = Vec::new();

    for child in children {
        let child_line = node_line(src, child);
        let stmt_name = child.name().value();

        // Handle `apply "name"` separately — no conditions, no action.
        if stmt_name == "apply" {
            let policy_name = arg_str(child, 0).ok_or_else(|| {
                anyhow!(
                    "{name}:{child_line}: 'apply' requires a \
                     policy name argument"
                )
            })?;
            stmts.push(AccessStatementDef::Apply {
                name: policy_name,
            });
            continue;
        }

        // Parse the action from the node name.
        let action = match stmt_name {
            "allow" => AccessAction::Allow,
            "pass"  => AccessAction::Pass,
            "deny" => {
                let code = child
                    .get("code")
                    .and_then(|e| e.value().as_i64())
                    .map(|n| n as u16)
                    .unwrap_or(403);
                AccessAction::Deny { code }
            }
            "redirect" => {
                let to = child
                    .get("to")
                    .and_then(|e| e.value().as_string())
                    .map(String::from)
                    .ok_or_else(|| {
                        anyhow!(
                            "{name}:{child_line}: 'redirect' requires \
                             a 'to' property"
                        )
                    })?;
                let code = child
                    .get("code")
                    .and_then(|e| e.value().as_i64())
                    .map(|n| n as u16)
                    .unwrap_or(302);
                AccessAction::Redirect { to, code }
            }
            other => bail!(
                "{name}:{child_line}: unknown access statement \
                 '{other}'; expected 'allow', 'deny', 'pass', \
                 'redirect', or 'apply'"
            ),
        };

        // Conditions are specified as child nodes inside a block:
        //   allow { ip "10.0.0.0/8"; country "US" "CA"; authenticated }
        // Multiple nodes of the same type = OR within that type.
        // Different types = AND across types.
        // No child block = unconditional (catch-all) rule.

        let cond_nodes = child
            .children()
            .map(|d| d.nodes())
            .unwrap_or_default();
        let mut conditions: Vec<AccessCondition> = Vec::new();

        for cond in cond_nodes {
            let cond_line = node_line(src, cond);
            parse_condition_node(
                cond, src, name, cond_line,
                &mut conditions, tcp_only,
            )?;
        }
        // Empty cond_nodes = unconditional (catch-all) rule.

        stmts.push(AccessStatementDef::Rule { conditions, action });
    }

    Ok(stmts)
}

// Parse a child-block condition node, e.g. `ip "10.0.0.0/8"` inside
// `allow { ip "10.0.0.0/8"; country "US" }`.
fn parse_condition_node(
    cond: &KdlNode,
    _src: &str,
    name: &str,
    cond_line: usize,
    conditions: &mut Vec<AccessCondition>,
    tcp_only: bool,
) -> anyhow::Result<()> {
    use ipnet::IpNet;
    use std::net::IpAddr;

    match cond.name().value() {
        "ip" => {
            let s = req_arg_str(cond, 0).with_context(|| {
                format!("{name}:{cond_line}")
            })?;
            let net: IpNet = s
                .parse()
                .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| {
                    anyhow!(
                        "{name}:{cond_line}: invalid IP address or \
                         CIDR '{s}'"
                    )
                })?;
            conditions.push(AccessCondition::Ip(net));
        }
        "country" => {
            let entries: Vec<_> = cond
                .entries()
                .iter()
                .filter(|e| e.name().is_none())
                .collect();
            if entries.is_empty() {
                bail!(
                    "{name}:{cond_line}: 'country' requires at least \
                     one country code argument"
                );
            }
            for entry in entries {
                let code = entry
                    .value()
                    .as_string()
                    .ok_or_else(|| {
                        anyhow!(
                            "{name}:{cond_line}: country code must be \
                             a string"
                        )
                    })?
                    .to_uppercase();
                conditions.push(AccessCondition::Country(code));
            }
        }
        "user" => {
            if tcp_only {
                bail!(
                    "{name}:{cond_line}: 'user' conditions are not \
                     supported in tcp-proxy access blocks \
                     (no HTTP authentication available)"
                );
            }
            let u = req_arg_str(cond, 0).with_context(|| {
                format!("{name}:{cond_line}")
            })?;
            conditions.push(AccessCondition::User(u));
        }
        "group" => {
            if tcp_only {
                bail!(
                    "{name}:{cond_line}: 'group' conditions are not \
                     supported in tcp-proxy access blocks \
                     (no HTTP authentication available)"
                );
            }
            let g = req_arg_str(cond, 0).with_context(|| {
                format!("{name}:{cond_line}")
            })?;
            conditions.push(AccessCondition::Group(g));
        }
        "authenticated" => {
            if tcp_only {
                bail!(
                    "{name}:{cond_line}: 'authenticated' conditions \
                     are not supported in tcp-proxy access blocks \
                     (no HTTP authentication available)"
                );
            }
            conditions.push(AccessCondition::Authenticated);
        }
        other => bail!(
            "{name}:{cond_line}: unknown access condition '{other}'; \
             expected 'ip', 'country', 'user', 'group', or \
             'authenticated'"
        ),
    }
    Ok(())
}

fn parse_handler(
    node: &KdlNode,
    src: &str,
    name: &str,
    location_path: &str,
) -> anyhow::Result<HandlerConfig> {
    let line = node_line(src, node);
    match node.name().value() {
        "static" => {
            let root = req_child_str(node, "root")
                .with_context(|| format!("{name}:{line}"))?;
            let strip_prefix =
                child_bool(node, "strip-prefix").unwrap_or(false);
            // Collect explicit index-file children; fall back to
            // built-in defaults when none are declared.
            let index_files: Vec<String> = node
                .children()
                .map(|doc| {
                    doc.nodes()
                        .iter()
                        .filter(|n| n.name().value() == "index-file")
                        .filter_map(|n| arg_str(n, 0))
                        .collect()
                })
                .unwrap_or_default();
            let index_files = if index_files.is_empty() {
                vec!["index.html".into(), "index.htm".into()]
            } else {
                index_files
            };
            Ok(HandlerConfig::Static {
                root,
                index_files,
                strip_prefix,
            })
        }
        "proxy" => {
            let upstream = req_child_str(node, "upstream")
                .with_context(|| format!("{name}:{line}"))?;
            let strip_prefix =
                child_bool(node, "strip-prefix").unwrap_or(false);
            Ok(HandlerConfig::Proxy { upstream, strip_prefix })
        }
        "redirect" => {
            let to = req_child_str(node, "to")
                .with_context(|| format!("{name}:{line}"))?;
            let code =
                child_i64(node, "code").map(|n| n as u16).unwrap_or(301);
            Ok(HandlerConfig::Redirect { to, code })
        }
        "fastcgi" => {
            let socket = req_child_str(node, "socket")
                .with_context(|| format!("{name}:{line}"))?;
            let root = req_child_str(node, "root")
                .with_context(|| format!("{name}:{line}"))?;
            let index = child_str(node, "index");
            Ok(HandlerConfig::FastCgi { socket, root, index })
        }
        "scgi" => {
            let socket = req_child_str(node, "socket")
                .with_context(|| format!("{name}:{line}"))?;
            let root = req_child_str(node, "root")
                .with_context(|| format!("{name}:{line}"))?;
            let index = child_str(node, "index");
            Ok(HandlerConfig::Scgi { socket, root, index })
        }
        "cgi" => {
            let root = req_child_str(node, "root")
                .with_context(|| format!("{name}:{line}"))?;
            Ok(HandlerConfig::Cgi { root })
        }
        "status" => Ok(HandlerConfig::Status),
        other => bail!(
            "{name}:{line}: unknown handler '{other}' \
             in location '{location_path}'"
        ),
    }
}

// -- KDL access helpers --------------------------------------------
//
// kdl 4.x: node.get(key) returns &KdlEntry; call .value() to reach
// the underlying &KdlValue.

fn arg_str(node: &KdlNode, pos: usize) -> Option<String> {
    node.get(pos)?.value().as_string().map(String::from)
}

fn req_arg_str(node: &KdlNode, pos: usize) -> anyhow::Result<String> {
    arg_str(node, pos).ok_or_else(|| {
        anyhow!(
            "'{}' missing required argument at position {pos}",
            node.name().value()
        )
    })
}

// Returns the first positional argument of the named child node.
fn child_str(node: &KdlNode, key: &str) -> Option<String> {
    node.children()?
        .nodes()
        .iter()
        .find(|n| n.name().value() == key)
        .and_then(|n| arg_str(n, 0))
}

fn req_child_str(node: &KdlNode, key: &str) -> anyhow::Result<String> {
    child_str(node, key).ok_or_else(|| {
        anyhow!(
            "'{}' missing required child node '{key}'",
            node.name().value()
        )
    })
}

// Returns the first positional argument of the named child node as i64.
fn child_i64(node: &KdlNode, key: &str) -> Option<i64> {
    let children = node.children()?;
    let child = children
        .nodes()
        .iter()
        .find(|n| n.name().value() == key)?;
    child.get(0)?.value().as_i64()
}

fn child_bool(node: &KdlNode, key: &str) -> Option<bool> {
    node.children()?
        .nodes()
        .iter()
        .find(|n| n.name().value() == key)?
        .get(0)?
        .value()
        .as_bool()
}

// Like child_str but distinguishes absent / null / string, mirroring
// prop_null_or_str for child nodes.
fn child_null_or_str(
    node: &KdlNode,
    key: &str,
) -> Option<Option<String>> {
    use kdl::KdlValue;
    let children = node.children()?;
    let child = children
        .nodes()
        .iter()
        .find(|n| n.name().value() == key)?;
    Some(match child.get(0)?.value() {
        KdlValue::Null => None,
        other          => other.as_string().map(String::from),
    })
}

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_static_config() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:8080"
            }
            vhost "localhost" {
                location "/" {
                    static {
                        root "./public"
                    }
                }
            }
            "#,
        )
        .unwrap();
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(cfg.vhosts.len(), 1);
        assert_eq!(cfg.vhosts[0].name, "localhost");
        assert!(matches!(
            cfg.vhosts[0].locations[0].handler,
            HandlerConfig::Static { .. }
        ));
    }

    #[test]
    fn tls_listener() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:443"
                tls "file" {
                    cert "cert.pem"
                    key "key.pem"
                }
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        let tls = cfg.listeners[0].tls.as_ref().unwrap();
        assert!(matches!(
            &tls.cert,
            TlsConfig::Files { cert, key }
                if cert == "cert.pem" && key == "key.pem"
        ));
    }

    #[test]
    fn tls_self_signed_default() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "[::]:443"
                tls
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        assert!(matches!(
            cfg.listeners[0].tls.as_ref().unwrap().cert,
            TlsConfig::SelfSigned
        ));
    }

    #[test]
    fn tls_explicit_self_signed() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "[::]:443"
                tls "self-signed"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        assert!(matches!(
            cfg.listeners[0].tls.as_ref().unwrap().cert,
            TlsConfig::SelfSigned
        ));
    }

    #[test]
    fn tls_acme() {
        let cfg = Config::parse(
            r#"
            server {
                state-dir "/tmp/aloha-test"
            }
            listener {
                bind "[::]:443"
                tls "acme" {
                    domain "example.com"
                }
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        assert!(matches!(
            cfg.listeners[0].tls.as_ref().unwrap().cert,
            TlsConfig::Acme { .. }
        ));
    }

    #[test]
    fn acme_multi_domain_parses() {
        let cfg = Config::parse(
            r#"
            server {
                state-dir "/tmp/aloha-test"
            }
            listener {
                bind "[::]:443"
                tls "acme" {
                    domain "example.com"
                    domain "www.example.com"
                    domain "api.example.com"
                    email "a@b.com"
                }
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        if let TlsConfig::Acme { domains, email, staging, name, .. } =
            &cfg.listeners[0].tls.as_ref().unwrap().cert
        {
            assert_eq!(
                domains,
                &["example.com", "www.example.com", "api.example.com"]
            );
            assert_eq!(email.as_deref(), Some("a@b.com"));
            assert!(!staging);
            assert!(name.is_none());
        } else {
            panic!("expected Acme");
        }
    }

    #[test]
    fn acme_explicit_name() {
        let cfg = Config::parse(
            r#"
            server {
                state-dir "/tmp/aloha-test"
            }
            listener {
                bind "[::]:443"
                tls "acme" {
                    domain "example.com"
                    domain "www.example.com"
                    name "my-cert"
                }
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        if let TlsConfig::Acme { name, .. } =
            &cfg.listeners[0].tls.as_ref().unwrap().cert
        {
            assert_eq!(name.as_deref(), Some("my-cert"));
        } else {
            panic!("expected Acme");
        }
    }

    #[test]
    fn acme_requires_domain() {
        let result = Config::parse(
            r#"
            server {
                state-dir "/tmp/aloha-test"
            }
            listener {
                bind "[::]:443"
                tls "acme"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn acme_requires_state_dir() {
        let result = Config::parse(
            r#"
            listener {
                bind "[::]:443"
                tls "acme" {
                    domain "example.com"
                }
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn acme_staging_defaults_false() {
        let cfg = Config::parse(
            r#"
            server {
                state-dir "/tmp/aloha-test"
            }
            listener {
                bind "[::]:443"
                tls "acme" {
                    domain "example.com"
                }
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        if let TlsConfig::Acme { staging, .. } =
            cfg.listeners[0].tls.as_ref().unwrap().cert
        {
            assert!(!staging);
        }
    }

    #[test]
    fn tls_missing_key_is_error() {
        let result = Config::parse(
            r#"
            listener {
                bind "[::]:443"
                tls "file" {
                    cert "cert.pem"
                }
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn index_files_default() {
        let cfg = Config::parse(
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
        )
        .unwrap();
        if let HandlerConfig::Static { index_files, .. } =
            &cfg.vhosts[0].locations[0].handler
        {
            assert_eq!(index_files, &["index.html", "index.htm"]);
        }
    }

    #[test]
    fn index_files_custom() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static {
                        root "."
                        index-file "start.html"
                    }
                }
            }
            "#,
        )
        .unwrap();
        if let HandlerConfig::Static { index_files, .. } =
            &cfg.vhosts[0].locations[0].handler
        {
            assert_eq!(index_files, &["start.html"]);
        }
    }

    #[test]
    fn multiple_handler_types() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/static/" {
                    static { root "/var/www"; }
                }
                location "/api/" {
                    proxy { upstream "http://127.0.0.1:3000"; }
                }
                location "/old/" {
                    redirect {
                        to "/new/"
                        code 301
                    }
                }
                location "/php/" {
                    fastcgi {
                        socket "unix:/run/php/fpm.sock"
                        root "/var/www/html"
                    }
                }
            }
            "#,
        )
        .unwrap();
        let locs = &cfg.vhosts[0].locations;
        assert!(matches!(locs[0].handler, HandlerConfig::Static { .. }));
        assert!(matches!(locs[1].handler, HandlerConfig::Proxy { .. }));
        assert!(matches!(
            locs[2].handler,
            HandlerConfig::Redirect { .. }
        ));
        assert!(matches!(
            locs[3].handler,
            HandlerConfig::FastCgi { .. }
        ));
    }

    // -- tcp-proxy -------------------------------------------------

    #[test]
    fn tcp_proxy_parses() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "[::]:5432"
                tcp-proxy {
                    upstream "db.internal:5432"
                    proxy-protocol "v2"
                }
            }
            "#,
        )
        .unwrap();
        let proxy = cfg.listeners[0].tcp_proxy.as_ref().unwrap();
        assert_eq!(proxy.upstream, "db.internal:5432");
        assert_eq!(
            proxy.proxy_protocol,
            Some(ProxyProtocolVersion::V2)
        );
    }

    #[test]
    fn tcp_proxy_without_proxy_protocol() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "[::]:3306"
                tcp-proxy {
                    upstream "db.internal:3306"
                }
            }
            "#,
        )
        .unwrap();
        let proxy = cfg.listeners[0].tcp_proxy.as_ref().unwrap();
        assert!(proxy.proxy_protocol.is_none());
    }

    #[test]
    fn tcp_proxy_v1_parses() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "[::]:80"
                tcp-proxy {
                    upstream "backend:80"
                    proxy-protocol "v1"
                }
            }
            "#,
        )
        .unwrap();
        let proxy = cfg.listeners[0].tcp_proxy.as_ref().unwrap();
        assert_eq!(proxy.proxy_protocol, Some(ProxyProtocolVersion::V1));
    }

    #[test]
    fn tcp_proxy_with_tls_termination() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "[::]:443"
                tls "self-signed"
                tcp-proxy {
                    upstream "backend:5432"
                }
            }
            "#,
        )
        .unwrap();
        assert!(cfg.listeners[0].tls.is_some());
        let proxy = cfg.listeners[0].tcp_proxy.as_ref().unwrap();
        assert_eq!(proxy.upstream, "backend:5432");
    }

    #[test]
    fn tcp_proxy_with_tls_and_proxy_protocol() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "[::]:443"
                tls "self-signed"
                tcp-proxy {
                    upstream "backend:5432"
                    proxy-protocol "v2"
                }
            }
            "#,
        )
        .unwrap();
        let proxy = cfg.listeners[0].tcp_proxy.as_ref().unwrap();
        assert_eq!(
            proxy.proxy_protocol,
            Some(ProxyProtocolVersion::V2)
        );
    }

    #[test]
    fn tcp_proxy_only_config_needs_no_vhost() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "[::]:5432"
                tcp-proxy {
                    upstream "db.internal:5432"
                }
            }
            "#,
        )
        .unwrap();
        assert!(cfg.vhosts.is_empty());
        assert!(cfg.listeners[0].tcp_proxy.is_some());
    }

    #[test]
    fn tcp_proxy_default_vhost_stays_none() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "[::]:5432"
                tcp-proxy {
                    upstream "db.internal:5432"
                }
            }
            "#,
        )
        .unwrap();
        // tcp-proxy listeners bypass HTTP; default_vhost should be None.
        assert!(cfg.listeners[0].default_vhost.is_none());
    }

    #[test]
    fn tcp_proxy_access_ip_parses() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "[::]:5432"
                tcp-proxy {
                    upstream "db.internal:5432"
                    access {
                        allow {
                            ip "10.0.0.0/8"
                        }
                        deny code=403
                    }
                }
            }
            "#,
        )
        .unwrap();
        let proxy = cfg.listeners[0].tcp_proxy.as_ref().unwrap();
        let stmts = proxy.access.as_ref().unwrap();
        assert_eq!(stmts.len(), 2);
        // No country conditions → stmts_have_country returns false.
        assert!(stmts.iter().all(|s| match s {
            AccessStatementDef::Rule { conditions, .. } => {
                !conditions.iter().any(|c| {
                    matches!(c, AccessCondition::Country(_))
                })
            }
            _ => true,
        }));
    }

    #[test]
    fn tcp_proxy_access_country_parses() {
        let cfg = Config::parse(
            r#"
            server {
                geoip {
                    db "/dev/null"
                }
            }
            listener {
                bind "[::]:5432"
                tcp-proxy {
                    upstream "db.internal:5432"
                    access {
                        allow {
                            country "US" "CA"
                        }
                        deny code=403
                    }
                }
            }
            "#,
        )
        .unwrap();
        let proxy = cfg.listeners[0].tcp_proxy.as_ref().unwrap();
        let stmts = proxy.access.as_ref().unwrap();
        assert!(stmts.iter().any(|s| match s {
            AccessStatementDef::Rule { conditions, .. } => {
                conditions.iter().any(|c| {
                    matches!(c, AccessCondition::Country(_))
                })
            }
            _ => false,
        }));
    }

    #[test]
    fn tcp_proxy_access_absent_means_none() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "[::]:5432"
                tcp-proxy {
                    upstream "db.internal:5432"
                }
            }
            "#,
        )
        .unwrap();
        let proxy = cfg.listeners[0].tcp_proxy.as_ref().unwrap();
        assert!(proxy.access.is_none());
    }

    #[test]
    fn tcp_proxy_access_rejects_user_condition() {
        let err = Config::parse(
            r#"
            listener {
                bind "[::]:5432"
                tcp-proxy {
                    upstream "db.internal:5432"
                    access {
                        allow {
                            user "alice"
                        }
                    }
                }
            }
            "#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not supported in tcp-proxy"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn tcp_proxy_access_rejects_group_condition() {
        let err = Config::parse(
            r#"
            listener {
                bind "[::]:5432"
                tcp-proxy {
                    upstream "db.internal:5432"
                    access {
                        allow {
                            group "admins"
                        }
                    }
                }
            }
            "#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not supported in tcp-proxy"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn tcp_proxy_access_rejects_authenticated_condition() {
        let err = Config::parse(
            r#"
            listener {
                bind "[::]:5432"
                tcp-proxy {
                    upstream "db.internal:5432"
                    access {
                        allow {
                            authenticated
                        }
                    }
                }
            }
            "#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not supported in tcp-proxy"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn status_handler_parses() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/status" {
                    status
                }
            }
            "#,
        )
        .unwrap();
        assert!(matches!(
            cfg.vhosts[0].locations[0].handler,
            HandlerConfig::Status
        ));
    }

    #[test]
    fn scgi_handler_parses() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    scgi {
                        socket "unix:/run/myapp.sock"
                        root   "/var/www/html"
                        index  "index.py"
                    }
                }
            }
            "#,
        )
        .unwrap();
        assert!(matches!(
            cfg.vhosts[0].locations[0].handler,
            HandlerConfig::Scgi { .. }
        ));
        if let HandlerConfig::Scgi { socket, root, index } =
            &cfg.vhosts[0].locations[0].handler
        {
            assert_eq!(socket, "unix:/run/myapp.sock");
            assert_eq!(root, "/var/www/html");
            assert_eq!(index.as_deref(), Some("index.py"));
        }
    }

    #[test]
    fn cgi_handler_parses() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/cgi-bin/" {
                    cgi {
                        root "/usr/lib/cgi-bin"
                    }
                }
            }
            "#,
        )
        .unwrap();
        assert!(matches!(
            cfg.vhosts[0].locations[0].handler,
            HandlerConfig::Cgi { .. }
        ));
        if let HandlerConfig::Cgi { root } = &cfg.vhosts[0].locations[0].handler {
            assert_eq!(root, "/usr/lib/cgi-bin");
        }
    }

    #[test]
    fn aliases() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "example.com" {
                alias "www.example.com"
                alias "example.net"
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.vhosts[0].aliases,
            ["www.example.com", "example.net"]
        );
    }

    #[test]
    fn validate_missing_vhost() {
        let result = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
                default-vhost "does-not-exist"
            }
            vhost "example.com" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn redirect_default_code() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/old/" {
                    redirect { to "/new/"; }
                }
            }
            "#,
        )
        .unwrap();
        if let HandlerConfig::Redirect { code, .. } =
            cfg.vhosts[0].locations[0].handler
        {
            assert_eq!(code, 301);
        }
    }

    #[test]
    fn fd_listener_parses() {
        let cfg = Config::parse(
            r#"
            listener {
                fd 3
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        let l = &cfg.listeners[0];
        assert_eq!(l.fd, Some(3));
        assert!(l.bind.is_none());
        assert_eq!(l.local_name(), "fd:3");
    }

    #[test]
    fn fd_listener_with_tls() {
        let cfg = Config::parse(
            r#"
            listener {
                fd 3
                tls "file" {
                    cert "cert.pem"
                    key "key.pem"
                }
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        assert!(matches!(
            &cfg.listeners[0].tls.as_ref().unwrap().cert,
            TlsConfig::Files { cert, .. } if cert == "cert.pem"
        ));
        assert_eq!(cfg.listeners[0].local_name(), "fd:3");
    }

    #[test]
    fn validate_rejects_both_bind_and_fd() {
        let result = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
                fd 3
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn validate_rejects_neither_bind_nor_fd() {
        let result = Config::parse(
            r#"
            listener {
                default-vhost "h"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn tls_options_per_listener() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "[::]:443"
                tls {
                    min-version "1.3"
                    cipher "TLS13_AES_256_GCM_SHA384"
                    cipher "TLS13_CHACHA20_POLY1305_SHA256"
                }
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        let opts = &cfg.listeners[0].tls.as_ref().unwrap().options;
        assert!(matches!(opts.min_version, Some(TlsVersion::Tls13)));
        assert_eq!(
            opts.ciphers,
            ["TLS13_AES_256_GCM_SHA384",
             "TLS13_CHACHA20_POLY1305_SHA256"]
        );
    }

    #[test]
    fn tls_options_global_defaults() {
        let cfg = Config::parse(
            r#"
            server {
                workers 2
                tls {
                    min-version "1.2"
                    cipher "TLS13_AES_256_GCM_SHA384"
                }
            }
            listener {
                bind "[::]:443"
                tls
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        let defaults = &cfg.server.tls_defaults;
        assert!(matches!(
            defaults.min_version,
            Some(TlsVersion::Tls12)
        ));
        assert_eq!(defaults.ciphers, ["TLS13_AES_256_GCM_SHA384"]);
    }

    #[test]
    fn tls_options_resolve_inheritance() {
        let global = TlsOptions {
            min_version: Some(TlsVersion::Tls12),
            ciphers: vec!["TLS13_AES_256_GCM_SHA384".into()],
        };
        // Listener overrides min_version but not ciphers.
        let per_listener = TlsOptions {
            min_version: Some(TlsVersion::Tls13),
            ciphers: vec![],
        };
        let resolved = per_listener.resolve(&global);
        assert!(matches!(
            resolved.min_version,
            Some(TlsVersion::Tls13)
        ));
        // Falls back to global ciphers since listener has none.
        assert_eq!(resolved.ciphers, ["TLS13_AES_256_GCM_SHA384"]);
    }

    #[test]
    fn tls_version_invalid() {
        let result = Config::parse(
            r#"
            listener {
                bind "[::]:443"
                tls {
                    min-version "1.1"
                }
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    // -- default-vhost resolution -----------------------------------

    #[test]
    fn default_vhost_absent_resolves_to_first_vhost() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "first.com" {
                location "/" {
                    static { root "."; }
                }
            }
            vhost "second.com" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.listeners[0].default_vhost.as_deref(),
            Some("first.com"),
            "absent default-vhost should resolve to the first vhost"
        );
    }

    #[test]
    fn default_vhost_explicit_null_means_no_default() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
                default-vhost null
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        assert!(
            cfg.listeners[0].default_vhost.is_none(),
            "default-vhost null should leave no fallback vhost"
        );
    }

    #[test]
    fn default_vhost_explicit_name_is_preserved() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
                default-vhost "second.com"
            }
            vhost "first.com" {
                location "/" {
                    static { root "."; }
                }
            }
            vhost "second.com" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.listeners[0].default_vhost.as_deref(),
            Some("second.com"),
            "explicit default-vhost name should be preserved"
        );
    }

    #[test]
    fn default_vhost_absent_multiple_listeners() {
        // Absent -> first vhost; null -> no default.
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            listener {
                bind "0.0.0.0:443"
                default-vhost null
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.listeners[0].default_vhost.as_deref(),
            Some("h")
        );
        assert!(cfg.listeners[1].default_vhost.is_none());
    }

    // -- timeouts --------------------------------------------------

    #[test]
    fn timeouts_parse() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
                timeouts {
                    request-header 30
                    handler 60
                    keepalive 75
                }
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        let t = &cfg.listeners[0].timeouts;
        assert_eq!(t.request_header_secs, Some(30));
        assert_eq!(t.handler_secs, Some(60));
        assert_eq!(t.keepalive_secs, Some(75));
    }

    #[test]
    fn timeouts_defaults_to_none() {
        let cfg = Config::parse(
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
        )
        .unwrap();
        let t = &cfg.listeners[0].timeouts;
        assert!(t.request_header_secs.is_none());
        assert!(t.handler_secs.is_none());
        assert!(t.keepalive_secs.is_none());
    }

    #[test]
    fn timeouts_partial() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
                timeouts {
                    handler 120
                }
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        let t = &cfg.listeners[0].timeouts;
        assert!(t.request_header_secs.is_none());
        assert_eq!(t.handler_secs, Some(120));
        assert!(t.keepalive_secs.is_none());
    }

    // -- server user/group -----------------------------------------

    #[test]
    fn server_user_and_group_parse() {
        let cfg = Config::parse(
            r#"
            server {
                user "nobody"
                group "nogroup"
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        assert_eq!(cfg.server.user.as_deref(), Some("nobody"));
        assert_eq!(cfg.server.group.as_deref(), Some("nogroup"));
    }

    #[test]
    fn server_user_only_parses() {
        let cfg = Config::parse(
            r#"
            server {
                user "www-data"
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        assert_eq!(cfg.server.user.as_deref(), Some("www-data"));
        assert!(cfg.server.group.is_none());
    }

    #[test]
    fn keep_groups_parses() {
        let cfg = Config::parse(
            r#"
            server {
                user "aloha"
                keep-groups true
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        assert!(cfg.server.keep_groups);
    }

    #[test]
    fn keep_groups_defaults_false() {
        let cfg = Config::parse(
            r#"
            server {
                user "aloha"
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        assert!(!cfg.server.keep_groups);
    }

        // -- access blocks ---------------------------------------------

    fn rule_action(s: &AccessStatementDef) -> &AccessAction {
        match s {
            AccessStatementDef::Rule { action, .. } => action,
            _ => panic!("expected Rule"),
        }
    }

    fn rule_conditions(s: &AccessStatementDef) -> &[AccessCondition] {
        match s {
            AccessStatementDef::Rule { conditions, .. } => conditions,
            _ => panic!("expected Rule"),
        }
    }

    #[test]
    fn access_allow_ip_parses() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/admin/" {
                    access {
                        allow {
                            ip "10.0.0.0/8"
                        }
                        deny code=403
                    }
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        let stmts = cfg.vhosts[0].locations[0].access.as_ref().unwrap();
        assert_eq!(stmts.len(), 2);
        assert!(matches!(rule_action(&stmts[0]), AccessAction::Allow));
        assert!(matches!(
            rule_action(&stmts[1]),
            AccessAction::Deny { code: 403 }
        ));
    }

    #[test]
    fn access_deny_custom_code_parses() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    access {
                        deny code=429 {
                            ip "1.2.3.4"
                        }
                    }
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        let stmts = cfg.vhosts[0].locations[0].access.as_ref().unwrap();
        assert!(matches!(
            rule_action(&stmts[0]),
            AccessAction::Deny { code: 429 }
        ));
        assert_eq!(rule_conditions(&stmts[0]).len(), 1);
        assert!(matches!(
            &rule_conditions(&stmts[0])[0],
            AccessCondition::Ip(_)
        ));
    }

    #[test]
    fn access_redirect_parses() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    access {
                        redirect to="/login/" code=302 {
                            user "unverified"
                        }
                        deny code=403
                    }
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        let stmts = cfg.vhosts[0].locations[0].access.as_ref().unwrap();
        assert!(matches!(
            rule_action(&stmts[0]),
            AccessAction::Redirect { code: 302, .. }
        ));
        if let AccessAction::Redirect { to, .. } = rule_action(&stmts[0]) {
            assert_eq!(to, "/login/");
        }
        assert!(matches!(
            &rule_conditions(&stmts[0])[0],
            AccessCondition::User(u) if u == "unverified"
        ));
    }

    #[test]
    fn access_empty_block_has_zero_statements() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    access {
                    }
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        let stmts = cfg.vhosts[0].locations[0].access.as_ref().unwrap();
        assert_eq!(stmts.len(), 0);
    }

    #[test]
    fn access_absent_means_none() {
        let cfg = Config::parse(
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
        )
        .unwrap();
        assert!(cfg.vhosts[0].locations[0].access.is_none());
    }

    #[test]
    fn access_invalid_cidr_is_error() {
        let result = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    access {
                        allow {
                            ip "not-an-ip"
                        }
                    }
                    static { root "."; }
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn access_unknown_action_is_error() {
        let result = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    access {
                        block {
                            ip "1.2.3.4"
                        }
                    }
                    static { root "."; }
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn access_unknown_condition_is_error() {
        let result = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    access {
                        allow {
                            country "US"
                        }
                    }
                    static { root "."; }
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn access_redirect_missing_to_is_error() {
        let result = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    access {
                        redirect code=302 {
                            ip "1.2.3.4"
                        }
                    }
                    static { root "."; }
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn access_plain_ip_without_prefix_parses() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    access {
                        allow {
                            ip "192.168.1.1"
                        }
                        deny code=403
                    }
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        let stmts = cfg.vhosts[0].locations[0].access.as_ref().unwrap();
        assert!(matches!(
            &rule_conditions(&stmts[0])[0],
            AccessCondition::Ip(_)
        ));
    }

    #[test]
    fn access_authenticated_condition_parses() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/members/" {
                    access {
                        allow {
                            authenticated
                        }
                        deny code=403
                    }
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        let stmts = cfg.vhosts[0].locations[0].access.as_ref().unwrap();
        assert!(matches!(
            &rule_conditions(&stmts[0])[0],
            AccessCondition::Authenticated
        ));
    }

    #[test]
    fn access_group_condition_parses() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/admin/" {
                    access {
                        allow {
                            group "admin"
                        }
                        deny code=403
                    }
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        let stmts = cfg.vhosts[0].locations[0].access.as_ref().unwrap();
        assert!(matches!(
            &rule_conditions(&stmts[0])[0],
            AccessCondition::Group(g) if g == "admin"
        ));
    }

    #[test]
    fn access_no_condition_rule_is_catch_all() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    access {
                        allow {
                            ip "10.0.0.0/8"
                        }
                        deny code=403
                    }
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        let stmts = cfg.vhosts[0].locations[0].access.as_ref().unwrap();
        // deny rule has no conditions -> catch-all
        assert!(rule_conditions(&stmts[1]).is_empty());
    }

    // -- New syntax: inline conditions, pass, apply, error-page ------

    #[test]
    fn access_country_condition_parses() {
        // country "CN" "RU" as multi-value condition in child block
        let cfg = Config::parse(
            r#"
            server {
                geoip {
                    db "/dev/null"
                }
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    access {
                        deny {
                            country "CN" "RU"
                        }
                        allow
                    }
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        let stmts = cfg.vhosts[0].locations[0].access.as_ref().unwrap();
        assert_eq!(stmts.len(), 2);
        assert!(matches!(
            rule_action(&stmts[0]),
            AccessAction::Deny { code: 403 }
        ));
        let conds = rule_conditions(&stmts[0]);
        assert_eq!(conds.len(), 2);
        assert!(matches!(&conds[0], AccessCondition::Country(c) if c == "CN"));
        assert!(matches!(&conds[1], AccessCondition::Country(c) if c == "RU"));
    }

    #[test]
    fn access_pass_action_parses() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    access {
                        pass {
                            ip "10.0.0.0/8"
                        }
                        deny
                    }
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        let stmts = cfg.vhosts[0].locations[0].access.as_ref().unwrap();
        assert!(matches!(rule_action(&stmts[0]), AccessAction::Pass));
        assert!(matches!(
            rule_action(&stmts[1]),
            AccessAction::Deny { code: 403 }
        ));
    }

    #[test]
    fn access_apply_statement_parses() {
        let cfg = Config::parse(
            r#"
            server {
                access-policy "allow-all" {
                    allow
                }
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    access {
                        apply "allow-all"
                        deny
                    }
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        // Named policy stored in server config.
        assert!(cfg.server.access_policies.contains_key("allow-all"));
        // Inline access block has Apply statement.
        let stmts = cfg.vhosts[0].locations[0].access.as_ref().unwrap();
        assert!(matches!(&stmts[0], AccessStatementDef::Apply { name } if name == "allow-all"));
    }

    #[test]
    fn access_named_policy_parsed() {
        let cfg = Config::parse(
            r#"
            server {
                access-policy "geo-filter" {
                    pass {
                        ip "10.0.0.0/8"
                    }
                    deny code=403
                }
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        let stmts = cfg.server.access_policies.get("geo-filter").unwrap();
        assert_eq!(stmts.len(), 2);
        assert!(matches!(rule_action(&stmts[0]), AccessAction::Pass));
    }

    #[test]
    fn access_duplicate_policy_name_is_error() {
        let result = Config::parse(
            r#"
            server {
                access-policy "dup" {
                    allow
                }
                access-policy "dup" {
                    deny
                }
            }
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
        assert!(result.is_err());
    }

    #[test]
    fn error_page_file_path_parses() {
        let cfg = Config::parse(
            r#"
            server {
                error-page 403 "/var/www/errors/403.html"
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        assert_eq!(cfg.server.error_pages.len(), 1);
        assert_eq!(cfg.server.error_pages[0].0, 403);
        assert!(matches!(
            &cfg.server.error_pages[0].1,
            ErrorPageDef::File(p) if p == "/var/www/errors/403.html"
        ));
    }

    #[test]
    fn error_page_inline_html_parses() {
        let cfg = Config::parse(
            r#"
            server {
                error-page 401 html="<h1>Please log in</h1>"
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        assert_eq!(cfg.server.error_pages.len(), 1);
        assert!(matches!(
            &cfg.server.error_pages[0].1,
            ErrorPageDef::Inline(html) if html == "<h1>Please log in</h1>"
        ));
    }

    #[test]
    fn error_page_missing_source_is_error() {
        let result = Config::parse(
            r#"
            server {
                error-page 404
            }
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
        assert!(result.is_err());
    }

    #[test]
    fn location_no_handler_is_error() {
        let result = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn redirect_302() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/temp/" {
                    redirect {
                        to "/new/"
                        code 302
                    }
                }
            }
            "#,
        )
        .unwrap();
        if let HandlerConfig::Redirect { to, code } =
            &cfg.vhosts[0].locations[0].handler
        {
            assert_eq!(code, &302u16);
            assert_eq!(to, "/new/");
        } else {
            panic!("expected Redirect handler");
        }
    }

    #[test]
    fn server_user_defaults_to_none() {
        let cfg = Config::parse(
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
        )
        .unwrap();
        assert!(cfg.server.user.is_none());
        assert!(cfg.server.group.is_none());
    }

    // -- health config ---------------------------------------------

    #[test]
    fn health_enabled_by_default() {
        let cfg = Config::parse(
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
        )
        .unwrap();
        assert!(cfg.server.health.enabled);
    }

    #[test]
    fn health_explicit_enabled_true() {
        let cfg = Config::parse(
            r#"
            server {
                health {
                    enabled true
                }
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        assert!(cfg.server.health.enabled);
    }

    #[test]
    fn health_explicit_enabled_false() {
        let cfg = Config::parse(
            r#"
            server {
                health {
                    enabled false
                }
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        assert!(!cfg.server.health.enabled);
    }

    // -- auth backend ----------------------------------------------

    #[test]
    fn server_auth_pam_default_service() {
        let cfg = Config::parse(
            r#"
            server {
                auth "pam"
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        assert!(matches!(
            cfg.server.auth,
            Some(AuthBackend::Pam { service, .. })
                if service == "login"
        ));
    }

    #[test]
    fn server_auth_pam_explicit_service() {
        let cfg = Config::parse(
            r#"
            server {
                auth "pam" {
                    service "aloha"
                }
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        assert!(matches!(
            cfg.server.auth,
            Some(AuthBackend::Pam { service, .. })
                if service == "aloha"
        ));
    }

    #[test]
    fn server_auth_absent_is_none() {
        let cfg = Config::parse(
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
        )
        .unwrap();
        assert!(cfg.server.auth.is_none());
    }

    #[test]
    fn server_auth_unknown_backend_is_error() {
        let result = Config::parse(
            r#"
            server {
                auth "htpasswd"
            }
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
        assert!(result.is_err());
    }

    #[test]
    fn location_auth_realm_parses() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/admin/" {
                    auth {
                        realm "Admin Area"
                    }
                    access {
                        allow {
                            authenticated
                        }
                        deny code=401
                    }
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        let auth = cfg.vhosts[0].locations[0].auth.as_ref().unwrap();
        assert_eq!(auth.realm, "Admin Area");
    }

    #[test]
    fn location_auth_default_realm() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/secure/" {
                    auth {}
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        let auth = cfg.vhosts[0].locations[0].auth.as_ref().unwrap();
        assert_eq!(auth.realm, "Restricted");
    }

    // -- LDAP auth backend -----------------------------------------

    #[test]
    fn server_auth_ldap_defaults() {
        let cfg = Config::parse(
            r#"
            server {
                auth "ldap" {
                    url "ldap://localhost:389"
                    bind-dn "uid={user},ou=people,dc=example,dc=com"
                    base-dn "ou=groups,dc=example,dc=com"
                }
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        if let Some(AuthBackend::Ldap(c)) = &cfg.server.auth {
            assert_eq!(c.url, "ldap://localhost:389");
            assert_eq!(
                c.bind_dn,
                "uid={user},ou=people,dc=example,dc=com"
            );
            assert_eq!(c.base_dn, "ou=groups,dc=example,dc=com");
            assert_eq!(c.group_filter, "(memberUid={user})");
            assert_eq!(c.group_attr, "cn");
            assert!(!c.starttls);
            assert_eq!(c.timeout_secs, 5);
        } else {
            panic!("expected AuthBackend::Ldap");
        }
    }

    #[test]
    fn server_auth_ldap_explicit_options() {
        let cfg = Config::parse(
            r#"
            server {
                auth "ldap" {
                    url "ldaps://ldap.example.com:636"
                    bind-dn "uid={user},ou=people,dc=example,dc=com"
                    base-dn "ou=groups,dc=example,dc=com"
                    group-filter "(member=uid={user},ou=people,dc=example,dc=com)"
                    group-attr "cn"
                    starttls false
                    timeout 10
                }
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        if let Some(AuthBackend::Ldap(c)) = &cfg.server.auth {
            assert_eq!(c.url, "ldaps://ldap.example.com:636");
            assert_eq!(
                c.group_filter,
                "(member=uid={user},ou=people,dc=example,dc=com)"
            );
            assert_eq!(c.timeout_secs, 10);
        } else {
            panic!("expected AuthBackend::Ldap");
        }
    }

    #[test]
    fn server_auth_ldap_unix_socket_url() {
        let cfg = Config::parse(
            r#"
            server {
                auth "ldap" {
                    url "ldapi:///var/run/slapd/ldapi"
                    bind-dn "uid={user},ou=people,dc=example,dc=com"
                    base-dn "ou=groups,dc=example,dc=com"
                }
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        if let Some(AuthBackend::Ldap(c)) = &cfg.server.auth {
            assert_eq!(c.url, "ldapi:///var/run/slapd/ldapi");
        } else {
            panic!("expected AuthBackend::Ldap");
        }
    }

    #[test]
    fn server_auth_ldap_missing_url_is_error() {
        let result = Config::parse(
            r#"
            server {
                auth "ldap" {
                    bind-dn "uid={user},ou=people,dc=example,dc=com"
                    base-dn "ou=groups,dc=example,dc=com"
                }
            }
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
        assert!(result.is_err());
    }

    #[test]
    fn server_auth_ldap_missing_bind_dn_is_error() {
        let result = Config::parse(
            r#"
            server {
                auth "ldap" {
                    url "ldap://localhost:389"
                    base-dn "ou=groups,dc=example,dc=com"
                }
            }
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
        assert!(result.is_err());
    }

    #[test]
    fn server_auth_ldap_missing_base_dn_is_error() {
        let result = Config::parse(
            r#"
            server {
                auth "ldap" {
                    url "ldap://localhost:389"
                    bind-dn "uid={user},ou=people,dc=example,dc=com"
                }
            }
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
        assert!(result.is_err());
    }

    #[test]
    fn server_auth_ldap_invalid_url_scheme_is_error() {
        let result = Config::parse(
            r#"
            server {
                auth "ldap" {
                    url "http://localhost:389"
                    bind-dn "uid={user},ou=people,dc=example,dc=com"
                    base-dn "ou=groups,dc=example,dc=com"
                }
            }
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
        assert!(result.is_err());
    }

    #[test]
    fn server_auth_ldap_bind_dn_without_placeholder_is_error() {
        let result = Config::parse(
            r#"
            server {
                auth "ldap" {
                    url "ldap://localhost:389"
                    bind-dn "cn=readonly,dc=example,dc=com"
                    base-dn "ou=groups,dc=example,dc=com"
                }
            }
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
        assert!(result.is_err());
    }

    #[test]
    fn server_auth_ldap_starttls_parses() {
        let cfg = Config::parse(
            r#"
            server {
                auth "ldap" {
                    url "ldap://localhost:389"
                    bind-dn "uid={user},ou=people,dc=example,dc=com"
                    base-dn "ou=groups,dc=example,dc=com"
                    starttls true
                }
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap();
        if let Some(AuthBackend::Ldap(c)) = &cfg.server.auth {
            assert!(c.starttls);
        } else {
            panic!("expected AuthBackend::Ldap");
        }
    }

    #[test]
    fn server_auth_unknown_backend_error_mentions_ldap() {
        let err = Config::parse(
            r#"
            server {
                auth "kerberos"
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
            "#,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("ldap"),
            "error should mention 'ldap': {msg}"
        );
    }

    #[test]
    fn location_auth_absent_is_none() {
        let cfg = Config::parse(
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
        )
        .unwrap();
        assert!(cfg.vhosts[0].locations[0].auth.is_none());
    }

    // -- request-headers / response-headers parsing ---------------

    #[test]
    fn request_headers_set_parses() {
        let cfg = Config::parse(r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    request-headers {
                        set "X-Client-IP" "{client_ip}"
                    }
                    static { root "."; }
                }
            }
        "#).unwrap();
        let ops = &cfg.vhosts[0].locations[0].request_headers;
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], HeaderOpConfig::Set { name, value }
            if name == "X-Client-IP" && value == "{client_ip}"));
    }

    #[test]
    fn request_headers_add_parses() {
        let cfg = Config::parse(r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    request-headers {
                        add "Vary" "accept"
                    }
                    static { root "."; }
                }
            }
        "#).unwrap();
        let ops = &cfg.vhosts[0].locations[0].request_headers;
        assert!(matches!(&ops[0], HeaderOpConfig::Add { .. }));
    }

    #[test]
    fn request_headers_remove_parses() {
        let cfg = Config::parse(r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    request-headers {
                        remove "Authorization"
                    }
                    static { root "."; }
                }
            }
        "#).unwrap();
        let ops = &cfg.vhosts[0].locations[0].request_headers;
        assert!(matches!(&ops[0],
            HeaderOpConfig::Remove { name } if name == "Authorization"));
    }

    #[test]
    fn response_headers_parses() {
        let cfg = Config::parse(r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    response-headers {
                        set "X-Frame-Options" "DENY"
                    }
                    static { root "."; }
                }
            }
        "#).unwrap();
        let ops = &cfg.vhosts[0].locations[0].response_headers;
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0],
            HeaderOpConfig::Set { name, value }
                if name == "X-Frame-Options" && value == "DENY"));
    }

    #[test]
    fn header_rules_absent_means_empty_vecs() {
        let cfg = Config::parse(r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
        "#).unwrap();
        assert!(cfg.vhosts[0].locations[0].request_headers.is_empty());
        assert!(cfg.vhosts[0].locations[0].response_headers.is_empty());
    }

    #[test]
    fn invalid_header_name_is_error() {
        let result = Config::parse(r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    request-headers {
                        set "not valid!" "value"
                    }
                    static { root "."; }
                }
            }
        "#);
        assert!(result.is_err());
    }

    #[test]
    fn unknown_op_in_request_headers_is_error() {
        let result = Config::parse(r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    request-headers {
                        prepend "X-Foo" "bar"
                    }
                    static { root "."; }
                }
            }
        "#);
        assert!(result.is_err());
    }
}
