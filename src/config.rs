// KDL configuration file parsing and validation.
//
// Config::load() reads a .kdl file; Config::parse() accepts a string
// (used in tests).  All fields are resolved to concrete values before
// validate() is called so downstream code never sees partial state.

use crate::access::{AccessAction, AccessCondition, AccessPolicy, AccessRule};
use anyhow::{anyhow, bail, Context};
use kdl::{KdlDocument, KdlNode};
use miette::Diagnostic as _;
use std::path::Path;
use regex::Regex;

// -- Public types --------------------------------------------------

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
    // Authentication back-end; None means anonymous-only.
    pub auth: Option<AuthBackend>,
}

/// Authentication back-end activated at the server level.
#[derive(Debug, Clone)]
pub enum AuthBackend {
    /// Validate HTTP Basic credentials against the PAM stack.
    /// `service` is the PAM service name, e.g. `"login"`.
    Pam { service: String },
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
    /// LDAP server URL, e.g. `ldap://localhost:389` or
    /// `ldapi:///var/run/slapd/ldapi`.
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

#[derive(Debug)]
pub struct LocationConfig {
    // URL path prefix; locations are tested in config order.
    pub path: String,
    pub handler: HandlerConfig,
    // Firewall-style access policy (IP + identity rules).
    pub access: Option<AccessPolicy>,
    // HTTP Basic auth realm; None means no WWW-Authenticate challenge.
    pub auth: Option<BasicAuthConfig>,
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
    Ok(ServerConfig {
        state_dir: child_str(node, "state-dir"),
        tls_defaults,
        user:  child_str(node, "user"),
        group: child_str(node, "group"),
        auth,
    })
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
            Ok(AuthBackend::Pam { service })
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

            Ok(AuthBackend::Ldap(LdapAuthConfig {
                url,
                bind_dn,
                base_dn,
                group_filter,
                group_attr,
                starttls,
                timeout_secs,
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
    Ok(TcpProxyConfig { upstream, proxy_protocol })
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
        .map(|n| parse_access_policy(n, src, name))
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
    Ok(LocationConfig { path, handler, access, auth })
}

// Parse an `access { }` block into an AccessPolicy.
//
//   access {
//       allow { ip "10.0.0.0/8"; group "admin" }
//       deny code=403 { ip "1.2.3.4" }
//       redirect to="/login/" { user "unverified" }
//       deny code=403      // catch-all: no children = always matches
//   }
fn parse_access_policy(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<AccessPolicy> {
    use ipnet::IpNet;
    use std::net::IpAddr;

    let children =
        node.children().map(|d| d.nodes()).unwrap_or_default();
    let mut rules = Vec::new();

    for child in children {
        let child_line = node_line(src, child);
        let action = match child.name().value() {
            "allow" => AccessAction::Allow,
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
                "{name}:{child_line}: unknown access rule '{other}'; \
                 expected 'allow', 'deny', or 'redirect'"
            ),
        };

        // Parse conditions from child nodes.
        let cond_nodes = child
            .children()
            .map(|d| d.nodes())
            .unwrap_or_default();
        let mut conditions = Vec::new();
        for cond in cond_nodes {
            let cond_line = node_line(src, cond);
            match cond.name().value() {
                "ip" => {
                    let s = req_arg_str(cond, 0).with_context(|| {
                        format!("{name}:{cond_line}")
                    })?;
                    // Try CIDR notation first, then plain IP address.
                    let net: IpNet = s
                        .parse()
                        .or_else(|_| {
                            s.parse::<IpAddr>().map(IpNet::from)
                        })
                        .map_err(|_| {
                            anyhow!(
                                "{name}:{cond_line}: invalid IP \
                                 address or CIDR '{s}'"
                            )
                        })?;
                    conditions.push(AccessCondition::Ip(net));
                }
                "user" => {
                    let u = req_arg_str(cond, 0).with_context(|| {
                        format!("{name}:{cond_line}")
                    })?;
                    conditions.push(AccessCondition::User(u));
                }
                "group" => {
                    let g = req_arg_str(cond, 0).with_context(|| {
                        format!("{name}:{cond_line}")
                    })?;
                    conditions.push(AccessCondition::Group(g));
                }
                "authenticated" => {
                    conditions.push(AccessCondition::Authenticated);
                }
                other => bail!(
                    "{name}:{cond_line}: unknown access condition \
                     '{other}'; expected 'ip', 'user', 'group', \
                     or 'authenticated'"
                ),
            }
        }

        rules.push(AccessRule { conditions, action });
    }

    Ok(AccessPolicy { rules })
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
    fn status_handler_parses() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/_status" {
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


        // -- access blocks ---------------------------------------------

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
        let policy = cfg.vhosts[0].locations[0].access.as_ref().unwrap();
        assert_eq!(policy.rules.len(), 2);
        assert!(matches!(&policy.rules[0].action, AccessAction::Allow));
        assert!(matches!(
            &policy.rules[1].action,
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
        let policy = cfg.vhosts[0].locations[0].access.as_ref().unwrap();
        assert!(matches!(
            &policy.rules[0].action,
            AccessAction::Deny { code: 429 }
        ));
        assert_eq!(policy.rules[0].conditions.len(), 1);
        assert!(matches!(
            &policy.rules[0].conditions[0],
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
        let policy = cfg.vhosts[0].locations[0].access.as_ref().unwrap();
        assert!(matches!(
            &policy.rules[0].action,
            AccessAction::Redirect { code: 302, .. }
        ));
        if let AccessAction::Redirect { to, .. } = &policy.rules[0].action {
            assert_eq!(to, "/login/");
        }
        assert!(matches!(
            &policy.rules[0].conditions[0],
            AccessCondition::User(u) if u == "unverified"
        ));
    }

    #[test]
    fn access_empty_block_has_zero_rules() {
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
        let policy = cfg.vhosts[0].locations[0].access.as_ref().unwrap();
        assert_eq!(policy.rules.len(), 0);
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
        let policy = cfg.vhosts[0].locations[0].access.as_ref().unwrap();
        assert!(matches!(
            &policy.rules[0].conditions[0],
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
        let policy = cfg.vhosts[0].locations[0].access.as_ref().unwrap();
        assert!(matches!(
            &policy.rules[0].conditions[0],
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
        let policy = cfg.vhosts[0].locations[0].access.as_ref().unwrap();
        assert!(matches!(
            &policy.rules[0].conditions[0],
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
        let policy = cfg.vhosts[0].locations[0].access.as_ref().unwrap();
        // deny rule has no conditions -> catch-all
        assert!(policy.rules[1].conditions.is_empty());
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
            Some(AuthBackend::Pam { service })
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
            Some(AuthBackend::Pam { service })
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
}
