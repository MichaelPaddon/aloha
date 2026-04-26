use crate::auth::{AuthPolicy, AuthRule};
use anyhow::{anyhow, bail, Context};
use kdl::{KdlDocument, KdlNode};
use miette::Diagnostic as _;
use std::path::Path;
use regex::Regex;

// ── Public types ──────────────────────────────────────────────────

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

#[derive(Debug, Clone)]
pub struct ListenerConfig {
    // Exactly one of bind or fd must be set (enforced by validate).
    pub bind: Option<String>,
    // Raw file descriptor — used for systemd socket activation.
    pub fd: Option<i32>,
    pub tls: Option<TlsListenerConfig>,
    pub default_vhost: Option<String>,
    pub timeouts: Timeouts,
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
/// is `SelfSigned` — an ephemeral certificate generated at startup,
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
    // None = open; Some = require authentication matching the policy.
    pub auth: Option<AuthPolicy>,
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
    },
    Redirect {
        to: String,
        code: u16,
    },
    FastCgi {
        socket: String,
        index: Option<String>,
    },
}

// ── Config loading ────────────────────────────────────────────────

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
                anyhow!("line {line}: syntax error — `{snippet}`")
            } else {
                anyhow!("{name}:{line}: syntax error — `{snippet}`")
            }
        })?;
        let mut config = Config::default();
        // Raw default-vhost specs, one per listener, in order:
        //   None          – child node absent; resolved to first vhost
        //   Some(None)    – explicit null; no fallback vhost
        //   Some(Some(s)) – named vhost
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
        // Resolve: absent → first vhost name, null → None, named → Some(s).
        let first = config.vhosts.first().map(|v| v.name.clone());
        for (listener, raw) in
            config.listeners.iter_mut().zip(raw_defaults)
        {
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
        if self.vhosts.is_empty() {
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

// ── Node parsers ──────────────────────────────────────────────────

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
    Ok(ServerConfig {
        state_dir: child_str(node, "state-dir"),
        tls_defaults,
        user:  child_str(node, "user"),
        group: child_str(node, "group"),
    })
}

// Returns (config, raw_default_vhost) where raw_default_vhost is:
//   None          – child node absent; resolved to first vhost
//   Some(None)    – explicitly set to null
//   Some(Some(s)) – explicitly set to a hostname string
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
    // bind/fd mutual-exclusion is checked in Config::validate.
    // default_vhost is resolved later in Config::parse.
    Ok((
        ListenerConfig { bind, fd, tls, default_vhost: None, timeouts },
        raw_default_vhost,
    ))
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
                "static" | "proxy" | "redirect" | "fastcgi"
            )
        })
        .ok_or_else(|| {
            anyhow!("{name}:{line}: location '{path}' has no handler node")
        })?;
    let handler = parse_handler(handler_node, src, name, &path)?;
    let auth = children
        .iter()
        .find(|n| n.name().value() == "auth")
        .map(|n| parse_auth_policy(n, src, name))
        .transpose()?;
    Ok(LocationConfig { path, handler, auth })
}

// Auth rules use node names as rule types — idiomatic KDL avoids
// bare identifiers as values (only strings, numbers, bools are valid).
//
//   auth {
//       group "admin" "superuser"  // in admin OR superuser
//       user  "alice"              // OR: exactly alice
//       authenticated              // OR: any logged-in user
//       deny {
//           user "mallory"         // ban this user despite allow rules
//       }
//   }
fn parse_auth_policy(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<AuthPolicy> {
    let line = node_line(src, node);
    let children =
        node.children().map(|d| d.nodes()).unwrap_or_default();
    let mut allow = Vec::new();
    let mut deny = Vec::new();
    for child in children {
        let child_line = node_line(src, child);
        match child.name().value() {
            "deny" => {
                parse_auth_rules(child, src, name, &mut deny)?;
            }
            kind => {
                parse_auth_rule_node(
                    kind,
                    child,
                    child_line,
                    name,
                    &mut allow,
                )?;
            }
        }
    }
    if allow.is_empty() {
        bail!("{name}:{line}: auth block has no allow rules");
    }
    Ok(AuthPolicy { allow, deny })
}

// Parse rule nodes from a `deny { … }` or the top-level `auth { … }` block.
fn parse_auth_rules(
    node: &KdlNode,
    src: &str,
    name: &str,
    out: &mut Vec<AuthRule>,
) -> anyhow::Result<()> {
    let children =
        node.children().map(|d| d.nodes()).unwrap_or_default();
    for child in children {
        let child_line = node_line(src, child);
        parse_auth_rule_node(
            child.name().value(),
            child,
            child_line,
            name,
            out,
        )?;
    }
    Ok(())
}

// Parse a single rule node (e.g. `group "admin" "superuser"`) and
// push one `AuthRule` per argument into `out`.  Multiple arguments
// expand to multiple OR-combined rules.
fn parse_auth_rule_node(
    kind: &str,
    node: &KdlNode,
    line: usize,
    name: &str,
    out: &mut Vec<AuthRule>,
) -> anyhow::Result<()> {
    match kind {
        "authenticated" => out.push(AuthRule::Authenticated),
        "user" => {
            let names = req_arg_strs(node, "user", line, name)?;
            out.extend(names.into_iter().map(AuthRule::User));
        }
        "group" => {
            let names = req_arg_strs(node, "group", line, name)?;
            out.extend(names.into_iter().map(AuthRule::Group));
        }
        other => bail!(
            "{name}:{line}: unknown auth rule '{other}'; \
             expected 'authenticated', 'user', or 'group'"
        ),
    }
    Ok(())
}

// Collect one or more string arguments from a node, erroring if none.
fn req_arg_strs(
    node: &KdlNode,
    kind: &str,
    line: usize,
    name: &str,
) -> anyhow::Result<Vec<String>> {
    let mut vals = Vec::new();
    let mut i = 0;
    while let Some(v) = arg_str(node, i) {
        vals.push(v);
        i += 1;
    }
    if vals.is_empty() {
        bail!(
            "{name}:{line}: '{kind}' needs at least one argument"
        );
    }
    Ok(vals)
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
            Ok(HandlerConfig::Proxy { upstream })
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
            let index = child_str(node, "index");
            Ok(HandlerConfig::FastCgi { socket, index })
        }
        other => bail!(
            "{name}:{line}: unknown handler '{other}' \
             in location '{location_path}'"
        ),
    }
}

// ── KDL access helpers ────────────────────────────────────────────
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

// ── Tests ─────────────────────────────────────────────────────────

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
                    fastcgi { socket "unix:/run/php/fpm.sock"; }
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

    // ── default-vhost resolution ───────────────────────────────────

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
        // Absent → first vhost; null → no default.
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

    // ── timeouts ──────────────────────────────────────────────────

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

    // ── server user/group ─────────────────────────────────────────

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

    // ── auth blocks ───────────────────────────────────────────────

    #[test]
    fn auth_group_rule_parses() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/admin/" {
                    auth {
                        group "admin"
                    }
                    static {
                        root "/var/www/admin"
                    }
                }
            }
            "#,
        )
        .unwrap();
        let auth = cfg.vhosts[0].locations[0].auth.as_ref().unwrap();
        assert_eq!(auth.allow.len(), 1);
        assert!(matches!(
            &auth.allow[0],
            AuthRule::Group(g) if g == "admin"
        ));
    }

    #[test]
    fn auth_multiple_rules_parse() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/secret/" {
                    auth {
                        group "admin"
                        user "alice"
                    }
                    static {
                        root "/var/www/secret"
                    }
                }
            }
            "#,
        )
        .unwrap();
        let auth = cfg.vhosts[0].locations[0].auth.as_ref().unwrap();
        assert_eq!(auth.allow.len(), 2);
        assert!(matches!(&auth.allow[0], AuthRule::Group(g) if g == "admin"));
        assert!(matches!(&auth.allow[1], AuthRule::User(u) if u == "alice"));
    }

    #[test]
    fn auth_authenticated_rule_parses() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/members/" {
                    auth {
                        authenticated
                    }
                    static {
                        root "/var/www/members"
                    }
                }
            }
            "#,
        )
        .unwrap();
        let auth = cfg.vhosts[0].locations[0].auth.as_ref().unwrap();
        assert!(matches!(&auth.allow[0], AuthRule::Authenticated));
    }

    #[test]
    fn auth_absent_means_open() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static {
                        root "."
                    }
                }
            }
            "#,
        )
        .unwrap();
        assert!(cfg.vhosts[0].locations[0].auth.is_none());
    }

    #[test]
    fn auth_empty_block_is_error() {
        let result = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    auth {
                    }
                    static {
                        root "."
                    }
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn auth_unknown_require_type_is_error() {
        let result = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    auth {
                        role "admin"
                    }
                    static {
                        root "."
                    }
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn auth_multi_arg_group_expands_to_or_rules() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    auth {
                        group "admin" "superuser"
                    }
                    static {
                        root "."
                    }
                }
            }
            "#,
        )
        .unwrap();
        let auth = cfg.vhosts[0].locations[0].auth.as_ref().unwrap();
        assert_eq!(auth.allow.len(), 2);
        assert!(matches!(&auth.allow[0], AuthRule::Group(g) if g == "admin"));
        assert!(
            matches!(&auth.allow[1], AuthRule::Group(g) if g == "superuser")
        );
    }

    #[test]
    fn auth_multi_arg_user_expands_to_or_rules() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    auth {
                        user "alice" "bob"
                    }
                    static {
                        root "."
                    }
                }
            }
            "#,
        )
        .unwrap();
        let auth = cfg.vhosts[0].locations[0].auth.as_ref().unwrap();
        assert_eq!(auth.allow.len(), 2);
        assert!(matches!(&auth.allow[0], AuthRule::User(u) if u == "alice"));
        assert!(matches!(&auth.allow[1], AuthRule::User(u) if u == "bob"));
    }

    #[test]
    fn auth_deny_block_parses() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    auth {
                        group "users"
                        deny {
                            user "mallory"
                            group "suspended"
                        }
                    }
                    static {
                        root "."
                    }
                }
            }
            "#,
        )
        .unwrap();
        let auth = cfg.vhosts[0].locations[0].auth.as_ref().unwrap();
        assert_eq!(auth.allow.len(), 1);
        assert!(matches!(&auth.allow[0], AuthRule::Group(g) if g == "users"));
        assert_eq!(auth.deny.len(), 2);
        assert!(matches!(&auth.deny[0], AuthRule::User(u) if u == "mallory"));
        assert!(
            matches!(&auth.deny[1], AuthRule::Group(g) if g == "suspended")
        );
    }

    #[test]
    fn auth_deny_without_allow_is_error() {
        let result = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    auth {
                        deny {
                            user "mallory"
                        }
                    }
                    static {
                        root "."
                    }
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn auth_deny_multi_arg_expands() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    auth {
                        authenticated
                        deny {
                            user "mallory" "eve"
                        }
                    }
                    static {
                        root "."
                    }
                }
            }
            "#,
        )
        .unwrap();
        let auth = cfg.vhosts[0].locations[0].auth.as_ref().unwrap();
        assert_eq!(auth.deny.len(), 2);
        assert!(matches!(&auth.deny[0], AuthRule::User(u) if u == "mallory"));
        assert!(matches!(&auth.deny[1], AuthRule::User(u) if u == "eve"));
    }

    #[test]
    fn auth_group_missing_arg_is_error() {
        let result = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    auth {
                        group
                    }
                    static {
                        root "."
                    }
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn auth_user_missing_arg_is_error() {
        let result = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    auth {
                        user
                    }
                    static {
                        root "."
                    }
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn auth_deny_unknown_rule_is_error() {
        let result = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    auth {
                        authenticated
                        deny {
                            role "admin"
                        }
                    }
                    static {
                        root "."
                    }
                }
            }
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn auth_mixed_allow_rule_types() {
        let cfg = Config::parse(
            r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    auth {
                        authenticated
                        user "alice"
                        group "admin"
                    }
                    static {
                        root "."
                    }
                }
            }
            "#,
        )
        .unwrap();
        let auth = cfg.vhosts[0].locations[0].auth.as_ref().unwrap();
        assert_eq!(auth.allow.len(), 3);
        assert!(matches!(&auth.allow[0], AuthRule::Authenticated));
        assert!(matches!(&auth.allow[1], AuthRule::User(u) if u == "alice"));
        assert!(matches!(&auth.allow[2], AuthRule::Group(g) if g == "admin"));
        assert!(auth.deny.is_empty());
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
}
