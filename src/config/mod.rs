// KDL configuration file parsing and validation.
//
// Config::load() reads a .kdl file; Config::parse() accepts a string
// (used in tests).  All fields are resolved to concrete values before
// validate() is called so downstream code never sees partial state.

use crate::access::{PolicyAction, Predicate};
use ::kdl::KdlDocument;
use anyhow::{Context, anyhow, bail};
use hyper::header::HeaderName;
use miette::Diagnostic as _;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;

mod kdl;
mod parse;
use parse::{
    node_line, parse_certificate, parse_listener, parse_server, parse_vhost,
};
#[cfg(test)]
mod tests;

// -- Public types --------------------------------------------------

/// Unresolved policy rule as parsed from KDL.  Apply references are
/// inlined to a flat Vec<PolicyRule> in router.rs during resolution.
#[derive(Debug, Clone)]
pub enum PolicyRuleDef {
    Rule {
        predicate: Option<Predicate>,
        action: PolicyAction,
    },
    /// Inline the named policy's rules at this point.
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
    // Top-level named certificate definitions.  Listeners refer to
    // these by name via `tls cert="<name>"`, so a single ACME manager
    // and on-disk certificate directory can be shared across listeners.
    pub certificates: Vec<CertificateDef>,
}

/// A named certificate defined at the top level of the config.  Multiple
/// listeners may reference the same definition; at startup it produces
/// exactly one acceptor (and, for ACME, one renewal loop) that is shared
/// among them via `Arc<ArcSwap<TlsAcceptor>>`.
#[derive(Debug, Clone)]
pub struct CertificateDef {
    pub name: String,
    /// The certificate source.  Never `TlsConfig::Ref` (refs cannot
    /// nest); validated at parse time.
    pub source: TlsConfig,
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
    // startup (e.g. from podman --group-add keep-groups) survive the
    // privilege drop.  Only set this in controlled container environments
    // where the inherited groups are known and intentional.
    pub inherit_supplementary_groups: bool,
    // Authentication back-end; None means anonymous-only.
    pub auth: Option<AuthBackend>,
    // GeoIP database configuration; None means no geo conditions can be used.
    pub geoip: Option<GeoIpConfig>,
    pub health: HealthConfig,
    // Named policy blocks available to all vhosts/locations.
    pub policies: HashMap<String, Vec<PolicyRuleDef>>,
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
    Pam { service: String },
    /// Validate HTTP Basic credentials via an LDAP simple bind.
    Ldap(LdapAuthConfig),
    /// Delegate to an external HTTP endpoint.
    /// GET is sent with forwarded request headers; HTTP 200 means
    /// authenticated, any other status means anonymous.
    Subrequest(SubrequestAuthConfig),
    /// Issue and/or validate ES256 JWT session cookies.
    /// `inner` is the credential back-end used on first login; when
    /// absent, the manager only validates incoming tokens (standalone).
    Jwt {
        cookie_name: String,
        validity_secs: u64,
        inner: Option<Box<AuthBackend>>,
    },
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
}

/// Configuration for subrequest-based authentication.
///
/// Makes an outgoing HTTP GET to `url`, forwarding the listed request
/// headers.  A 200 response means authenticated; any other status or a
/// network error means anonymous.
#[derive(Debug, Clone)]
pub struct SubrequestAuthConfig {
    /// URL to call for every authentication decision.
    /// Must use `http://` scheme (HTTP only for now).
    pub url: String,
    /// Request headers forwarded verbatim to the auth endpoint.
    /// Typically `["Authorization"]` or `["Cookie"]`.
    pub forward_headers: Vec<String>,
    /// Response header whose value becomes the authenticated username.
    /// `None` → empty username (still treated as `Authenticated`).
    pub user_header: Option<String>,
    /// Response header holding a comma-separated list of group names.
    pub groups_header: Option<String>,
    /// Seconds to wait for the auth endpoint before returning
    /// `Anonymous`.  Defaults to 5.
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
pub enum ProxyProtocolVersion {
    V1,
    V2,
}

/// Stream proxy mode for a listener: forward raw bytes to an upstream
/// instead of doing HTTP routing.  Set via a `proxy` child on a `listener`
/// block.  TLS termination (for the incoming connection) is still
/// configured with `tls-*` on the listener itself.
#[derive(Debug, Clone)]
pub struct StreamMode {
    /// Upstream address: `"host:port"` for TCP or `"unix:/path"` for
    /// a Unix domain socket.
    pub upstream: String,
    /// When set, connect to the upstream using TLS (re-encryption).
    /// Only valid for TCP upstreams; unix socket upstreams ignore this.
    pub upstream_tls: Option<UpstreamTlsConfig>,
    /// Prepend a PROXY protocol header so the backend sees the real
    /// client IP even though it only sees aloha's connection.
    pub proxy_protocol: Option<ProxyProtocolVersion>,
    /// Optional IP/country-based access control.  User, group, and
    /// `authenticated` predicates are rejected at parse time because
    /// stream listeners have no HTTP authentication layer.
    pub policy: Option<Vec<PolicyRuleDef>>,
}

/// TLS options for the upstream connection in stream proxy mode.
#[derive(Debug, Clone)]
pub struct UpstreamTlsConfig {
    /// Skip certificate verification.  Only use for internal or dev
    /// upstreams with self-signed certificates.
    pub skip_verify: bool,
}

#[derive(Debug, Clone)]
pub struct ListenerConfig {
    // Bind address: "host:port" for TCP or "unix:/path" for Unix sockets.
    pub bind: String,
    pub tls: Option<TlsListenerConfig>,
    // When Some: stream proxy mode (forward raw bytes to upstream).
    // When None: HTTP routing mode (vhost/location dispatch).
    pub stream: Option<StreamMode>,
    // When set, read and strip a PROXY protocol header immediately after
    // accept(), before TLS or HTTP parsing.  The header's source address
    // replaces the TCP peer address for the duration of the connection.
    // Use when aloha sits behind HAProxy or another load balancer that
    // speaks PROXY protocol on the incoming side.
    pub accept_proxy_protocol: Option<ProxyProtocolVersion>,
    // HTTP-only fields; unused in stream mode:
    pub default_vhost: Option<String>,
    pub timeouts: Timeouts,
    // Cap on simultaneous open connections; None = unlimited.
    // New connections are deferred (not dropped) at the limit.
    pub max_connections: Option<u32>,
    // Reject requests whose Content-Length exceeds this (bytes).
    // None = unlimited.  Checked before any handler runs.
    pub max_request_body: Option<u64>,
}

impl ListenerConfig {
    // Canonical string identifier used as the router key and in logs.
    pub fn local_name(&self) -> String {
        self.bind.clone()
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
    /// Reference to a top-level `certificate "<name>" { ... }`.
    /// Refs cannot nest; the referent is always a concrete source.
    Ref(String),
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

/// A vhost name or alias.  `regex == true` means the value is an
/// (anchored, `^(?:...)$`) regex matched against the request Host;
/// otherwise it is a literal hostname.
#[derive(Debug, Clone)]
pub struct VHostName {
    pub value: String,
    pub regex: bool,
}

#[derive(Debug)]
pub struct VHostConfig {
    // Primary hostname; also used as the map key in the router.
    pub name: VHostName,
    pub aliases: Vec<VHostName>,
    pub locations: Vec<LocationConfig>,
}

/// Config-level header operation: raw strings before name validation.
/// Converted to `headers::HeaderOp` (validated) in `router.rs`.
#[derive(Debug, Clone)]
pub enum HeaderOpConfig {
    Set { name: String, value: String },
    Add { name: String, value: String },
    Remove { name: String },
}

impl HeaderOpConfig {
    pub fn header_name(&self) -> &str {
        match self {
            HeaderOpConfig::Set { name, .. }
            | HeaderOpConfig::Add { name, .. }
            | HeaderOpConfig::Remove { name } => name,
        }
    }
}

#[derive(Debug)]
pub struct LocationConfig {
    // URL path prefix; locations are tested in config order.
    pub path: String,
    pub handler: HandlerConfig,
    // Firewall-style access policy (unresolved; resolved in router.rs).
    pub policy: Option<Vec<PolicyRuleDef>>,
    // HTTP Basic auth realm; None means no WWW-Authenticate challenge.
    pub auth: Option<BasicAuthConfig>,
    // Header rules applied before the handler sees the request.
    pub request_headers: Vec<HeaderOpConfig>,
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
        proxy_protocol: Option<ProxyProtocolVersion>,
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
    /// Return 200 + identity headers; the surrounding `access` block
    /// handles the actual authentication and authorisation decision
    /// before this handler is reached.
    AuthRequest,
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
        let doc: KdlDocument = text.parse().map_err(|e: ::kdl::KdlError| {
            // KDL's own error message is a generic placeholder ("An
            // unspecified error occurred.").  Extract the byte offset
            // from the miette label instead and compute a line number.
            let offset = e
                .labels()
                .and_then(|mut it| it.next())
                .map(|l| l.offset())
                .unwrap_or(0)
                .min(text.len());
            let line =
                text[..offset].bytes().filter(|&b| b == b'\n').count() + 1;
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
                    let (listener, raw) = parse_listener(node, text, name)?;
                    config.listeners.push(listener);
                    raw_defaults.push(raw);
                }
                "vhost" => {
                    config.vhosts.push(parse_vhost(node, text, name)?);
                }
                "certificate" => {
                    config
                        .certificates
                        .push(parse_certificate(node, text, name)?);
                }
                other => {
                    bail!("{name}:{line}: unknown top-level node '{other}'")
                }
            }
        }
        // Resolve: absent -> first vhost name, null -> None, named -> Some(s).
        // Stream listeners have no default_vhost; skip the assignment for them.
        let first = config.vhosts.first().map(|v| v.name.value.clone());
        for (listener, raw) in config.listeners.iter_mut().zip(raw_defaults) {
            if listener.stream.is_none() {
                listener.default_vhost = match raw {
                    None => first.clone(),
                    Some(None) => None,
                    Some(Some(name)) => Some(name),
                };
            }
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.listeners.is_empty() {
            bail!("config must define at least one listener");
        }
        // Vhosts are only required when at least one HTTP listener is present.
        let has_http = self.listeners.iter().any(|l| l.stream.is_none());
        if has_http && self.vhosts.is_empty() {
            bail!("config must define at least one vhost");
        }
        // Verify unix socket paths are non-empty.
        for (i, l) in self.listeners.iter().enumerate() {
            if let Some(path) = l.bind.strip_prefix("unix:")
                && path.is_empty()
            {
                bail!("listener[{i}] unix socket path is empty");
            }
        }
        // JWT mode requires a state_dir for key storage.
        if matches!(self.server.auth, Some(AuthBackend::Jwt { .. }))
            && self.server.state_dir.is_none()
        {
            bail!(
                "server.state-dir is required when auth jwt is \
                 configured"
            );
        }
        // Certificate names must be unique.
        {
            let mut seen: HashSet<&str> = HashSet::new();
            for c in &self.certificates {
                if !seen.insert(c.name.as_str()) {
                    bail!("duplicate certificate name '{}'", c.name);
                }
            }
        }
        // Every listener `TlsConfig::Ref` must resolve.
        for (i, l) in self.listeners.iter().enumerate() {
            if let Some(t) = &l.tls
                && let TlsConfig::Ref(name) = &t.cert
                && !self.certificates.iter().any(|c| &c.name == name)
            {
                bail!(
                    "listener[{i}] references unknown certificate \
                     '{name}'; define it at the top level with \
                     `certificate \"{name}\" {{ ... }}`"
                );
            }
        }
        // ACME mode requires a state_dir for cert/account storage.
        // Detect ACME via direct usage *or* a Ref that resolves to ACME.
        let uses_acme = self
            .listeners
            .iter()
            .filter_map(|l| l.tls.as_ref())
            .any(|t| {
                self.resolve_cert(&t.cert)
                    .is_some_and(|c| matches!(c, TlsConfig::Acme { .. }))
            })
            || self
                .certificates
                .iter()
                .any(|c| matches!(c.source, TlsConfig::Acme { .. }));
        if uses_acme && self.server.state_dir.is_none() {
            bail!(
                "server.state-dir is required when any listener \
                 uses tls mode=acme"
            );
        }
        // On-disk identity check: two distinct cert sources cannot
        // claim the same persistent storage slot.  For ACME this is
        // the cert directory name (explicit `name` or domains[0]); for
        // file-based certs it is the (cert_path, key_path) tuple.  This
        // catches the historical foot-gun of two listeners each carrying
        // an inline `tls-acme` block with the same default name.
        self.check_cert_identity_conflicts()?;
        // Validate regex syntax for any vhost name or alias flagged
        // with regex=#true.  Compile errors are caught here rather
        // than at the first incoming request.
        for v in &self.vhosts {
            let names = std::iter::once(&v.name).chain(v.aliases.iter());
            for n in names {
                if n.regex {
                    Regex::new(&n.value).with_context(|| {
                        format!("invalid regex in vhost name '{}'", n.value,)
                    })?;
                }
            }
        }
        // Verify every default-vhost reference resolves (HTTP listeners only).
        let known = self.vhost_names();
        for (i, l) in self.listeners.iter().enumerate() {
            if l.stream.is_none()
                && let Some(ref name) = l.default_vhost
                && !known.contains(name.as_str())
            {
                bail!(
                    "listener[{i}] default-vhost '{name}' \
                             not found in vhosts"
                );
            }
        }
        // Validate header names in request-headers and response-headers.
        for v in &self.vhosts {
            for loc in &v.locations {
                for ops in [&loc.request_headers, &loc.response_headers] {
                    for op in ops.iter() {
                        let n = op.header_name();
                        HeaderName::from_bytes(n.as_bytes()).map_err(|_| {
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
        // If any policy uses country predicates, a geoip db must be
        // configured.  Recurse through Apply references so a named
        // policy with a country predicate is caught even if it is only
        // referenced via apply.
        let uses_country = {
            let mut visited = HashSet::new();
            self.vhosts.iter().any(|v| {
                v.locations.iter().any(|loc| {
                    loc.policy.as_ref().is_some_and(|s| {
                        policy_needs_geoip(
                            s,
                            &self.server.policies,
                            &mut visited,
                        )
                    })
                })
            }) || self.listeners.iter().any(|l| {
                l.stream
                    .as_ref()
                    .and_then(|s| s.policy.as_ref())
                    .is_some_and(|s| {
                        policy_needs_geoip(
                            s,
                            &self.server.policies,
                            &mut visited,
                        )
                    })
            }) || self.server.policies.values().any(|s| {
                policy_needs_geoip(s, &self.server.policies, &mut visited)
            })
        };
        if uses_country && self.server.geoip.is_none() {
            bail!(
                "policy 'country' predicates require \
                 server {{ geoip {{ db \"...\" }} }}"
            );
        }
        Ok(())
    }

    // Reject configurations where two distinct certificate sources
    // would claim the same on-disk slot.
    fn check_cert_identity_conflicts(&self) -> anyhow::Result<()> {
        // Collect every concrete cert source the server will instantiate,
        // tagged with a human-readable origin for error messages.  A
        // listener that refers to a top-level certificate by name is
        // skipped: the named cert is already in the list and we don't
        // want to double-count a deliberate share.
        let mut sources: Vec<(String, &TlsConfig)> = Vec::new();
        for c in &self.certificates {
            sources.push((format!("certificate \"{}\"", c.name), &c.source));
        }
        for (i, l) in self.listeners.iter().enumerate() {
            let Some(t) = &l.tls else { continue };
            if matches!(t.cert, TlsConfig::Ref(_)) {
                continue;
            }
            sources.push((format!("listener[{i}] inline tls"), &t.cert));
        }

        // Group by on-disk identity.  Self-signed sources have no
        // persistent identity (each is ephemeral and in-memory), so we
        // skip them.
        let mut by_acme_name: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut by_files: HashMap<(&str, &str), Vec<&str>> = HashMap::new();
        for (origin, src) in &sources {
            match src {
                TlsConfig::Acme { domains, name, .. } => {
                    let key = name.as_deref().unwrap_or(&domains[0]);
                    by_acme_name.entry(key).or_default().push(origin);
                }
                TlsConfig::Files { cert, key } => {
                    by_files
                        .entry((cert.as_str(), key.as_str()))
                        .or_default()
                        .push(origin);
                }
                TlsConfig::SelfSigned | TlsConfig::Ref(_) => {}
            }
        }
        for (key, owners) in &by_acme_name {
            if owners.len() > 1 {
                bail!(
                    "ACME cert directory '{key}' is claimed by multiple \
                     sources: {}. Define a single top-level \
                     `certificate \"{key}\" {{ acme {{ ... }} }}` and \
                     have each listener reference it via \
                     `tls cert=\"{key}\"` to share one renewal loop \
                     and on-disk slot",
                    owners.join(", ")
                );
            }
        }
        for ((cert, key), owners) in &by_files {
            if owners.len() > 1 {
                bail!(
                    "file-based cert (cert=\"{cert}\", key=\"{key}\") is \
                     claimed by multiple sources: {}. Define a single \
                     top-level `certificate \"...\" {{ files cert=... \
                     key=... }}` and have each listener reference it",
                    owners.join(", ")
                );
            }
        }
        Ok(())
    }

    /// Resolve a TlsConfig to its concrete source, following one level
    /// of `Ref`.  Returns `None` only if a `Ref` points at an unknown
    /// name (which validation rejects, so callers post-validation can
    /// `.expect()`).
    pub fn resolve_cert<'a>(
        &'a self,
        cfg: &'a TlsConfig,
    ) -> Option<&'a TlsConfig> {
        match cfg {
            TlsConfig::Ref(name) => self
                .certificates
                .iter()
                .find(|c| &c.name == name)
                .map(|c| &c.source),
            other => Some(other),
        }
    }

    // Returns the set of all known hostnames (names + aliases).
    pub fn vhost_names(&self) -> std::collections::HashSet<&str> {
        self.vhosts
            .iter()
            .flat_map(|v| {
                std::iter::once(v.name.value.as_str())
                    .chain(v.aliases.iter().map(|a| a.value.as_str()))
            })
            .collect()
    }
}

// Returns true iff any rule in `stmts` (recursively through Apply
// references) uses a Country predicate.  `visited` prevents infinite
// loops on circular Apply chains (which are caught later at resolution
// time; here we just skip cycles safely).
fn policy_needs_geoip(
    stmts: &[PolicyRuleDef],
    policies: &HashMap<String, Vec<PolicyRuleDef>>,
    visited: &mut HashSet<String>,
) -> bool {
    stmts.iter().any(|s| match s {
        PolicyRuleDef::Rule { predicate, .. } => {
            predicate.as_ref().is_some_and(|p| p.needs_geoip())
        }
        PolicyRuleDef::Apply { name } => {
            if visited.contains(name) {
                return false;
            }
            visited.insert(name.clone());
            policies.get(name).is_some_and(|inner| {
                policy_needs_geoip(inner, policies, visited)
            })
        }
    })
}
