use super::kdl::*;
use super::{
    AuthBackend, BasicAuthConfig, CertificateDef, ErrorPageDef, GeoIpConfig,
    HandlerConfig, HeaderOpConfig, HealthConfig, LdapAuthConfig,
    ListenerConfig, LocationConfig, PolicyRuleDef, ProxyProtocolVersion,
    ServerConfig, StreamMode, SubrequestAuthConfig, Timeouts, TlsConfig,
    TlsListenerConfig, TlsOptions, TlsVersion, UpstreamTlsConfig, VHostConfig,
    VHostName,
};
use crate::access::{PolicyAction, Predicate};
use ::kdl::KdlNode;
use anyhow::{Context, anyhow, bail};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;

pub(super) fn node_line(src: &str, node: &KdlNode) -> usize {
    src[..node.span().offset()]
        .bytes()
        .filter(|&b| b == b'\n')
        .count()
        + 1
}

pub(super) fn parse_server(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<ServerConfig> {
    let tls_defaults = node
        .children()
        .and_then(|doc| doc.nodes().iter().find(|n| n.name().value() == "tls"))
        .map(|n| parse_tls_options(n, src, name))
        .transpose()?
        .unwrap_or_default();
    let auth = node
        .children()
        .and_then(|doc| doc.nodes().iter().find(|n| n.name().value() == "auth"))
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
            doc.nodes().iter().find(|n| n.name().value() == "health")
        })
        .map(|n| HealthConfig {
            // Accept `health #false` (positional bool) or
            // `health { enabled #false }` (block form).  Default
            // enabled when the node is present without either form.
            enabled: n
                .get(0)
                .and_then(|e| e.as_bool())
                .or_else(|| child_bool(n, "enabled"))
                .unwrap_or(true),
        })
        .unwrap_or_default();
    // Collect named policy blocks defined in the server node.
    let mut policies = HashMap::new();
    for child in node.children().map(|d| d.nodes()).unwrap_or_default() {
        let child_name = child.name().value();
        if child_name == "policy" {
            let child_line = node_line(src, child);
            let policy_name = arg_str(child, 0).ok_or_else(|| {
                anyhow!(
                    "{name}:{child_line}: 'policy' requires \
                     a name argument"
                )
            })?;
            let stmts = parse_policy_statements(child, src, name, false)?;
            if policies.insert(policy_name.clone(), stmts).is_some() {
                bail!(
                    "{name}:{child_line}: duplicate policy \
                     name '{policy_name}'"
                );
            }
        }
    }

    // Collect error-page entries from the server node.
    let mut error_pages = Vec::new();
    for child in node.children().map(|d| d.nodes()).unwrap_or_default() {
        if child.name().value() == "error-page" {
            let child_line = node_line(src, child);
            let code = child
                .entries()
                .iter()
                .find(|e| e.name().is_none())
                .and_then(|e| e.value().as_integer())
                .map(|n| n as u16)
                .ok_or_else(|| {
                    anyhow!(
                        "{name}:{child_line}: 'error-page' requires a \
                     numeric status code as first argument"
                    )
                })?;
            let path = child.get("path").and_then(|e| e.as_string());
            let html = child.get("html").and_then(|e| e.as_string());
            let def = match (path, html) {
                (Some(_), Some(_)) => bail!(
                    "{name}:{child_line}: 'error-page' accepts only one \
                     of path=\"...\" or html=\"...\""
                ),
                (Some(p), None) => ErrorPageDef::File(p.to_owned()),
                (None, Some(h)) => ErrorPageDef::Inline(h.to_owned()),
                (None, None) => bail!(
                    "{name}:{child_line}: 'error-page' requires \
                     path=\"...\" or html=\"...\" property"
                ),
            };
            error_pages.push((code, def));
        }
    }

    Ok(ServerConfig {
        state_dir: child_str(node, "state-dir"),
        tls_defaults,
        user: child_str(node, "user"),
        group: child_str(node, "group"),
        inherit_supplementary_groups: child_bool(
            node,
            "inherit-supplementary-groups",
        )
        .unwrap_or(false),
        auth,
        geoip,
        health,
        policies,
        error_pages,
    })
}

fn parse_geoip(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<GeoIpConfig> {
    let line = node_line(src, node);
    // Accept `geoip "/path"` (positional) or `geoip { db "/path" }`
    // (block form).
    let db = arg_str(node, 0)
        .or_else(|| child_str(node, "db"))
        .ok_or_else(|| {
            anyhow!(
                "{name}:{line}: geoip requires a database path, either as \
             a positional argument or a 'db' child"
            )
        })?;
    Ok(GeoIpConfig { db })
}

// Parse an `auth pam { ... }` or `auth ldap { ... }` node inside
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
            let starttls = child_bool(node, "starttls").unwrap_or(false);
            let timeout_secs =
                child_i64(node, "timeout").map(|n| n as u64).unwrap_or(5);

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
        "subrequest" => {
            // Accept positional `auth subrequest "http://..."` or
            // block form `auth subrequest { url "http://..." }`.
            let url = arg_str(node, 1)
                .or_else(|| child_str(node, "url"))
                .ok_or_else(|| {
                    anyhow!(
                        "{name}:{line}: auth subrequest requires a URL \
                     (as second positional arg or 'url' child)"
                    )
                })?;
            if !url.starts_with("http://") {
                bail!(
                    "{name}:{line}: auth subrequest: url must use \
                     http:// scheme"
                );
            }
            // Each `forward-header "Name"` child contributes one
            // header name to the forwarding list.
            let forward_headers: Vec<String> = node
                .children()
                .map(|doc| {
                    doc.nodes()
                        .iter()
                        .filter(|n| n.name().value() == "forward-header")
                        .flat_map(positional_strs)
                        .collect()
                })
                .unwrap_or_default();
            let user_header = prop_or_child_str(node, "user-header");
            let groups_header = prop_or_child_str(node, "groups-header");
            let timeout_secs =
                child_i64(node, "timeout").map(|n| n as u64).unwrap_or(5);
            Ok(AuthBackend::Subrequest(SubrequestAuthConfig {
                url,
                forward_headers,
                user_header,
                groups_header,
                timeout_secs,
            }))
        }
        "jwt" => {
            let cookie_name = child_str(node, "cookie-name")
                .unwrap_or_else(|| "aloha_session".to_owned());
            let validity_secs =
                child_i64(node, "validity").map(|n| n as u64).unwrap_or(300);
            // Optional `wrap "pam"|"ldap"|"subrequest" { ... }` child
            // uses the same syntax as a top-level `auth` node.
            let inner = node
                .children()
                .and_then(|doc| {
                    doc.nodes().iter().find(|n| n.name().value() == "wrap")
                })
                .map(|n| parse_auth_backend(n, src, name))
                .transpose()?
                .map(Box::new);
            Ok(AuthBackend::Jwt {
                cookie_name,
                validity_secs,
                inner,
            })
        }
        other => bail!(
            "{name}:{line}: unknown auth backend '{other}'; \
             expected 'pam', 'ldap', 'subrequest', or 'jwt'"
        ),
    }
}

// Returns (config, raw_default_vhost) where raw_default_vhost is:
//   None          - child node absent; resolved to first vhost
//   Some(None)    - explicitly set to null
//   Some(Some(s)) - explicitly set to a hostname string
pub(super) fn parse_listener(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<(ListenerConfig, Option<Option<String>>)> {
    // bind: positional `listener "[::]:80"` or `bind "..."` child.
    let line = node_line(src, node);
    let bind = arg_str(node, 0)
        .or_else(|| child_str(node, "bind"))
        .ok_or_else(|| anyhow!("{name}:{line}: listener requires 'bind'"))?;
    let children = node.children().map(|d| d.nodes()).unwrap_or_default();
    let tls = parse_listener_tls(children.iter(), src, name)?;

    // A 'proxy' child activates stream mode: raw bytes forwarded to upstream.
    let proxy_node = children.iter().find(|n| n.name().value() == "proxy");
    if let Some(proxy) = proxy_node {
        let proxy_line = node_line(src, proxy);
        // HTTP-only options are invalid in stream mode.
        if let Some(bad) = children
            .iter()
            .find(|n| n.name().value() == "default-vhost")
        {
            let line = node_line(src, bad);
            bail!(
                "{name}:{line}: 'default-vhost' is only valid in HTTP \
                 listeners; stream listeners do not do virtual host routing"
            );
        }
        if let Some(bad) =
            children.iter().find(|n| n.name().value() == "timeouts")
        {
            let line = node_line(src, bad);
            bail!("{name}:{line}: 'timeouts' is only valid in HTTP listeners");
        }
        let upstream = req_arg_str(proxy, 0)
            .with_context(|| format!("{name}:{proxy_line}"))?;
        let proxy_children =
            proxy.children().map(|d| d.nodes()).unwrap_or_default();
        let upstream_tls = proxy_children
            .iter()
            .find(|n| n.name().value() == "tls")
            .map(|tls_node| {
                let skip_verify = tls_node
                    .children()
                    .map(|d| {
                        d.nodes()
                            .iter()
                            .any(|n| n.name().value() == "skip-verify")
                    })
                    .unwrap_or(false);
                anyhow::Ok(UpstreamTlsConfig { skip_verify })
            })
            .transpose()?;
        let proxy_protocol = child_str(proxy, "proxy-protocol")
            .map(|v| parse_proxy_protocol(&v, name, proxy_line))
            .transpose()?;
        let policy = children
            .iter()
            .find(|n| n.name().value() == "policy")
            .map(|n| parse_policy_statements(n, src, name, true))
            .transpose()?;
        let stream = Some(StreamMode {
            upstream,
            upstream_tls,
            proxy_protocol,
            policy,
        });
        let accept_proxy_protocol = {
            let line = node_line(src, node);
            child_str(node, "accept-proxy-protocol")
                .map(|v| parse_proxy_protocol(&v, name, line))
                .transpose()?
        };
        let max_connections =
            prop_or_child_i64(node, "max-connections").map(|n| n as u32);
        return Ok((
            ListenerConfig {
                bind,
                tls,
                stream,
                accept_proxy_protocol,
                default_vhost: None,
                timeouts: Timeouts::default(),
                max_connections,
                max_request_body: None,
            },
            // No raw default-vhost for stream listeners.
            Some(None),
        ));
    }

    // HTTP mode.
    if let Some(bad) = children.iter().find(|n| n.name().value() == "policy") {
        let line = node_line(src, bad);
        bail!(
            "{name}:{line}: 'policy' at the listener level is only valid \
             for stream listeners; put 'policy' inside a 'location' block"
        );
    }
    let raw_default_vhost = child_null_or_str(node, "default-vhost");
    let timeouts = children
        .iter()
        .find(|n| n.name().value() == "timeouts")
        .map(parse_timeouts)
        .unwrap_or_default();
    let accept_proxy_protocol = {
        let line = node_line(src, node);
        child_str(node, "accept-proxy-protocol")
            .map(|v| parse_proxy_protocol(&v, name, line))
            .transpose()?
    };
    let max_connections =
        prop_or_child_i64(node, "max-connections").map(|n| n as u32);
    let max_request_body =
        prop_or_child_i64(node, "max-request-body").map(|n| n as u64);
    // default_vhost is resolved later in Config::parse.
    Ok((
        ListenerConfig {
            bind,
            tls,
            stream: None,
            accept_proxy_protocol,
            default_vhost: None,
            timeouts,
            max_connections,
            max_request_body,
        },
        raw_default_vhost,
    ))
}

fn parse_proxy_protocol(
    v: &str,
    name: &str,
    line: usize,
) -> anyhow::Result<ProxyProtocolVersion> {
    match v {
        "v1" => Ok(ProxyProtocolVersion::V1),
        "v2" => Ok(ProxyProtocolVersion::V2),
        other => bail!(
            "{name}:{line}: unknown proxy-protocol '{other}'; \
             expected 'v1' or 'v2'"
        ),
    }
}

fn parse_timeouts(node: &KdlNode) -> Timeouts {
    // Each value may be expressed as a property
    // (`timeouts request-header=30 handler=60`) or as a child node
    // (`timeouts { request-header 30; handler 60 }`).
    Timeouts {
        request_header_secs: prop_or_child_i64(node, "request-header")
            .map(|n| n as u64),
        handler_secs: prop_or_child_i64(node, "handler").map(|n| n as u64),
        keepalive_secs: prop_or_child_i64(node, "keepalive").map(|n| n as u64),
    }
}

/// Resolve TLS configuration for a listener.  Walks the listener's
/// children once and handles the three inline forms (`tls-file`,
/// `tls-self-signed`, `tls-acme`) plus `tls cert="<name>"`, which
/// references a top-level `certificate` definition so multiple listeners
/// can share a single ACME manager and on-disk cert directory.
fn parse_listener_tls<'a, I: IntoIterator<Item = &'a KdlNode>>(
    children: I,
    src: &str,
    name: &str,
) -> anyhow::Result<Option<TlsListenerConfig>> {
    let mut tls_nodes: Vec<&KdlNode> = Vec::new();
    for child in children {
        match child.name().value() {
            "tls-file" | "tls-self-signed" | "tls-acme" | "tls" => {
                tls_nodes.push(child)
            }
            _ => {}
        }
    }
    let node = match tls_nodes.as_slice() {
        [] => return Ok(None),
        [n] => *n,
        [_, n2, ..] => {
            let line = node_line(src, n2);
            bail!(
                "{name}:{line}: at most one 'tls' / 'tls-*' node per \
                 listener"
            );
        }
    };
    let cert = match node.name().value() {
        "tls-file" => parse_tls_file(node, src, name)?,
        "tls-self-signed" => parse_tls_self_signed(node, src, name)?,
        "tls-acme" => parse_tls_acme(node, src, name)?,
        "tls" => parse_tls_ref(node, src, name)?,
        _ => unreachable!(),
    };
    let options = parse_tls_options(node, src, name)?;
    Ok(Some(TlsListenerConfig { cert, options }))
}

// Listener `tls cert="<name>"` -- reference a top-level certificate.
// Accepts positional form (`tls "main"`) as a shorthand.
fn parse_tls_ref(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<TlsConfig> {
    let line = node_line(src, node);
    let ref_name = arg_str(node, 0)
        .or_else(|| prop_or_child_str(node, "cert"))
        .ok_or_else(|| {
            anyhow!(
                "{name}:{line}: 'tls' on a listener requires a \
                 certificate name -- either as positional \
                 (`tls \"main\"`) or property (`tls cert=\"main\"`). \
                 For an inline cert use 'tls-file', 'tls-self-signed', \
                 or 'tls-acme' instead"
            )
        })?;
    Ok(TlsConfig::Ref(ref_name))
}

fn parse_tls_file(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<TlsConfig> {
    let line = node_line(src, node);
    let nn = node.name().value();
    let cert = prop_or_child_str(node, "cert").ok_or_else(|| {
        anyhow!(
            "{name}:{line}: {nn} requires 'cert' (as cert=\"...\" \
             property or as a 'cert' child)"
        )
    })?;
    let key = prop_or_child_str(node, "key").ok_or_else(|| {
        anyhow!(
            "{name}:{line}: {nn} requires 'key' (as key=\"...\" \
             property or as a 'key' child)"
        )
    })?;
    Ok(TlsConfig::Files { cert, key })
}

fn parse_tls_self_signed(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<TlsConfig> {
    let line = node_line(src, node);
    let nn = node.name().value();
    // Reject misuse: self-signed accepts only tls-options children.
    for forbidden in ["cert", "key", "domain", "email", "staging"] {
        if node
            .children()
            .map(|d| d.nodes().iter().any(|n| n.name().value() == forbidden))
            .unwrap_or(false)
        {
            bail!(
                "{name}:{line}: {nn} has no '{forbidden}' \
                 (it generates an in-memory cert)"
            );
        }
    }
    Ok(TlsConfig::SelfSigned)
}

fn parse_tls_acme(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<TlsConfig> {
    let line = node_line(src, node);
    let nn = node.name().value();
    // Domains: prefer block form (allows multi-SAN); accept a single
    // domain via the `domain="..."` property as a one-line shorthand.
    let mut domains: Vec<String> = node
        .children()
        .map(|doc| {
            doc.nodes()
                .iter()
                .filter(|n| n.name().value() == "domain")
                .flat_map(positional_strs)
                .collect()
        })
        .unwrap_or_default();
    if domains.is_empty()
        && let Some(d) = node.get("domain").and_then(|e| e.as_string())
    {
        domains.push(d.to_owned());
    }
    if domains.is_empty() {
        bail!(
            "{name}:{line}: {nn} requires at least one 'domain' \
             (as domain=\"...\" property or as 'domain' child node(s))"
        );
    }
    Ok(TlsConfig::Acme {
        domains,
        name: prop_or_child_str(node, "name"),
        email: prop_or_child_str(node, "email"),
        staging: prop_or_child_bool(node, "staging").unwrap_or(false),
        server: prop_or_child_str(node, "server"),
        retry_interval_secs: prop_or_child_i64(node, "retry-interval")
            .map(|n| n as u64)
            .unwrap_or(3600),
    })
}

/// Parse a top-level `certificate "<name>" { ... }` node.
///
/// The body holds exactly one source child: `acme { ... }`,
/// `files cert=... key=...`, or `self-signed`.  The source parsers
/// (`parse_tls_acme` etc.) are reused verbatim -- they look at properties
/// and child nodes by key, not by their own node name.
pub(super) fn parse_certificate(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<CertificateDef> {
    let line = node_line(src, node);
    let cert_name = req_arg_str(node, 0).with_context(|| {
        format!(
            "{name}:{line}: certificate requires a name as its first argument"
        )
    })?;

    let mut source_nodes: Vec<&KdlNode> = Vec::new();
    for child in node.children().map(|d| d.nodes()).unwrap_or_default() {
        match child.name().value() {
            "acme" | "files" | "self-signed" => source_nodes.push(child),
            _ => {}
        }
    }
    let source_node = match source_nodes.as_slice() {
        [] => bail!(
            "{name}:{line}: certificate '{cert_name}' has no source body; \
             expected one of 'acme {{ ... }}', 'files cert=... key=...', \
             or 'self-signed'"
        ),
        [n] => *n,
        [_, n2, ..] => {
            let line = node_line(src, n2);
            bail!(
                "{name}:{line}: certificate '{cert_name}' has more than \
                 one source body; pick one of 'acme', 'files', or \
                 'self-signed'"
            );
        }
    };
    let source = match source_node.name().value() {
        "acme" => parse_tls_acme(source_node, src, name)?,
        "files" => parse_tls_file(source_node, src, name)?,
        "self-signed" => parse_tls_self_signed(source_node, src, name)?,
        _ => unreachable!(),
    };
    Ok(CertificateDef { name: cert_name, source })
}

// Parse TLS version/cipher options from any tls node (server or
// listener).  Used for both global defaults and per-listener overrides.
fn parse_tls_options(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<TlsOptions> {
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
    Ok(TlsOptions {
        min_version,
        ciphers,
    })
}

fn parse_tls_version(
    s: &str,
    name: &str,
    line: usize,
) -> anyhow::Result<TlsVersion> {
    match s {
        "1.2" => Ok(TlsVersion::Tls12),
        "1.3" => Ok(TlsVersion::Tls13),
        other => bail!(
            "{name}:{line}: unknown TLS version '{other}'; \
             expected '1.2' or '1.3'"
        ),
    }
}

pub(super) fn parse_vhost(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<VHostConfig> {
    let vhost_name = parse_vhost_name(node)?;
    let children = node.children().map(|d| d.nodes()).unwrap_or_default();
    let mut aliases = Vec::new();
    let mut locations = Vec::new();
    for child in children {
        let child_line = node_line(src, child);
        match child.name().value() {
            "alias" => aliases.push(parse_vhost_name(child)?),
            "location" => locations.push(parse_location(child, src, name)?),
            other => bail!(
                "{name}:{child_line}: unknown node '{other}' \
                 in vhost '{}'",
                vhost_name.value
            ),
        }
    }
    Ok(VHostConfig {
        name: vhost_name,
        aliases,
        locations,
    })
}

fn parse_vhost_name(node: &KdlNode) -> anyhow::Result<VHostName> {
    let value = req_arg_str(node, 0)?;
    let regex = node.get("regex").and_then(|e| e.as_bool()).unwrap_or(false);
    Ok(VHostName { value, regex })
}

fn parse_location(
    node: &KdlNode,
    src: &str,
    name: &str,
) -> anyhow::Result<LocationConfig> {
    let line = node_line(src, node);
    let path = req_arg_str(node, 0)?;
    let children = node.children().map(|d| d.nodes()).unwrap_or_default();
    // The first recognised handler node wins.
    let handler_node = children
        .iter()
        .find(|n| {
            matches!(
                n.name().value(),
                "static"
                    | "proxy"
                    | "redirect"
                    | "fastcgi"
                    | "scgi"
                    | "cgi"
                    | "status"
                    | "auth-request"
            )
        })
        .ok_or_else(|| {
            anyhow!("{name}:{line}: location '{path}' has no handler node")
        })?;
    let handler = parse_handler(handler_node, src, name, &path)?;
    let policy = children
        .iter()
        .find(|n| n.name().value() == "policy")
        .map(|n| parse_policy_statements(n, src, name, false))
        .transpose()?;
    let auth = children
        .iter()
        .find(|n| n.name().value() == "basic-auth")
        .map(|n| {
            // Accept realm both as a property (basic-auth realm="...")
            // and as a child node (basic-auth { realm "..." }).
            let realm = n
                .get("realm")
                .and_then(|e| e.as_string())
                .map(|s| s.to_owned())
                .or_else(|| child_str(n, "realm"))
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
        path,
        handler,
        policy,
        auth,
        request_headers,
        response_headers,
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
    let children = node.children().map(|d| d.nodes()).unwrap_or_default();
    // Parse a two-arg header op (set or add), returning (name, value).
    let parse_two_arg = |child: &KdlNode,
                         op: &str,
                         child_line: usize|
     -> anyhow::Result<(String, String)> {
        let hname = req_arg_str(child, 0)
            .with_context(|| format!("{name}:{child_line}"))?;
        let value = req_arg_str(child, 1).with_context(|| {
            anyhow!(
                "{name}:{child_line}: '{op}' requires a \
                 header name and a value"
            )
        })?;
        Ok((hname, value))
    };
    let mut ops = Vec::new();
    for child in children {
        let child_line = node_line(src, child);
        match child.name().value() {
            "set" => {
                let (hname, value) = parse_two_arg(child, "set", child_line)?;
                ops.push(HeaderOpConfig::Set { name: hname, value });
            }
            "add" => {
                let (hname, value) = parse_two_arg(child, "add", child_line)?;
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

// Parse a `policy { }` or `policy "name" { }` block.
//
// Each statement is one of:
//   allow [predicate]
//   deny  [code=N] [predicate]
//   redirect to="url" [code=N] [predicate]
//   apply "policy-name"
//
// A predicate is either:
//   - Inline on the statement node: allow address "10.0.0.0/8"
//   - A child block (AND of multiple predicates):
//       allow { address "10.0.0.0/8"; authenticated }
//   - Absent (unconditional catch-all): deny code=403
//
// `tcp_only` rejects identity predicates (user, group, authenticated)
// at parse time because stream listeners have no HTTP auth layer.
fn parse_policy_statements(
    node: &KdlNode,
    src: &str,
    name: &str,
    tcp_only: bool,
) -> anyhow::Result<Vec<PolicyRuleDef>> {
    let children = node.children().map(|d| d.nodes()).unwrap_or_default();
    let mut stmts = Vec::new();

    for child in children {
        let child_line = node_line(src, child);
        let stmt_name = child.name().value();

        if stmt_name == "apply" {
            let policy_name = arg_str(child, 0).ok_or_else(|| {
                anyhow!(
                    "{name}:{child_line}: 'apply' requires a \
                     policy name argument"
                )
            })?;
            stmts.push(PolicyRuleDef::Apply { name: policy_name });
            continue;
        }

        let action = match stmt_name {
            "allow" => PolicyAction::Allow,
            "deny" => {
                let code = child
                    .get("code")
                    .and_then(|e| e.as_integer())
                    .map(|n| n as u16)
                    .unwrap_or(403);
                PolicyAction::Deny { code }
            }
            "redirect" => {
                let to = child
                    .get("to")
                    .and_then(|e| e.as_string())
                    .map(String::from)
                    .ok_or_else(|| {
                        anyhow!(
                            "{name}:{child_line}: 'redirect' \
                             requires a 'to' property"
                        )
                    })?;
                let code = child
                    .get("code")
                    .and_then(|e| e.as_integer())
                    .map(|n| n as u16)
                    .unwrap_or(302);
                PolicyAction::Redirect { to, code }
            }
            other => bail!(
                "{name}:{child_line}: unknown policy statement \
                 '{other}'; expected 'allow', 'deny', 'redirect', \
                 or 'apply'"
            ),
        };

        let predicate =
            parse_predicate(child, src, name, child_line, tcp_only)?;
        stmts.push(PolicyRuleDef::Rule { predicate, action });
    }

    Ok(stmts)
}

// Extract the predicate from a statement node.
//
// Priority: inline positional args > child block.
// Error if both are present.
// Returns None for an unconditional (catch-all) statement.
fn parse_predicate(
    node: &KdlNode,
    src: &str,
    name: &str,
    line: usize,
    tcp_only: bool,
) -> anyhow::Result<Option<Predicate>> {
    let pos_args: Vec<String> = node
        .entries()
        .iter()
        .filter(|e| e.name().is_none())
        .filter_map(|e| e.value().as_string().map(String::from))
        .collect();
    let has_block = node
        .children()
        .map(|d| !d.nodes().is_empty())
        .unwrap_or(false);

    if !pos_args.is_empty() && has_block {
        bail!(
            "{name}:{line}: '{}' cannot have both an inline \
             predicate and a child block; use one or the other",
            node.name().value()
        );
    }

    if !pos_args.is_empty() {
        // Inline predicate: first arg is the type (or "not").
        let pred = parse_inline_predicate(&pos_args, name, line, tcp_only)?;
        return Ok(Some(pred));
    }

    if has_block {
        let cond_nodes = node.children().map(|d| d.nodes()).unwrap_or_default();
        let mut preds = Vec::with_capacity(cond_nodes.len());
        for cond in cond_nodes {
            let cond_line = node_line(src, cond);
            preds.push(parse_predicate_node(cond, name, cond_line, tcp_only)?);
        }
        return Ok(Some(if preds.len() == 1 {
            preds.remove(0)
        } else {
            Predicate::And(preds)
        }));
    }

    Ok(None)
}

// Parse an inline predicate from the positional args of a statement.
//
// Forms:
//   ["type", "val1", "val2", ...] — simple predicate
//   ["not", "type", "val1", ...]  — negated predicate
fn parse_inline_predicate(
    args: &[String],
    name: &str,
    line: usize,
    tcp_only: bool,
) -> anyhow::Result<Predicate> {
    if args[0] == "not" {
        if args.len() < 2 {
            bail!(
                "{name}:{line}: 'not' requires a predicate type \
                 (e.g. not address \"10.0.0.0/8\")"
            );
        }
        let inner =
            build_simple_predicate(&args[1], &args[2..], name, line, tcp_only)?;
        // not { auth } still needs auth resolution to negate, so we
        // check tcp_only on the inner predicate.
        if tcp_only && inner.needs_auth() {
            bail!(
                "{name}:{line}: identity predicates are not supported \
                 in stream listener policy blocks \
                 (no HTTP authentication available)"
            );
        }
        return Ok(Predicate::Not(Box::new(inner)));
    }
    build_simple_predicate(&args[0], &args[1..], name, line, tcp_only)
}

// Parse a predicate node from a child block.
//
// Handles: address, country, user, group, authenticated, not.
fn parse_predicate_node(
    node: &KdlNode,
    name: &str,
    line: usize,
    tcp_only: bool,
) -> anyhow::Result<Predicate> {
    let pred_name = node.name().value();
    let values: Vec<String> = node
        .entries()
        .iter()
        .filter(|e| e.name().is_none())
        .filter_map(|e| e.value().as_string().map(String::from))
        .collect();

    if pred_name == "not" {
        // In block form: `not address "10.0.0.0/8"` or `not authenticated`.
        // First arg is the inner predicate type.
        if values.is_empty() {
            bail!(
                "{name}:{line}: 'not' requires a predicate type \
                 (e.g. not address \"10.0.0.0/8\")"
            );
        }
        let inner = build_simple_predicate(
            &values[0],
            &values[1..],
            name,
            line,
            tcp_only,
        )?;
        if tcp_only && inner.needs_auth() {
            bail!(
                "{name}:{line}: identity predicates are not \
                 supported in stream listener policy blocks \
                 (no HTTP authentication available)"
            );
        }
        return Ok(Predicate::Not(Box::new(inner)));
    }

    build_simple_predicate(pred_name, &values, name, line, tcp_only)
}

// Construct a simple (non-negated) Predicate from a type name and values.
fn build_simple_predicate(
    pred_type: &str,
    values: &[String],
    name: &str,
    line: usize,
    tcp_only: bool,
) -> anyhow::Result<Predicate> {
    match pred_type {
        "address" => {
            if values.is_empty() {
                bail!(
                    "{name}:{line}: 'address' requires at least \
                     one CIDR or IP address argument"
                );
            }
            let nets = values
                .iter()
                .map(|s| {
                    s.parse::<IpNet>()
                        .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
                        .map_err(|_| {
                            anyhow!(
                                "{name}:{line}: invalid IP address or \
                             CIDR '{s}'"
                            )
                        })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(Predicate::Address(nets))
        }
        "country" => {
            if values.is_empty() {
                bail!(
                    "{name}:{line}: 'country' requires at least \
                     one country code argument"
                );
            }
            Ok(Predicate::Country(
                values.iter().map(|s| s.to_uppercase()).collect(),
            ))
        }
        "user" => {
            if tcp_only {
                bail!(
                    "{name}:{line}: 'user' predicates are not \
                     supported in stream listener policy blocks \
                     (no HTTP authentication available)"
                );
            }
            if values.is_empty() {
                bail!(
                    "{name}:{line}: 'user' requires at least \
                     one username argument"
                );
            }
            Ok(Predicate::User(values.to_vec()))
        }
        "group" => {
            if tcp_only {
                bail!(
                    "{name}:{line}: 'group' predicates are not \
                     supported in stream listener policy blocks \
                     (no HTTP authentication available)"
                );
            }
            if values.is_empty() {
                bail!(
                    "{name}:{line}: 'group' requires at least \
                     one group name argument"
                );
            }
            Ok(Predicate::Group(values.to_vec()))
        }
        "authenticated" => {
            if tcp_only {
                bail!(
                    "{name}:{line}: 'authenticated' predicates are \
                     not supported in stream listener policy blocks \
                     (no HTTP authentication available)"
                );
            }
            Ok(Predicate::Authenticated)
        }
        other => bail!(
            "{name}:{line}: unknown predicate type '{other}'; \
             expected 'address', 'country', 'user', 'group', \
             'authenticated', or 'not'"
        ),
    }
}

// Parse the shared socket+root+index fields of a fastcgi or scgi handler.
fn parse_socket_handler(
    node: &KdlNode,
    src: &str,
    name: &str,
    variant: &str,
) -> anyhow::Result<(String, String, Option<String>)> {
    let line = node_line(src, node);
    let socket = prop_or_child_str(node, "socket")
        .ok_or_else(|| anyhow!("{name}:{line}: {variant} requires 'socket'"))?;
    let root = prop_or_child_str(node, "root")
        .ok_or_else(|| anyhow!("{name}:{line}: {variant} requires 'root'"))?;
    Ok((socket, root, prop_or_child_str(node, "index")))
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
            // Root: positional, root="..." property, or root child.
            let root = arg_str(node, 0)
                .or_else(|| prop_or_child_str(node, "root"))
                .ok_or_else(|| {
                    anyhow!(
                        "{name}:{line}: static handler requires a root path"
                    )
                })?;
            let strip_prefix =
                prop_or_child_bool(node, "strip-prefix").unwrap_or(false);
            // Collect explicit index-file children; fall back to
            // built-in defaults when none are declared.  Each
            // index-file node may carry one or more positional string
            // args; multiple index-file nodes are also accepted.
            let index_files: Vec<String> = node
                .children()
                .map(|doc| {
                    doc.nodes()
                        .iter()
                        .filter(|n| n.name().value() == "index-file")
                        .flat_map(positional_strs)
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
            // Upstream: positional, upstream="..." property, or
            // upstream child.
            let upstream = arg_str(node, 0)
                .or_else(|| prop_or_child_str(node, "upstream"))
                .ok_or_else(|| {
                    anyhow!(
                        "{name}:{line}: proxy handler requires an upstream URL"
                    )
                })?;
            let strip_prefix =
                prop_or_child_bool(node, "strip-prefix").unwrap_or(false);
            let proxy_protocol = prop_or_child_str(node, "proxy-protocol")
                .map(|v| parse_proxy_protocol(&v, name, line))
                .transpose()?;
            Ok(HandlerConfig::Proxy {
                upstream,
                strip_prefix,
                proxy_protocol,
            })
        }
        "redirect" => {
            // Target: positional, to="..." property, or to child.
            let to = arg_str(node, 0)
                .or_else(|| prop_or_child_str(node, "to"))
                .ok_or_else(|| {
                    anyhow!(
                        "{name}:{line}: redirect handler requires a target URL"
                    )
                })?;
            let code = prop_or_child_i64(node, "code")
                .map(|n| n as u16)
                .unwrap_or(301);
            Ok(HandlerConfig::Redirect { to, code })
        }
        "fastcgi" => {
            let (socket, root, index) =
                parse_socket_handler(node, src, name, "fastcgi")?;
            Ok(HandlerConfig::FastCgi {
                socket,
                root,
                index,
            })
        }
        "scgi" => {
            let (socket, root, index) =
                parse_socket_handler(node, src, name, "scgi")?;
            Ok(HandlerConfig::Scgi {
                socket,
                root,
                index,
            })
        }
        "cgi" => {
            // Accept positional `cgi "/path"`, `cgi root="..."`, or
            // block-form `cgi { root "..." }`.
            let root = arg_str(node, 0)
                .or_else(|| prop_or_child_str(node, "root"))
                .ok_or_else(|| {
                    anyhow!(
                        "{name}:{line}: cgi handler requires a root path \
                     (positional, root=\"...\" property, or 'root' child)"
                    )
                })?;
            Ok(HandlerConfig::Cgi { root })
        }
        "status" => Ok(HandlerConfig::Status),
        "auth-request" => Ok(HandlerConfig::AuthRequest),
        other => bail!(
            "{name}:{line}: unknown handler '{other}' \
             in location '{location_path}'"
        ),
    }
}
