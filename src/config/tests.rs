use super::*;
use crate::access::{PolicyAction, Predicate};
use crate::config::PolicyRuleDef;

#[test]
fn minimal_static_config() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:8080"
        }
        vhost localhost {
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
    assert_eq!(cfg.vhosts[0].name.value, "localhost");
    assert!(matches!(
        cfg.vhosts[0].locations[0].handler,
        HandlerConfig::Static { .. }
    ));
}

#[test]
fn tls_file_property_form() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:443"
            tls-file cert="cert.pem" key="key.pem"
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
fn tls_file_missing_cert_is_error() {
    let err = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:443"
            tls-file key="key.pem"
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("'cert'"), "got: {err}");
}

#[test]
fn tls_self_signed_no_args() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:443"
            tls-self-signed
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    assert!(matches!(
        cfg.listeners[0].tls.as_ref().unwrap().cert,
        TlsConfig::SelfSigned
    ));
}

#[test]
fn tls_self_signed_rejects_cert() {
    let err = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:443"
            tls-self-signed { cert "x.pem" }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("tls-self-signed"), "got: {err}");
}

#[test]
fn tls_acme_property_form() {
    let cfg = Config::parse(
        r#"
        server { state-dir "/tmp/aloha-test" }
        listener {
            bind "[::]:443"
            tls-acme domain="example.com" email="a@b.com"
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    if let TlsConfig::Acme { domains, email, .. } =
        &cfg.listeners[0].tls.as_ref().unwrap().cert
    {
        assert_eq!(domains, &["example.com"]);
        assert_eq!(email.as_deref(), Some("a@b.com"));
    } else {
        panic!("expected Acme");
    }
}

#[test]
fn tls_listener() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:443"
            tls-file {
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
            tls-self-signed
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
            tls-self-signed
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
            tls-acme {
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
            tls-acme {
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
    if let TlsConfig::Acme {
        domains,
        email,
        staging,
        name,
        ..
    } = &cfg.listeners[0].tls.as_ref().unwrap().cert
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
fn acme_domain_variadic_form() {
    let cfg = Config::parse(
        r#"
        server {
            state-dir "/tmp/aloha-test"
        }
        listener {
            bind "[::]:443"
            tls-acme {
                domain "a.com" "b.com" "c.com"
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
    if let TlsConfig::Acme { domains, .. } =
        &cfg.listeners[0].tls.as_ref().unwrap().cert
    {
        assert_eq!(domains, &["a.com", "b.com", "c.com"]);
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
            tls-acme {
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
            tls-acme
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
            tls-acme {
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
            tls-acme {
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
            tls-file {
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
fn index_files_variadic_form() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                static {
                    root "."
                    index-file "a.html" "b.html" "c.html"
                }
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Static { index_files, .. } =
        &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(index_files, &["a.html", "b.html", "c.html"]);
    } else {
        panic!("expected Static handler");
    }
}

#[test]
fn index_files_mixed_forms() {
    // Repeated nodes and variadic args may be combined.
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                static {
                    root "."
                    index-file "a.html" "b.html"
                    index-file "c.html"
                }
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Static { index_files, .. } =
        &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(index_files, &["a.html", "b.html", "c.html"]);
    } else {
        panic!("expected Static handler");
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
    assert!(matches!(locs[2].handler, HandlerConfig::Redirect { .. }));
    assert!(matches!(locs[3].handler, HandlerConfig::FastCgi { .. }));
}

// -- stream listener (proxy child) --------------------------------

#[test]
fn listener_proxy_parses() {
    let cfg = Config::parse(
        r#"
        listener "[::]:5432" {
            proxy "db.internal:5432" {
                proxy-protocol v2
            }
        }
        "#,
    )
    .unwrap();
    let l = &cfg.listeners[0];
    assert_eq!(l.bind, "[::]:5432");
    let s = l.stream.as_ref().unwrap();
    assert_eq!(s.upstream, "db.internal:5432");
    assert_eq!(s.proxy_protocol, Some(ProxyProtocolVersion::V2));
}

#[test]
fn listener_proxy_without_proxy_protocol() {
    let cfg = Config::parse(
        r#"
        listener "[::]:3306" {
            proxy "db.internal:3306"
        }
        "#,
    )
    .unwrap();
    assert!(
        cfg.listeners[0]
            .stream
            .as_ref()
            .unwrap()
            .proxy_protocol
            .is_none()
    );
}

#[test]
fn listener_proxy_v1_parses() {
    let cfg = Config::parse(
        r#"
        listener "[::]:80" {
            proxy "backend:80" {
                proxy-protocol v1
            }
        }
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg.listeners[0].stream.as_ref().unwrap().proxy_protocol,
        Some(ProxyProtocolVersion::V1)
    );
}

#[test]
fn proxy_protocol_bad_value_rejected() {
    for bad in ["1", "2", "v3", "V2"] {
        let src = format!(
            r#"
            listener "[::]:80" {{
                proxy "backend:80" {{
                    proxy-protocol "{bad}"
                }}
            }}
            "#
        );
        let err = Config::parse(&src).unwrap_err().to_string();
        assert!(
            err.contains("expected 'v1' or 'v2'"),
            "expected error for {bad:?}, got: {err}"
        );
    }
}

#[test]
fn listener_proxy_with_tls_termination() {
    let cfg = Config::parse(
        r#"
        listener "[::]:443" {
            tls-self-signed
            proxy "backend:5432"
        }
        "#,
    )
    .unwrap();
    let l = &cfg.listeners[0];
    assert!(l.tls.is_some());
    assert_eq!(l.stream.as_ref().unwrap().upstream, "backend:5432");
}

#[test]
fn listener_proxy_with_tls_and_proxy_protocol() {
    let cfg = Config::parse(
        r#"
        listener "[::]:443" {
            tls-self-signed
            proxy "backend:5432" {
                proxy-protocol v2
            }
        }
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg.listeners[0].stream.as_ref().unwrap().proxy_protocol,
        Some(ProxyProtocolVersion::V2)
    );
}

#[test]
fn listener_proxy_only_needs_no_vhost() {
    let cfg = Config::parse(
        r#"
        listener "[::]:5432" {
            proxy "db.internal:5432"
        }
        "#,
    )
    .unwrap();
    assert!(cfg.vhosts.is_empty());
    assert_eq!(cfg.listeners.len(), 1);
    assert!(cfg.listeners[0].stream.is_some());
}

#[test]
fn listener_proxy_unix_upstream() {
    let cfg = Config::parse(
        r#"
        listener "[::]:5432" {
            proxy "unix:/run/pg.sock"
        }
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg.listeners[0].stream.as_ref().unwrap().upstream,
        "unix:/run/pg.sock"
    );
}

#[test]
fn listener_proxy_upstream_tls_parses() {
    let cfg = Config::parse(
        r#"
        listener "[::]:5432" {
            proxy "db.internal:5432" {
                tls
            }
        }
        "#,
    )
    .unwrap();
    let ut = cfg.listeners[0]
        .stream
        .as_ref()
        .unwrap()
        .upstream_tls
        .as_ref()
        .unwrap();
    assert!(!ut.skip_verify);
}

#[test]
fn listener_proxy_upstream_tls_skip_verify_parses() {
    let cfg = Config::parse(
        r#"
        listener "[::]:5432" {
            proxy "db.internal:5432" {
                tls { skip-verify }
            }
        }
        "#,
    )
    .unwrap();
    let ut = cfg.listeners[0]
        .stream
        .as_ref()
        .unwrap()
        .upstream_tls
        .as_ref()
        .unwrap();
    assert!(ut.skip_verify);
}

#[test]
fn listener_proxy_default_vhost_rejected() {
    let err = Config::parse(
        r#"
        listener "[::]:5432" {
            default-vhost "foo"
            proxy "db.internal:5432"
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("only valid in HTTP listeners"),
        "expected error, got: {err}"
    );
}

#[test]
fn listener_http_policy_rejected() {
    let err = Config::parse(
        r#"
        listener "[::]:80" {
            policy {
                allow address "10.0.0.0/8"
            }
        }
        vhost "h" {
            location "/" { static { root "."; } }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("only valid for stream listeners"),
        "expected error, got: {err}"
    );
}

#[test]
fn listener_proxy_policy_address_parses() {
    let cfg = Config::parse(
        r#"
        listener "[::]:5432" {
            proxy "db.internal:5432"
            policy {
                allow address "10.0.0.0/8"
                deny code=403
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.listeners[0]
        .stream
        .as_ref()
        .unwrap()
        .policy
        .as_ref()
        .unwrap();
    assert_eq!(stmts.len(), 2);
    // No country predicates present.
    assert!(stmts.iter().all(|s| match s {
        PolicyRuleDef::Rule { predicate, .. } => {
            predicate.as_ref().is_none_or(|p| !p.needs_geoip())
        }
        _ => true,
    }));
}

#[test]
fn geoip_positional_form_parses() {
    let cfg = Config::parse(
        r#"
        server {
            geoip "/etc/aloha/GeoLite2-Country.mmdb"
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
    assert_eq!(
        cfg.server.geoip.as_ref().unwrap().db,
        "/etc/aloha/GeoLite2-Country.mmdb"
    );
}

#[test]
fn geoip_block_form_still_parses() {
    let cfg = Config::parse(
        r#"
        server {
            geoip { db "/dev/null" }
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
    assert_eq!(cfg.server.geoip.as_ref().unwrap().db, "/dev/null");
}

#[test]
fn listener_proxy_policy_country_parses() {
    let cfg = Config::parse(
        r#"
        server {
            geoip {
                db "/dev/null"
            }
        }
        listener "[::]:5432" {
            proxy "db.internal:5432"
            policy {
                allow country US CA
                deny code=403
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.listeners[0]
        .stream
        .as_ref()
        .unwrap()
        .policy
        .as_ref()
        .unwrap();
    assert!(stmts.iter().any(|s| match s {
        PolicyRuleDef::Rule { predicate, .. } => {
            predicate.as_ref().is_some_and(|p| p.needs_geoip())
        }
        _ => false,
    }));
}

#[test]
fn listener_proxy_access_absent_means_none() {
    let cfg = Config::parse(
        r#"
        listener "[::]:5432" {
            proxy "db.internal:5432"
        }
        "#,
    )
    .unwrap();
    assert!(cfg.listeners[0].stream.as_ref().unwrap().policy.is_none());
}

#[test]
fn listener_proxy_access_rejects_user_condition() {
    let err = Config::parse(
        r#"
        listener "[::]:5432" {
            proxy "db.internal:5432"
            policy {
                allow user alice
            }
        }
        "#,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("not supported in stream listener"),
        "unexpected error: {err}"
    );
}

#[test]
fn listener_proxy_policy_rejects_group_predicate() {
    let err = Config::parse(
        r#"
        listener "[::]:5432" {
            proxy "db.internal:5432"
            policy {
                allow group admins
            }
        }
        "#,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("not supported in stream listener"),
        "unexpected error: {err}"
    );
}

#[test]
fn listener_proxy_policy_rejects_authenticated_predicate() {
    let err = Config::parse(
        r#"
        listener "[::]:5432" {
            proxy "db.internal:5432"
            policy {
                allow authenticated
            }
        }
        "#,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("not supported in stream listener"),
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
                    index  index.py
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
    if let HandlerConfig::Scgi {
        socket,
        root,
        index,
    } = &cfg.vhosts[0].locations[0].handler
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
fn listener_bind_positional_parses() {
    let cfg = Config::parse(
        r#"
        listener "[::]:8080"
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.listeners[0].bind, "[::]:8080");
}

#[test]
fn listener_bind_positional_with_block() {
    let cfg = Config::parse(
        r#"
        listener "[::]:443" {
            tls-self-signed
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.listeners[0].bind, "[::]:443");
    assert!(cfg.listeners[0].tls.is_some());
}

#[test]
fn listener_proxy_bind_positional_parses() {
    let cfg = Config::parse(
        r#"
        listener "[::]:5432" {
            proxy "db.internal:5432"
        }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.listeners[0].bind, "[::]:5432");
    assert_eq!(
        cfg.listeners[0].stream.as_ref().unwrap().upstream,
        "db.internal:5432"
    );
}

#[test]
fn static_positional_form_parses() {
    let cfg = Config::parse(
        r#"
        listener { bind "0.0.0.0:80" }
        vhost "h" {
            location "/" {
                static "/var/www" strip-prefix=#true
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Static {
        root, strip_prefix, ..
    } = &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(root, "/var/www");
        assert!(*strip_prefix);
    } else {
        panic!("expected Static handler");
    }
}

#[test]
fn proxy_positional_form_parses() {
    let cfg = Config::parse(
        r#"
        listener { bind "0.0.0.0:80" }
        vhost "h" {
            location "/api/" {
                proxy "http://localhost:3000" strip-prefix=#true
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Proxy {
        upstream,
        strip_prefix,
        ..
    } = &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(upstream, "http://localhost:3000");
        assert!(*strip_prefix);
    } else {
        panic!("expected Proxy handler");
    }
}

#[test]
fn redirect_positional_form_parses() {
    let cfg = Config::parse(
        r#"
        listener { bind "0.0.0.0:80" }
        vhost "h" {
            location "/old/" {
                redirect "https://example.com/new/" code=302
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Redirect { to, code } =
        &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(to, "https://example.com/new/");
        assert_eq!(*code, 302);
    } else {
        panic!("expected Redirect handler");
    }
}

#[test]
fn fastcgi_property_form_parses() {
    let cfg = Config::parse(
        r#"
        listener { bind "0.0.0.0:80" }
        vhost "h" {
            location "/php/" {
                fastcgi socket="unix:/run/php.sock" root="/var/www" index=index.php
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::FastCgi {
        socket,
        root,
        index,
    } = &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(socket, "unix:/run/php.sock");
        assert_eq!(root, "/var/www");
        assert_eq!(index.as_deref(), Some("index.php"));
    } else {
        panic!("expected FastCgi handler");
    }
}

#[test]
fn scgi_property_form_parses() {
    let cfg = Config::parse(
        r#"
        listener { bind "0.0.0.0:80" }
        vhost "h" {
            location "/scgi/" {
                scgi socket="127.0.0.1:9000" root="/var/www"
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Scgi {
        socket,
        root,
        index,
    } = &cfg.vhosts[0].locations[0].handler
    {
        assert_eq!(socket, "127.0.0.1:9000");
        assert_eq!(root, "/var/www");
        assert!(index.is_none());
    } else {
        panic!("expected Scgi handler");
    }
}

#[test]
fn cgi_positional_form_parses() {
    let cfg = Config::parse(
        r#"
        listener { bind "0.0.0.0:80" }
        vhost "h" {
            location "/cgi-bin/" {
                cgi "/usr/lib/cgi-bin"
            }
        }
        "#,
    )
    .unwrap();
    if let HandlerConfig::Cgi { root } = &cfg.vhosts[0].locations[0].handler {
        assert_eq!(root, "/usr/lib/cgi-bin");
    } else {
        panic!("expected Cgi handler");
    }
}

#[test]
fn aliases() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost example.com {
            alias www.example.com
            alias example.net
            location "/" {
                static { root "."; }
            }
        }
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg.vhosts[0]
            .aliases
            .iter()
            .map(|a| a.value.as_str())
            .collect::<Vec<_>>(),
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
        vhost example.com {
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
fn listener_bind_child_node() {
    // `bind` can appear as a child node (alternative to positional arg).
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:8080"
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
    assert_eq!(l.bind, "0.0.0.0:8080");
    assert_eq!(l.local_name(), "0.0.0.0:8080");
}

#[test]
fn validate_rejects_missing_bind() {
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
            tls-self-signed {
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
        ["TLS13_AES_256_GCM_SHA384", "TLS13_CHACHA20_POLY1305_SHA256"]
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
            tls-self-signed
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
    assert!(matches!(defaults.min_version, Some(TlsVersion::Tls12)));
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
    assert!(matches!(resolved.min_version, Some(TlsVersion::Tls13)));
    // Falls back to global ciphers since listener has none.
    assert_eq!(resolved.ciphers, ["TLS13_AES_256_GCM_SHA384"]);
}

#[test]
fn tls_version_invalid() {
    let result = Config::parse(
        r#"
        listener {
            bind "[::]:443"
            tls-self-signed {
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
            default-vhost #null
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
        "default-vhost #null should leave no fallback vhost"
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
            default-vhost #null
        }
        vhost "h" {
            location "/" {
                static { root "."; }
            }
        }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.listeners[0].default_vhost.as_deref(), Some("h"));
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

#[test]
fn timeouts_property_form() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
            timeouts request-header=30 handler=60 keepalive=75
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    let t = &cfg.listeners[0].timeouts;
    assert_eq!(t.request_header_secs, Some(30));
    assert_eq!(t.handler_secs, Some(60));
    assert_eq!(t.keepalive_secs, Some(75));
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
            user www-data
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
fn inherit_supplementary_groups_parses() {
    let cfg = Config::parse(
        r#"
        server {
            user aloha
            inherit-supplementary-groups #true
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
    assert!(cfg.server.inherit_supplementary_groups);
}

#[test]
fn inherit_supplementary_groups_defaults_false() {
    let cfg = Config::parse(
        r#"
        server {
            user aloha
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
    assert!(!cfg.server.inherit_supplementary_groups);
}

// -- policy blocks ---------------------------------------------

fn rule_action(s: &PolicyRuleDef) -> &PolicyAction {
    match s {
        PolicyRuleDef::Rule { action, .. } => action,
        _ => panic!("expected Rule"),
    }
}

fn rule_predicate(s: &PolicyRuleDef) -> Option<&Predicate> {
    match s {
        PolicyRuleDef::Rule { predicate, .. } => predicate.as_ref(),
        _ => panic!("expected Rule"),
    }
}

#[test]
fn policy_allow_address_parses() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/admin/" {
                policy {
                    allow address "10.0.0.0/8"
                    deny code=403
                }
                static { root "."; }
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert_eq!(stmts.len(), 2);
    assert!(matches!(rule_action(&stmts[0]), PolicyAction::Allow));
    assert!(matches!(
        rule_action(&stmts[1]),
        PolicyAction::Deny { code: 403 }
    ));
    assert!(matches!(
        rule_predicate(&stmts[0]),
        Some(Predicate::Address(_))
    ));
}

#[test]
fn policy_deny_custom_code_parses() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                policy {
                    deny code=429 address "1.2.3.4"
                }
                static { root "."; }
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert!(matches!(
        rule_action(&stmts[0]),
        PolicyAction::Deny { code: 429 }
    ));
    assert!(matches!(
        rule_predicate(&stmts[0]),
        Some(Predicate::Address(_))
    ));
}

#[test]
fn policy_redirect_parses() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                policy {
                    redirect to="/login/" code=302 user unverified
                    deny code=403
                }
                static { root "."; }
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert!(matches!(
        rule_action(&stmts[0]),
        PolicyAction::Redirect { code: 302, .. }
    ));
    if let PolicyAction::Redirect { to, .. } = rule_action(&stmts[0]) {
        assert_eq!(to, "/login/");
    }
    assert!(matches!(
        rule_predicate(&stmts[0]),
        Some(Predicate::User(_))
    ));
}

#[test]
fn policy_empty_block_has_zero_rules() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                policy {
                }
                static { root "."; }
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert_eq!(stmts.len(), 0);
}

#[test]
fn policy_absent_means_none() {
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
    assert!(cfg.vhosts[0].locations[0].policy.is_none());
}

#[test]
fn policy_invalid_cidr_is_error() {
    let result = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                policy {
                    allow address "not-an-ip"
                }
                static { root "."; }
            }
        }
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn policy_unknown_statement_is_error() {
    let result = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                policy {
                    block address "1.2.3.4"
                }
                static { root "."; }
            }
        }
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn policy_country_without_geoip_is_error() {
    // country predicates require a geoip db at validate() time.
    let result = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                policy {
                    allow country US
                }
                static { root "."; }
            }
        }
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn policy_redirect_missing_to_is_error() {
    let result = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                policy {
                    redirect code=302 address "1.2.3.4"
                }
                static { root "."; }
            }
        }
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn policy_address_without_prefix_parses() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                policy {
                    allow address "192.168.1.1"
                    deny code=403
                }
                static { root "."; }
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert!(matches!(
        rule_predicate(&stmts[0]),
        Some(Predicate::Address(_))
    ));
}

#[test]
fn policy_authenticated_predicate_parses() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/members/" {
                policy {
                    allow authenticated
                    deny code=403
                }
                static { root "."; }
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert!(matches!(
        rule_predicate(&stmts[0]),
        Some(Predicate::Authenticated)
    ));
}

#[test]
fn policy_group_predicate_parses() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/admin/" {
                policy {
                    allow group admin
                    deny code=403
                }
                static { root "."; }
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert!(matches!(
        rule_predicate(&stmts[0]),
        Some(Predicate::Group(g)) if g == &["admin"]
    ));
}

#[test]
fn policy_no_predicate_rule_is_catch_all() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                policy {
                    allow address "10.0.0.0/8"
                    deny code=403
                }
                static { root "."; }
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    // deny rule has no predicate -> catch-all
    assert!(rule_predicate(&stmts[1]).is_none());
}

#[test]
fn policy_country_predicate_parses() {
    // Inline multi-value country predicate.
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
                policy {
                    deny country CN RU
                    allow
                }
                static { root "."; }
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert_eq!(stmts.len(), 2);
    assert!(matches!(
        rule_action(&stmts[0]),
        PolicyAction::Deny { code: 403 }
    ));
    assert!(matches!(
        rule_predicate(&stmts[0]),
        Some(Predicate::Country(c)) if c.len() == 2
    ));
}

#[test]
fn policy_pass_action_is_error() {
    // `pass` is no longer a valid statement.
    let result = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                policy {
                    pass address "10.0.0.0/8"
                    deny
                }
                static { root "."; }
            }
        }
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn policy_apply_statement_parses() {
    let cfg = Config::parse(
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
                    deny
                }
                static { root "."; }
            }
        }
        "#,
    )
    .unwrap();
    // Named policy stored in server config.
    assert!(cfg.server.policies.contains_key("allow-all"));
    // Inline policy block has Apply statement.
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert!(
        matches!(&stmts[0], PolicyRuleDef::Apply { name } if name == "allow-all")
    );
}

#[test]
fn policy_named_policy_parsed() {
    let cfg = Config::parse(
        r#"
        server {
            policy "ip-filter" {
                deny code=403 not address "10.0.0.0/8"
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
    let stmts = cfg.server.policies.get("ip-filter").unwrap();
    assert_eq!(stmts.len(), 1);
    assert!(matches!(
        rule_action(&stmts[0]),
        PolicyAction::Deny { code: 403 }
    ));
    // Predicate should be Not(Address(...))
    assert!(matches!(rule_predicate(&stmts[0]), Some(Predicate::Not(_))));
}

#[test]
fn policy_duplicate_name_is_error() {
    let result = Config::parse(
        r#"
        server {
            policy "dup" {
                allow
            }
            policy "dup" {
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
fn policy_old_ip_syntax_rejected() {
    let err = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                policy {
                    allow { ip "10.0.0.0/8" }
                }
                static { root "."; }
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("\'ip\'") || err.contains("'ip'"),
        "expected ip migration hint, got: {err}"
    );
}

#[test]
fn policy_address_multi_value_parses() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                policy {
                    allow address "10.0.0.0/8" "192.168.0.0/16"
                }
                static { root "."; }
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    match rule_predicate(&stmts[0]) {
        Some(Predicate::Address(nets)) => assert_eq!(nets.len(), 2),
        other => panic!("expected Address, got {other:?}"),
    }
}

#[test]
fn policy_user_multi_value_parses() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                policy {
                    allow user alice "bob"
                }
                static { root "."; }
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    match rule_predicate(&stmts[0]) {
        Some(Predicate::User(names)) => {
            assert_eq!(names, &["alice", "bob"]);
        }
        other => panic!("expected User, got {other:?}"),
    }
}

#[test]
fn policy_group_multi_value_parses() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                policy {
                    allow group admin "ops"
                }
                static { root "."; }
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    match rule_predicate(&stmts[0]) {
        Some(Predicate::Group(groups)) => {
            assert_eq!(groups, &["admin", "ops"]);
        }
        other => panic!("expected Group, got {other:?}"),
    }
}

#[test]
fn policy_not_inline_parses() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                policy {
                    deny code=401 not authenticated
                    allow
                }
                static { root "."; }
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    assert!(matches!(
        rule_predicate(&stmts[0]),
        Some(Predicate::Not(inner)) if matches!(inner.as_ref(), Predicate::Authenticated)
    ));
}

#[test]
fn policy_not_in_block_parses() {
    let cfg = Config::parse(
        r#"
        server {
            geoip { db "/dev/null" }
        }
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                policy {
                    allow { not country CN; authenticated }
                }
                static { root "."; }
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    // Block with two predicates → And
    assert!(matches!(rule_predicate(&stmts[0]), Some(Predicate::And(_))));
}

#[test]
fn policy_and_from_block_parses() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                policy {
                    allow { address "10.0.0.0/8"; authenticated }
                }
                static { root "."; }
            }
        }
        "#,
    )
    .unwrap();
    let stmts = cfg.vhosts[0].locations[0].policy.as_ref().unwrap();
    match rule_predicate(&stmts[0]) {
        Some(Predicate::And(preds)) => assert_eq!(preds.len(), 2),
        other => panic!("expected And, got {other:?}"),
    }
}

#[test]
fn policy_country_in_named_policy_triggers_geoip_validation() {
    // Bug #2 regression: country inside a named policy must be caught
    // by validate() even when only referenced via apply.
    let result = Config::parse(
        r#"
        server {
            policy "geo-block" {
                deny country CN
            }
        }
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/" {
                policy {
                    apply "geo-block"
                    allow
                }
                static { root "."; }
            }
        }
        "#,
    );
    // No geoip configured → validate() must reject this.
    assert!(
        result.is_err(),
        "country in named policy must trigger geoip validation"
    );
}

#[test]
fn error_page_path_property_form() {
    let cfg = Config::parse(
        r#"
        server {
            error-page 403 path="/var/www/errors/403.html"
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
fn error_page_legacy_positional_rejected() {
    let err = Config::parse(
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
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("path=") && err.contains("html="),
        "expected migration hint, got: {err}"
    );
}

#[test]
fn error_page_path_and_html_conflict_is_error() {
    let result = Config::parse(
        r#"
        server {
            error-page 404 path="/x.html" html="<h1>x</h1>"
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
                enabled #true
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
                enabled #false
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

#[test]
fn health_positional_bool_false() {
    let cfg = Config::parse(
        r#"
        server {
            health #false
        }
        listener { bind "0.0.0.0:80" }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    assert!(!cfg.server.health.enabled);
}

#[test]
fn health_positional_bool_true() {
    let cfg = Config::parse(
        r#"
        server {
            health #true
        }
        listener { bind "0.0.0.0:80" }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    assert!(cfg.server.health.enabled);
}

// -- auth backend ----------------------------------------------

#[test]
fn server_auth_pam_default_service() {
    let cfg = Config::parse(
        r#"
        server {
            auth pam
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
            auth pam {
                service aloha
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
fn basic_auth_block_form_parses() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/admin/" {
                basic-auth {
                    realm "Admin Area"
                }
                policy {
                    allow authenticated
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
fn basic_auth_property_form_parses() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/admin/" {
                basic-auth realm="Admin Area"
                policy { allow authenticated; deny code=401 }
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
fn basic_auth_default_realm() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "0.0.0.0:80"
        }
        vhost "h" {
            location "/secure/" {
                basic-auth
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
            auth ldap {
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
        assert_eq!(c.bind_dn, "uid={user},ou=people,dc=example,dc=com");
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
            auth ldap {
                url "ldaps://ldap.example.com:636"
                bind-dn "uid={user},ou=people,dc=example,dc=com"
                base-dn "ou=groups,dc=example,dc=com"
                group-filter "(member=uid={user},ou=people,dc=example,dc=com)"
                group-attr "cn"
                starttls #false
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
            auth ldap {
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
            auth ldap {
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
            auth ldap {
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
            auth ldap {
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
            auth ldap {
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
            auth ldap {
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
            auth ldap {
                url "ldap://localhost:389"
                bind-dn "uid={user},ou=people,dc=example,dc=com"
                base-dn "ou=groups,dc=example,dc=com"
                starttls #true
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
    assert!(msg.contains("ldap"), "error should mention 'ldap': {msg}");
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
    let cfg = Config::parse(
        r#"
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
    "#,
    )
    .unwrap();
    let ops = &cfg.vhosts[0].locations[0].request_headers;
    assert_eq!(ops.len(), 1);
    assert!(matches!(&ops[0], HeaderOpConfig::Set { name, value }
        if name == "X-Client-IP" && value == "{client_ip}"));
}

#[test]
fn request_headers_add_parses() {
    let cfg = Config::parse(
        r#"
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
    "#,
    )
    .unwrap();
    let ops = &cfg.vhosts[0].locations[0].request_headers;
    assert!(matches!(&ops[0], HeaderOpConfig::Add { .. }));
}

#[test]
fn request_headers_remove_parses() {
    let cfg = Config::parse(
        r#"
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
    "#,
    )
    .unwrap();
    let ops = &cfg.vhosts[0].locations[0].request_headers;
    assert!(matches!(&ops[0],
        HeaderOpConfig::Remove { name } if name == "Authorization"));
}

#[test]
fn response_headers_parses() {
    let cfg = Config::parse(
        r#"
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
    "#,
    )
    .unwrap();
    let ops = &cfg.vhosts[0].locations[0].response_headers;
    assert_eq!(ops.len(), 1);
    assert!(matches!(&ops[0],
        HeaderOpConfig::Set { name, value }
            if name == "X-Frame-Options" && value == "DENY"));
}

#[test]
fn header_rules_absent_means_empty_vecs() {
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
    assert!(cfg.vhosts[0].locations[0].request_headers.is_empty());
    assert!(cfg.vhosts[0].locations[0].response_headers.is_empty());
}

#[test]
fn invalid_header_name_is_error() {
    let result = Config::parse(
        r#"
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
    "#,
    );
    assert!(result.is_err());
}

#[test]
fn unknown_op_in_request_headers_is_error() {
    let result = Config::parse(
        r#"
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
    "#,
    );
    assert!(result.is_err());
}

// -- Unix domain socket listener tests --------------------------------

#[test]
#[cfg(unix)]
fn unix_socket_bind_parses() {
    let cfg = Config::parse(
        r#"
        listener { bind "unix:/run/aloha.sock" }
        vhost "h" {
            location "/" { static { root "."; } }
        }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.listeners[0].bind, "unix:/run/aloha.sock");
}

#[test]
#[cfg(unix)]
fn unix_socket_empty_path_is_error() {
    let result = Config::parse(
        r#"
        listener { bind "unix:" }
        vhost "h" {
            location "/" { static { root "."; } }
        }
        "#,
    );
    let err = result.unwrap_err().to_string();
    assert!(err.contains("unix socket path is empty"), "got: {err}");
}

// -- Proxy handler proxy-protocol tests -------------------------------

#[test]
fn proxy_handler_proxy_protocol_parses() {
    let cfg = Config::parse(
        r#"
        listener { bind "0.0.0.0:80" }
        vhost "h" {
            location "/" {
                proxy "http://backend:8080" {
                    proxy-protocol v1
                }
            }
        }
        "#,
    )
    .unwrap();
    let loc = &cfg.vhosts[0].locations[0];
    assert!(matches!(
        loc.handler,
        HandlerConfig::Proxy {
            proxy_protocol: Some(ProxyProtocolVersion::V1),
            ..
        }
    ));
}

#[test]
fn proxy_handler_proxy_protocol_v2_parses() {
    let cfg = Config::parse(
        r#"
        listener { bind "0.0.0.0:80" }
        vhost "h" {
            location "/" {
                proxy "http://backend:8080" {
                    proxy-protocol v2
                }
            }
        }
        "#,
    )
    .unwrap();
    let loc = &cfg.vhosts[0].locations[0];
    assert!(matches!(
        loc.handler,
        HandlerConfig::Proxy {
            proxy_protocol: Some(ProxyProtocolVersion::V2),
            ..
        }
    ));
}

#[test]
fn auth_request_handler_parses() {
    let cfg = Config::parse(
        r#"
        listener { bind "0.0.0.0:80" }
        vhost "h" {
            location "/auth" {
                auth-request
            }
        }
        "#,
    )
    .unwrap();
    assert!(matches!(
        cfg.vhosts[0].locations[0].handler,
        HandlerConfig::AuthRequest
    ));
}

#[test]
fn auth_subrequest_minimal_parses() {
    let cfg = Config::parse(
        r#"
        listener { bind "0.0.0.0:80" }
        server {
            auth subrequest {
                url "http://auth.internal/check"
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    match cfg.server.auth.as_ref().unwrap() {
        AuthBackend::Subrequest(c) => {
            assert_eq!(c.url, "http://auth.internal/check");
            assert!(c.forward_headers.is_empty());
            assert!(c.user_header.is_none());
            assert!(c.groups_header.is_none());
            assert_eq!(c.timeout_secs, 5); // default
        }
        other => panic!("expected Subrequest, got {other:?}"),
    }
}

#[test]
fn auth_subrequest_full_parses() {
    let cfg = Config::parse(
        r#"
        listener { bind "0.0.0.0:80" }
        server {
            auth subrequest {
                url "http://auth.internal/check"
                forward-header Authorization
                forward-header Cookie
                user-header X-Auth-User
                groups-header X-Auth-Groups
                timeout 10
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    match cfg.server.auth.as_ref().unwrap() {
        AuthBackend::Subrequest(c) => {
            assert_eq!(c.forward_headers, ["Authorization", "Cookie"]);
            assert_eq!(c.user_header.as_deref(), Some("X-Auth-User"));
            assert_eq!(c.groups_header.as_deref(), Some("X-Auth-Groups"));
            assert_eq!(c.timeout_secs, 10);
        }
        other => panic!("expected Subrequest, got {other:?}"),
    }
}

#[test]
fn auth_subrequest_requires_http_scheme() {
    let err = Config::parse(
        r#"
        listener { bind "0.0.0.0:80" }
        server {
            auth subrequest {
                url "https://auth.internal/check"
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.to_lowercase().contains("http://"),
        "expected scheme error, got: {err}"
    );
}

#[test]
fn auth_subrequest_missing_url_is_error() {
    let err = Config::parse(
        r#"
        listener { bind "0.0.0.0:80" }
        server {
            auth subrequest {
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.to_lowercase().contains("url"),
        "expected url error, got: {err}"
    );
}

// -- QUIC / HTTP/3 listener config ---------------------------------

#[test]
fn udp_prefix_selects_quic_transport() {
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:443"; tls-self-signed }
        listener { bind "udp:[::]:443"; tls-self-signed }
        vhost h { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.listeners[0].transport, Transport::Tcp);
    assert_eq!(cfg.listeners[1].transport, Transport::Udp);
}

#[test]
fn udp_listener_without_tls_is_rejected() {
    // QUIC mandates TLS at the transport level; surface that at parse
    // time rather than letting an unencrypted UDP socket open.
    let err = Config::parse(
        r#"
        listener { bind "udp:[::]:443" }
        vhost h { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("udp:") && err.contains("tls"),
        "expected tls-required error, got: {err}"
    );
}

#[test]
fn udp_listener_rejects_stream_mode() {
    let err = Config::parse(
        r#"
        listener {
            bind "udp:[::]:443"
            tls-self-signed
            proxy "127.0.0.1:5432"
        }
        vhost h { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("proxy") && err.contains("udp"),
        "expected stream-mode rejection, got: {err}"
    );
}

#[test]
fn auto_alt_svc_populated_on_matching_tcp_listener() {
    // Same-port TCP + UDP pair: TCP listener should carry an Alt-Svc
    // value pointing h3 clients at the UDP port.
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:443"; tls-self-signed }
        listener { bind "udp:[::]:443"; tls-self-signed }
        vhost h { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    let tcp = &cfg.listeners[0];
    let udp = &cfg.listeners[1];
    assert_eq!(tcp.transport, Transport::Tcp);
    let alt = tcp.auto_alt_svc.as_deref().expect("auto_alt_svc set");
    assert!(alt.contains("h3=\":443\""), "unexpected: {alt}");
    assert!(alt.contains("ma="), "missing max-age in: {alt}");
    // UDP listener itself never carries Alt-Svc -- it would only
    // advertise to other QUIC clients, which is meaningless.
    assert!(udp.auto_alt_svc.is_none());
}

#[test]
fn auto_alt_svc_only_when_ports_match() {
    // h3 on a different port from the TCP TLS endpoint: no automatic
    // advertisement -- the user has to set Alt-Svc explicitly via the
    // existing headers mechanism for that topology.
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:443"; tls-self-signed }
        listener { bind "udp:[::]:8443"; tls-self-signed }
        vhost h { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    assert!(cfg.listeners[0].auto_alt_svc.is_none());
    assert!(cfg.listeners[1].auto_alt_svc.is_none());
}

#[test]
fn auto_alt_svc_skips_plain_http_listeners() {
    // Auto-Alt-Svc only applies to TLS listeners.  A bare port-80
    // HTTP listener should not advertise h3 even when a same-port
    // UDP listener is configured (which would be unusual but legal).
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:80" }
        listener { bind "udp:[::]:80"; tls-self-signed }
        vhost h { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    assert!(cfg.listeners[0].auto_alt_svc.is_none());
}

// -- Proxy scheme (HTTP/3 outbound) --------------------------------

#[test]
fn proxy_connect_timeout_parses() {
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:80" }
        vhost h {
            location "/" {
                proxy "http://backend/" { connect-timeout 5 }
            }
        }
        "#,
    )
    .unwrap();
    match &cfg.vhosts[0].locations[0].handler {
        HandlerConfig::Proxy { connect_timeout_secs, .. } => {
            assert_eq!(*connect_timeout_secs, Some(5));
        }
        _ => panic!("expected Proxy handler"),
    }
}

#[test]
fn proxy_tls_skip_verify_parses() {
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:80" }
        vhost h {
            location "/" {
                proxy "https://backend/" {
                    tls { skip-verify }
                }
            }
        }
        "#,
    )
    .unwrap();
    let h = &cfg.vhosts[0].locations[0].handler;
    match h {
        HandlerConfig::Proxy { upstream_tls, .. } => {
            assert!(upstream_tls.as_ref().unwrap().skip_verify);
        }
        _ => panic!("expected Proxy handler"),
    }
}

#[test]
fn proxy_tls_skip_verify_rejects_non_https_upstream() {
    // skip-verify only makes sense for https upstreams; an http://
    // upstream silently consuming the knob would be a footgun.
    let err = Config::parse(
        r#"
        listener { bind "[::]:80" }
        vhost h {
            location "/" {
                proxy "http://backend/" {
                    tls { skip-verify }
                }
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("https://"),
        "expected https-only rejection, got: {err}"
    );
}

#[test]
fn proxy_pool_max_idle_parses() {
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:80" }
        vhost h {
            location "/" {
                proxy "http://backend/" {
                    pool-max-idle 32
                }
            }
        }
        "#,
    )
    .unwrap();
    let h = &cfg.vhosts[0].locations[0].handler;
    match h {
        HandlerConfig::Proxy { pool_max_idle, .. } => {
            assert_eq!(*pool_max_idle, Some(32));
        }
        _ => panic!("expected Proxy handler"),
    }
}

#[test]
fn proxy_scheme_h3_parses() {
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:80" }
        vhost h {
            location "/" {
                proxy "https://backend.example/" {
                    scheme "h3"
                }
            }
        }
        "#,
    )
    .unwrap();
    let h = &cfg.vhosts[0].locations[0].handler;
    match h {
        HandlerConfig::Proxy { scheme, .. } => {
            assert_eq!(*scheme, ProxyUpstreamScheme::H3);
        }
        _ => panic!("expected Proxy handler"),
    }
}

#[test]
fn proxy_scheme_h3_rejects_non_https_upstream() {
    let err = Config::parse(
        r#"
        listener { bind "[::]:80" }
        vhost h {
            location "/" {
                proxy "http://backend.example/" { scheme "h3" }
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("scheme=h3") && err.contains("https"),
        "expected scheme=h3 requires https; got: {err}"
    );
}

#[test]
fn proxy_scheme_unknown_is_rejected() {
    let err = Config::parse(
        r#"
        listener { bind "[::]:80" }
        vhost h {
            location "/" {
                proxy "https://backend.example/" { scheme "spdy" }
            }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("unknown proxy scheme"), "got: {err}");
}

// -- Per-listener ALPN override ------------------------------------

#[test]
fn alpn_override_parses() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "[::]:443"
            tls-self-signed
            alpn "h2" "http/1.1"
        }
        vhost h { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg.listeners[0].alpn.as_deref(),
        Some(&["h2".to_string(), "http/1.1".to_string()][..])
    );
}

#[test]
fn alpn_default_is_none() {
    // Absent `alpn` child means "use the protocol default" (None);
    // the tls builders fill in ["h2","http/1.1"] / ["h3"] as
    // appropriate.
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:443"; tls-self-signed }
        vhost h { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    assert!(cfg.listeners[0].alpn.is_none());
}

// -- QUIC transport tuning -----------------------------------------

#[test]
fn quic_transport_block_parses() {
    let cfg = Config::parse(
        r#"
        listener {
            bind "udp:[::]:443"
            tls-self-signed
            quic-transport {
                max-concurrent-bidi-streams 256
                max-idle-timeout 60
                keep-alive-interval 10
                zero-rtt #true
                retry-tokens #false
                retry-token-lifetime 30
            }
        }
        vhost h { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    let qt = cfg.listeners[0]
        .quic_transport
        .as_ref()
        .expect("quic_transport set");
    assert_eq!(qt.max_concurrent_bidi_streams, Some(256));
    assert_eq!(qt.max_idle_timeout_secs, Some(60));
    assert_eq!(qt.keep_alive_interval_secs, Some(10));
    assert!(qt.zero_rtt_enabled);
    assert!(!qt.retry_tokens);
    assert_eq!(qt.retry_token_lifetime_secs, Some(30));
}

#[test]
fn quic_transport_defaults() {
    // Empty quic-transport block: zero-rtt off, retry-tokens on,
    // everything else None (= use quinn defaults).
    let cfg = Config::parse(
        r#"
        listener {
            bind "udp:[::]:443"
            tls-self-signed
            quic-transport { }
        }
        vhost h { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    let qt = cfg.listeners[0].quic_transport.as_ref().unwrap();
    assert!(!qt.zero_rtt_enabled);
    assert!(qt.retry_tokens);
    assert_eq!(qt.max_concurrent_bidi_streams, None);
}

#[test]
fn quic_transport_rejected_on_tcp_listener() {
    let err = Config::parse(
        r#"
        listener {
            bind "[::]:443"
            tls-self-signed
            quic-transport { max-idle-timeout 30 }
        }
        vhost h { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("quic-transport") && err.contains("udp:"),
        "expected udp-only rejection, got: {err}"
    );
}

// -- Per-vhost ALPN ------------------------------------------------

#[test]
fn vhost_alpn_parses() {
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:443"; tls-self-signed }
        vhost "example.com" {
            alpn "http/1.1"
            location "/" { static { root "."; } }
        }
        "#,
    )
    .unwrap();
    assert_eq!(
        cfg.vhosts[0].alpn.as_deref(),
        Some(&["http/1.1".to_string()][..])
    );
}

#[test]
fn vhost_alpn_empty_list_is_rejected() {
    let err = Config::parse(
        r#"
        listener { bind "[::]:443"; tls-self-signed }
        vhost "example.com" {
            alpn
            location "/" { static { root "."; } }
        }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("alpn") && err.contains("at least one"),
        "expected empty-alpn rejection, got: {err}"
    );
}

#[test]
fn vhost_alpn_default_is_none() {
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:443"; tls-self-signed }
        vhost "example.com" {
            location "/" { static { root "."; } }
        }
        "#,
    )
    .unwrap();
    assert!(cfg.vhosts[0].alpn.is_none());
}

#[test]
fn alpn_empty_list_is_rejected() {
    let err = Config::parse(
        r#"
        listener {
            bind "[::]:443"
            tls-self-signed
            alpn
        }
        vhost h { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("alpn") && err.contains("at least one"),
        "expected empty-alpn rejection, got: {err}"
    );
}

// -- Named certificates --------------------------------------------

#[test]
fn certificate_acme_parses() {
    let cfg = Config::parse(
        r#"
        server { state-dir "/tmp/aloha-test" }
        certificate "main" {
            acme {
                domain "example.com"
                domain "www.example.com"
                email "admin@example.com"
            }
        }
        listener {
            bind "[::]:443"
            tls cert="main"
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.certificates.len(), 1);
    assert_eq!(cfg.certificates[0].name, "main");
    if let TlsConfig::Acme { domains, email, .. } = &cfg.certificates[0].source
    {
        assert_eq!(domains, &["example.com", "www.example.com"]);
        assert_eq!(email.as_deref(), Some("admin@example.com"));
    } else {
        panic!("expected Acme source");
    }
    assert!(matches!(
        cfg.listeners[0].tls.as_ref().unwrap().cert,
        TlsConfig::Ref(ref n) if n == "main"
    ));
}

#[test]
fn certificate_files_parses() {
    let cfg = Config::parse(
        r#"
        certificate "internal" {
            files cert="/etc/aloha/cert.pem" key="/etc/aloha/key.pem"
        }
        listener {
            bind "[::]:443"
            tls cert="internal"
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    if let TlsConfig::Files { cert, key } = &cfg.certificates[0].source {
        assert_eq!(cert, "/etc/aloha/cert.pem");
        assert_eq!(key, "/etc/aloha/key.pem");
    } else {
        panic!("expected Files source");
    }
}

#[test]
fn certificate_self_signed_parses() {
    let cfg = Config::parse(
        r#"
        certificate "dev" {
            self-signed
        }
        listener {
            bind "[::]:443"
            tls cert="dev"
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    assert!(matches!(
        cfg.certificates[0].source,
        TlsConfig::SelfSigned
    ));
}

#[test]
fn tls_ref_positional_form() {
    // `tls "main"` is the same as `tls cert="main"`.
    let cfg = Config::parse(
        r#"
        certificate "main" { self-signed }
        listener {
            bind "[::]:443"
            tls "main"
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    assert!(matches!(
        cfg.listeners[0].tls.as_ref().unwrap().cert,
        TlsConfig::Ref(ref n) if n == "main"
    ));
}

#[test]
fn tls_ref_with_option_overrides() {
    // A listener referencing a named cert may still carry its own
    // TlsOptions overrides.
    let cfg = Config::parse(
        r#"
        certificate "main" { self-signed }
        listener {
            bind "[::]:443"
            tls cert="main" {
                min-version "1.3"
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    let tls = cfg.listeners[0].tls.as_ref().unwrap();
    assert!(matches!(tls.cert, TlsConfig::Ref(_)));
    assert!(matches!(
        tls.options.min_version,
        Some(crate::config::TlsVersion::Tls13)
    ));
}

#[test]
fn two_listeners_share_named_acme_cert() {
    // The whole point of the refactor: two listeners with one ACME cert.
    let cfg = Config::parse(
        r#"
        server { state-dir "/tmp/aloha-test" }
        certificate "main" {
            acme {
                domain "example.com"
                email "a@b.com"
            }
        }
        listener {
            bind "[::]:443"
            tls cert="main"
        }
        listener {
            bind "[::]:8443"
            tls cert="main"
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.certificates.len(), 1);
    assert_eq!(cfg.listeners.len(), 2);
    for l in &cfg.listeners {
        assert!(matches!(
            l.tls.as_ref().unwrap().cert,
            TlsConfig::Ref(ref n) if n == "main"
        ));
    }
}

#[test]
fn tls_ref_without_name_is_error() {
    let err = Config::parse(
        r#"
        listener {
            bind "[::]:443"
            tls
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("certificate name") || err.contains("cert="),
        "expected hint about cert name, got: {err}"
    );
}

#[test]
fn tls_ref_to_unknown_name_is_error() {
    let err = Config::parse(
        r#"
        listener {
            bind "[::]:443"
            tls cert="missing"
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("unknown certificate") && err.contains("missing"),
        "expected unknown-cert error, got: {err}"
    );
}

#[test]
fn duplicate_certificate_names_is_error() {
    let err = Config::parse(
        r#"
        certificate "main" { self-signed }
        certificate "main" { self-signed }
        listener {
            bind "[::]:443"
            tls cert="main"
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("duplicate") && err.contains("main"),
        "expected duplicate-name error, got: {err}"
    );
}

#[test]
fn certificate_without_source_is_error() {
    let err = Config::parse(
        r#"
        certificate "main" {
        }
        listener {
            bind "[::]:443"
            tls cert="main"
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("source") || err.contains("body"),
        "expected source error, got: {err}"
    );
}

#[test]
fn certificate_with_two_sources_is_error() {
    let err = Config::parse(
        r#"
        certificate "main" {
            self-signed
            files cert="c.pem" key="k.pem"
        }
        listener {
            bind "[::]:443"
            tls cert="main"
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("more than one") || err.contains("source"),
        "expected multiple-source error, got: {err}"
    );
}

#[test]
fn two_inline_acme_with_same_default_name_is_error() {
    // Both listeners default name to "example.com" -> they'd race on
    // state_dir/certs/example.com/.  Before the refactor this silently
    // corrupted; now it's a parse-time error pointing at the fix.
    let err = Config::parse(
        r#"
        server { state-dir "/tmp/aloha-test" }
        listener {
            bind "[::]:443"
            tls-acme {
                domain "example.com"
                email "a@b.com"
            }
        }
        listener {
            bind "[::]:8443"
            tls-acme {
                domain "example.com"
                email "a@b.com"
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("example.com")
            && (err.contains("multiple")
                || err.contains("claimed")
                || err.contains("certificate")),
        "expected on-disk conflict error, got: {err}"
    );
}

#[test]
fn two_inline_acme_with_distinct_names_is_ok() {
    // Different explicit names avoid the on-disk slot conflict.  This
    // is the historical workaround and must remain valid.
    let cfg = Config::parse(
        r#"
        server { state-dir "/tmp/aloha-test" }
        listener {
            bind "[::]:443"
            tls-acme {
                domain "example.com"
                name "main"
                email "a@b.com"
            }
        }
        listener {
            bind "[::]:8443"
            tls-acme {
                domain "example.com"
                name "secondary"
                email "a@b.com"
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.listeners.len(), 2);
}

#[test]
fn named_acme_uses_state_dir_validation() {
    // ACME via a named cert still requires server.state-dir.
    let err = Config::parse(
        r#"
        certificate "main" {
            acme {
                domain "example.com"
                email "a@b.com"
            }
        }
        listener {
            bind "[::]:443"
            tls cert="main"
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("state-dir"),
        "expected state-dir requirement, got: {err}"
    );
}

#[test]
fn mixed_inline_and_named_certs_compose() {
    // An inline cert on one listener and a named cert on another --
    // common during incremental migration to named certs.
    let cfg = Config::parse(
        r#"
        server { state-dir "/tmp/aloha-test" }
        certificate "main" {
            acme {
                domain "example.com"
                email "a@b.com"
            }
        }
        listener {
            bind "[::]:443"
            tls cert="main"
        }
        listener {
            bind "127.0.0.1:9443"
            tls-self-signed
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.certificates.len(), 1);
    assert!(matches!(
        cfg.listeners[0].tls.as_ref().unwrap().cert,
        TlsConfig::Ref(_)
    ));
    assert!(matches!(
        cfg.listeners[1].tls.as_ref().unwrap().cert,
        TlsConfig::SelfSigned
    ));
}

#[test]
fn certificate_without_name_is_error() {
    let err = Config::parse(
        r#"
        certificate {
            self-signed
        }
        listener { bind "[::]:80" }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("name"),
        "expected name-required error, got: {err}"
    );
}

#[test]
fn two_files_certs_with_same_paths_is_error() {
    let err = Config::parse(
        r#"
        listener {
            bind "[::]:443"
            tls-file cert="/etc/aloha/c.pem" key="/etc/aloha/k.pem"
        }
        listener {
            bind "[::]:8443"
            tls-file cert="/etc/aloha/c.pem" key="/etc/aloha/k.pem"
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("file-based") || err.contains("claimed"),
        "expected file conflict error, got: {err}"
    );
}

#[test]
fn cert_key_mode_default_is_none() {
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:80" }
        server {}
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.server.cert_key_mode, None);
}

#[test]
fn cert_key_mode_parses_octal_string() {
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:80" }
        server {
            cert-key-mode "0640"
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    assert_eq!(cfg.server.cert_key_mode, Some(0o640));
}

#[test]
fn cert_key_mode_invalid_is_error() {
    let result = Config::parse(
        r#"
        listener { bind "[::]:80" }
        server {
            cert-key-mode "notamode"
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn oidc_parses_inside_jwt_wrap() {
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:80" }
        server {
            state-dir "/tmp/aloha-test"
            auth jwt {
                validity 3600
                wrap oidc {
                    issuer "https://accounts.example.com"
                    client-id "abc"
                    client-secret "shh"
                    redirect-uri "https://app.example/.aloha/oidc/callback"
                    scope "openid"
                    scope "email"
                    groups-claim "roles"
                    username-claim "preferred_username"
                }
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    let inner = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => b.as_ref(),
        _ => panic!("expected Jwt with inner"),
    };
    let oc = match inner {
        AuthBackend::Oidc(c) => c,
        _ => panic!("expected inner Oidc"),
    };
    assert_eq!(oc.issuer, "https://accounts.example.com");
    assert_eq!(oc.client_id, "abc");
    assert_eq!(oc.client_secret.as_deref(), Some("shh"));
    assert_eq!(oc.username_claim, "preferred_username");
    assert_eq!(oc.groups_claim, "roles");
    assert!(oc.scopes.contains(&"openid".to_owned()));
    assert!(oc.scopes.contains(&"email".to_owned()));
    assert_eq!(oc.login_path, "/.aloha/oidc/login");
    assert_eq!(oc.callback_path, "/.aloha/oidc/callback");
}

#[test]
fn oidc_outside_jwt_is_rejected() {
    let result = Config::parse(
        r#"
        listener { bind "[::]:80" }
        server {
            auth oidc {
                issuer "https://accounts.example.com"
                client-id "abc"
                redirect-uri "https://app.example/cb"
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    );
    let err = result.expect_err("oidc without jwt wrap must be rejected");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("auth oidc must be wrapped inside auth jwt"),
        "expected wrap-required error, got: {msg}",
    );
}

#[test]
fn oidc_rejects_non_https_issuer() {
    let result = Config::parse(
        r#"
        listener { bind "[::]:80" }
        server {
            state-dir "/tmp/aloha-test"
            auth jwt {
                wrap oidc {
                    issuer "http://evil.example.com"
                    client-id "abc"
                    redirect-uri "https://app.example/cb"
                }
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn oidc_refresh_defaults_off() {
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:80" }
        server {
            state-dir "/tmp/aloha-test"
            auth jwt {
                wrap oidc {
                    issuer "https://accounts.example.com"
                    client-id "abc"
                    redirect-uri "https://app.example/cb"
                }
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    let oc = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => match b.as_ref() {
            AuthBackend::Oidc(c) => c,
            _ => panic!("expected oidc"),
        },
        _ => panic!("expected jwt"),
    };
    assert!(!oc.refresh);
    assert_eq!(oc.refresh_ttl_secs, 86_400);
    assert_eq!(oc.refresh_cookie_name, "__aloha_oidc_refresh");
    assert!(!oc.scopes.iter().any(|s| s == "offline_access"));
}

#[test]
fn oidc_backchannel_defaults() {
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:80" }
        server {
            state-dir "/tmp/aloha-test"
            auth jwt {
                wrap oidc {
                    issuer "https://accounts.example.com"
                    client-id "abc"
                    redirect-uri "https://app.example/cb"
                }
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    let oc = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => match b.as_ref() {
            AuthBackend::Oidc(c) => c,
            _ => panic!("expected oidc"),
        },
        _ => panic!("expected jwt"),
    };
    assert!(oc.backchannel_logout_enabled);
    assert_eq!(
        oc.backchannel_logout_path,
        "/.aloha/oidc/backchannel-logout"
    );
    assert_eq!(oc.backchannel_max_iat_skew_secs, 120);
    assert_eq!(oc.backchannel_jti_ttl_secs, 300);
}

#[test]
fn oidc_backchannel_path_must_differ() {
    let result = Config::parse(
        r#"
        listener { bind "[::]:80" }
        server {
            state-dir "/tmp/aloha-test"
            auth jwt {
                wrap oidc {
                    issuer "https://accounts.example.com"
                    client-id "abc"
                    redirect-uri "https://app.example/cb"
                    backchannel-logout-path "/.aloha/oidc/logout"
                }
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    );
    assert!(result.is_err(), "overlapping paths must be rejected");
}

#[test]
fn oidc_operational_fields_default() {
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:80" }
        server {
            state-dir "/tmp/aloha-test"
            auth jwt {
                wrap oidc {
                    issuer "https://accounts.example.com"
                    client-id "abc"
                    redirect-uri "https://app.example/cb"
                }
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    let oc = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => match b.as_ref() {
            AuthBackend::Oidc(c) => c,
            _ => panic!("expected oidc"),
        },
        _ => panic!("expected jwt"),
    };
    assert!(!oc.userinfo);
    assert_eq!(oc.discovery_refresh_secs, 3600);
    assert!(oc.discovery_retry);
}

#[test]
fn oidc_discovery_refresh_zero_disables() {
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:80" }
        server {
            state-dir "/tmp/aloha-test"
            auth jwt {
                wrap oidc {
                    issuer "https://accounts.example.com"
                    client-id "abc"
                    redirect-uri "https://app.example/cb"
                    discovery-refresh 0
                    discovery-retry #false
                    userinfo #true
                }
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    let oc = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => match b.as_ref() {
            AuthBackend::Oidc(c) => c,
            _ => panic!("expected oidc"),
        },
        _ => panic!("expected jwt"),
    };
    assert_eq!(oc.discovery_refresh_secs, 0);
    assert!(!oc.discovery_retry);
    assert!(oc.userinfo);
}

#[test]
fn oidc_logout_fields_default() {
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:80" }
        server {
            state-dir "/tmp/aloha-test"
            auth jwt {
                wrap oidc {
                    issuer "https://accounts.example.com"
                    client-id "abc"
                    redirect-uri "https://app.example/cb"
                }
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    let oc = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => match b.as_ref() {
            AuthBackend::Oidc(c) => c,
            _ => panic!("expected oidc"),
        },
        _ => panic!("expected jwt"),
    };
    assert_eq!(oc.logout_path, "/.aloha/oidc/logout");
    assert_eq!(oc.post_logout_uri, "/");
    assert!(oc.idp_logout);
}

#[test]
fn oidc_logout_path_rejected_when_overlaps_login() {
    let result = Config::parse(
        r#"
        listener { bind "[::]:80" }
        server {
            state-dir "/tmp/aloha-test"
            auth jwt {
                wrap oidc {
                    issuer "https://accounts.example.com"
                    client-id "abc"
                    redirect-uri "https://app.example/cb"
                    logout-path "/.aloha/oidc/login"
                }
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    );
    let err = result.expect_err("overlapping paths must be rejected");
    let msg = format!("{err:#}");
    assert!(msg.contains("must differ"), "got: {msg}");
}

#[test]
fn oidc_post_logout_uri_rejects_off_origin() {
    let result = Config::parse(
        r#"
        listener { bind "[::]:80" }
        server {
            state-dir "/tmp/aloha-test"
            auth jwt {
                wrap oidc {
                    issuer "https://accounts.example.com"
                    client-id "abc"
                    redirect-uri "https://app.example/cb"
                    post-logout-uri "//evil.example/"
                }
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    );
    assert!(result.is_err());
}

#[test]
fn oidc_refresh_enabled_injects_offline_access_scope() {
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:80" }
        server {
            state-dir "/tmp/aloha-test"
            auth jwt {
                wrap oidc {
                    issuer "https://accounts.example.com"
                    client-id "abc"
                    redirect-uri "https://app.example/cb"
                    refresh #true
                    refresh-ttl 3600
                    refresh-cookie "session_rt"
                }
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    let oc = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => match b.as_ref() {
            AuthBackend::Oidc(c) => c,
            _ => panic!("expected oidc"),
        },
        _ => panic!("expected jwt"),
    };
    assert!(oc.refresh);
    assert_eq!(oc.refresh_ttl_secs, 3600);
    assert_eq!(oc.refresh_cookie_name, "session_rt");
    assert!(
        oc.scopes.iter().any(|s| s == "offline_access"),
        "expected offline_access in scopes, got {:?}",
        oc.scopes,
    );
}

#[test]
fn oidc_defaults_inject_openid_scope() {
    let cfg = Config::parse(
        r#"
        listener { bind "[::]:80" }
        server {
            state-dir "/tmp/aloha-test"
            auth jwt {
                wrap oidc {
                    issuer "https://accounts.example.com"
                    client-id "abc"
                    redirect-uri "https://app.example/.aloha/oidc/callback"
                }
            }
        }
        vhost "h" { location "/" { static { root "."; } } }
        "#,
    )
    .unwrap();
    let oc = match &cfg.server.auth {
        Some(AuthBackend::Jwt { inner: Some(b), .. }) => match b.as_ref() {
            AuthBackend::Oidc(c) => c,
            _ => panic!("expected oidc"),
        },
        _ => panic!("expected jwt"),
    };
    // Default scope set includes the mandatory `openid`.
    assert!(oc.scopes.first().map(|s| s.as_str()) == Some("openid"));
}
