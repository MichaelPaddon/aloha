// TLS acceptor construction: loads PEM files, generates self-signed
// certificates, and maps config cipher/version names to rustls types.
// ACME-managed certificates are handled separately in acme.rs.

use crate::config::{TlsConfig, TlsListenerConfig, TlsOptions, TlsVersion};
use anyhow::Context;
use arc_swap::ArcSwap;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

/// Certificate and private key in DER form, used as the canonical
/// representation that both the TCP TLS acceptor and the QUIC server
/// config are derived from.  Stored behind an `Arc` so that publishing
/// a renewal does not have to clone the key bytes (which `PrivateKeyDer`
/// does not implement `Clone` for).
pub struct CertPair {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

/// Live certificate "subscription" for a listener.  `tls` is the
/// existing hot-swappable acceptor used by the TCP path; `cert_rx`
/// publishes the underlying cert+key pair so that other consumers
/// (notably the QUIC endpoint) can rebuild their own protocol-specific
/// config on each renewal without having to know about ACME.
///
/// For static cert sources (`Files`, `SelfSigned`) the watch channel is
/// seeded once and never updated.  For ACME the renewal loop publishes
/// the new pair before swapping the TLS acceptor, so any QUIC listener
/// subscribed to the same source rolls over the cert atomically.
pub struct CertSource {
    pub tls: Arc<ArcSwap<TlsAcceptor>>,
    pub cert_rx: watch::Receiver<Arc<CertPair>>,
}

// Build a TlsAcceptor for the given listener config.
// `defaults` supplies global options; per-listener options win where set.
// ALPN is advertised for both h2 and http/1.1 so that
// hyper's auto::Builder selects the right protocol per connection.
/// Build the TLS acceptor *and* return the underlying cert+key pair
/// so callers can publish it (see `CertSource`) or derive additional
/// protocol-specific configs (e.g. `quinn::ServerConfig` for QUIC).
/// Only valid for the `Files` and `SelfSigned` variants; the `Acme`
/// variant is acquired via `AcmeManager` and panics here, matching
/// the long-standing invariant on `build_acceptor`.
pub fn build_acceptor_with_pair(
    tls: &TlsListenerConfig,
    defaults: &TlsOptions,
) -> anyhow::Result<(TlsAcceptor, CertPair)> {
    let opts = tls.options.resolve(defaults);
    match &tls.cert {
        TlsConfig::Files { cert, key } => {
            let (chain, key) =
                load_cert_and_key(Path::new(cert), Path::new(key))?;
            let acc = make_acceptor_from_refs(&chain, &key, &opts)?;
            Ok((acc, CertPair { chain, key }))
        }
        TlsConfig::SelfSigned => {
            tracing::warn!(
                "using ephemeral self-signed certificate -- \
                 not suitable for production"
            );
            let pair = build_self_signed_pair()?;
            let acc =
                make_acceptor_from_refs(&pair.chain, &pair.key, &opts)?;
            Ok((acc, pair))
        }
        TlsConfig::Acme { .. } => {
            unreachable!("Acme TLS handled by AcmeManager")
        }
    }
}

// Generate an in-memory self-signed certificate valid for "localhost".
// Returns the raw cert+key pair so the caller can build whatever
// protocol-specific config they need (TLS acceptor, QUIC server, ...).
fn build_self_signed_pair() -> anyhow::Result<CertPair> {
    use rcgen::{CertifiedKey, generate_simple_self_signed};

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()])
            .context("generating self-signed certificate")?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        signing_key.serialize_der(),
    ));
    Ok(CertPair { chain: vec![cert_der], key: key_der })
}

// Build a TLS acceptor without consuming the cert/key.  This is the
// preferred entry point now that the same pair is shared with the
// QUIC server config; the by-value `make_acceptor` is preserved for
// existing call sites in acme.rs.
pub fn make_acceptor_from_refs(
    chain: &[CertificateDer<'static>],
    key: &PrivateKeyDer<'static>,
    opts: &TlsOptions,
) -> anyhow::Result<TlsAcceptor> {
    make_acceptor(chain.to_vec(), clone_key(key), opts)
}

/// Clone a `PrivateKeyDer` by round-tripping its raw DER bytes, working
/// around the fact that `rustls::pki_types::PrivateKeyDer` does not
/// implement `Clone` (its variants wrap secret material that must be
/// cloned explicitly).  Used when the same key is needed by both the
/// rustls TLS acceptor and a `quinn::crypto::rustls::QuicServerConfig`.
pub fn clone_key(key: &PrivateKeyDer<'static>) -> PrivateKeyDer<'static> {
    use rustls::pki_types::{
        PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    };
    match key {
        PrivateKeyDer::Pkcs1(k) => PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from(k.secret_pkcs1_der().to_vec()),
        ),
        PrivateKeyDer::Pkcs8(k) => PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::from(k.secret_pkcs8_der().to_vec()),
        ),
        PrivateKeyDer::Sec1(k) => PrivateKeyDer::Sec1(
            PrivateSec1KeyDer::from(k.secret_sec1_der().to_vec()),
        ),
        // PrivateKeyDer is marked #[non_exhaustive]; future variants
        // should be added here explicitly so any new key type forces
        // a compile-time review of the QUIC path.
        _ => unreachable!("unhandled PrivateKeyDer variant"),
    }
}

// Shared acceptor construction from any cert+key source.
// Public so acme.rs can reuse it when loading stored ACME certs.
pub fn make_acceptor(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    opts: &TlsOptions,
) -> anyhow::Result<TlsAcceptor> {
    // Build a provider, optionally restricting the cipher suite list.
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    if !opts.ciphers.is_empty() {
        provider.cipher_suites = resolve_ciphers(&opts.ciphers)?;
    }

    let versions = protocol_versions(opts.min_version);
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&versions)
        .context("invalid TLS protocol version configuration")?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("building TLS ServerConfig")?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Build a `quinn::ServerConfig` for HTTP/3 from the same cert+key
/// pair used by the TCP TLS acceptor.  ALPN advertises only `h3` so
/// clients negotiate HTTP/3 against this endpoint; cipher and minimum
/// protocol-version options are honoured identically to the TCP path
/// to keep operator expectations consistent.
///
/// Only available when the `http3` cargo feature is enabled -- the
/// `quinn` and `h3` crates are pulled in conditionally to keep the
/// default build slim.
#[cfg(feature = "http3")]
pub fn build_quic_server_config(
    pair: &CertPair,
    opts: &TlsOptions,
) -> anyhow::Result<quinn::ServerConfig> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    if !opts.ciphers.is_empty() {
        provider.cipher_suites = resolve_ciphers(&opts.ciphers)?;
    }
    let versions = protocol_versions(opts.min_version);
    let mut rustls_cfg = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&versions)
        .context("invalid TLS protocol version configuration")?
        .with_no_client_auth()
        .with_single_cert(pair.chain.clone(), clone_key(&pair.key))
        .context("building rustls ServerConfig for QUIC")?;
    // QUIC advertises only h3; HTTP/1.1 and h2 are TCP-only ALPNs and
    // would only confuse a client that ended up here.
    rustls_cfg.alpn_protocols = vec![b"h3".to_vec()];
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_cfg)
        .context("wrapping rustls config as QuicServerConfig")?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic)))
}

// Map min_version to the set of enabled rustls protocol versions.
// "1.3" means TLS 1.3 only; "1.2" (or absent) means 1.2 and 1.3.
fn protocol_versions(
    min: Option<TlsVersion>,
) -> Vec<&'static rustls::SupportedProtocolVersion> {
    match min {
        None | Some(TlsVersion::Tls12) => {
            vec![&rustls::version::TLS12, &rustls::version::TLS13]
        }
        Some(TlsVersion::Tls13) => vec![&rustls::version::TLS13],
    }
}

// Map cipher suite name strings to SupportedCipherSuite values.
//
// We match against rustls::CipherSuite enum variants (IANA names),
// then find the corresponding SupportedCipherSuite in the provider's
// list.  This keeps us decoupled from provider-internal module paths.
fn resolve_ciphers(
    names: &[String],
) -> anyhow::Result<Vec<rustls::SupportedCipherSuite>> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    names
        .iter()
        .map(|name| {
            let cs = name_to_cipher_suite(name)?;
            provider
                .cipher_suites
                .iter()
                .find(|s| s.suite() == cs)
                .copied()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "cipher suite '{name}' is not available \
                 with the current provider"
                    )
                })
        })
        .collect()
}

fn name_to_cipher_suite(name: &str) -> anyhow::Result<rustls::CipherSuite> {
    use rustls::CipherSuite::*;
    Ok(match name {
        "TLS13_AES_256_GCM_SHA384" => TLS13_AES_256_GCM_SHA384,
        "TLS13_AES_128_GCM_SHA256" => TLS13_AES_128_GCM_SHA256,
        "TLS13_CHACHA20_POLY1305_SHA256" => TLS13_CHACHA20_POLY1305_SHA256,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => {
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        }
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => {
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        }
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => {
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        }
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => {
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        }
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => {
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        }
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        }
        other => anyhow::bail!("unknown cipher suite '{other}'"),
    })
}

pub fn load_cert_and_key(
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_chain: Vec<CertificateDer<'static>> =
        certs(&mut BufReader::new(File::open(cert_path).with_context(
            || format!("opening cert file {}", cert_path.display()),
        )?))
        .collect::<Result<_, _>>()
        .context("reading certificate PEM")?;

    if cert_chain.is_empty() {
        anyhow::bail!("no certificates found in {}", cert_path.display());
    }

    let key =
        private_key(&mut BufReader::new(File::open(key_path).with_context(
            || format!("opening key file {}", key_path.display()),
        )?))
        .context("reading private key PEM")?
        .with_context(|| {
            format!("no private key found in {}", key_path.display())
        })?;

    Ok((cert_chain, key))
}

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TlsVersion;

    fn install_provider() {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();
    }

    // -- name_to_cipher_suite -------------------------------------

    #[test]
    fn known_tls13_cipher_names_parse() {
        for name in &[
            "TLS13_AES_256_GCM_SHA384",
            "TLS13_AES_128_GCM_SHA256",
            "TLS13_CHACHA20_POLY1305_SHA256",
        ] {
            assert!(name_to_cipher_suite(name).is_ok(), "{name} should parse");
        }
    }

    #[test]
    fn known_tls12_cipher_names_parse() {
        for name in &[
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        ] {
            assert!(name_to_cipher_suite(name).is_ok(), "{name} should parse");
        }
    }

    #[test]
    fn unknown_cipher_name_is_error() {
        assert!(name_to_cipher_suite("RC4_MD5").is_err());
        assert!(name_to_cipher_suite("").is_err());
    }

    // -- protocol_versions ----------------------------------------

    #[test]
    fn no_min_version_includes_tls12_and_tls13() {
        let versions = protocol_versions(None);
        assert_eq!(versions.len(), 2);
    }

    #[test]
    fn min_tls12_includes_both_versions() {
        let versions = protocol_versions(Some(TlsVersion::Tls12));
        assert_eq!(versions.len(), 2);
    }

    #[test]
    fn min_tls13_includes_only_tls13() {
        let versions = protocol_versions(Some(TlsVersion::Tls13));
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, rustls::ProtocolVersion::TLSv1_3);
    }

    // -- build_self_signed ----------------------------------------

    #[tokio::test]
    async fn self_signed_acceptor_builds_without_error() {
        install_provider();
        let opts = TlsOptions::default();
        let pair = build_self_signed_pair().unwrap();
        let result =
            make_acceptor_from_refs(&pair.chain, &pair.key, &opts);
        assert!(result.is_ok());
    }
}
