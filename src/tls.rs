use crate::config::{TlsConfig, TlsListenerConfig, TlsOptions, TlsVersion};
use anyhow::Context;
use rustls::ServerConfig;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer,
};
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

// Build a TlsAcceptor for the given listener config.
// `defaults` supplies global options; per-listener options win where set.
// ALPN is advertised for both h2 and http/1.1 so that
// hyper's auto::Builder selects the right protocol per connection.
pub fn build_acceptor(
    tls: &TlsListenerConfig,
    defaults: &TlsOptions,
) -> anyhow::Result<TlsAcceptor> {
    let opts = tls.options.resolve(defaults);
    match &tls.cert {
        TlsConfig::Files { cert, key } => {
            let (chain, key) = load_cert_and_key(
                Path::new(cert),
                Path::new(key),
            )?;
            make_acceptor(chain, key, &opts)
        }
        TlsConfig::SelfSigned => {
            tracing::warn!(
                "using ephemeral self-signed certificate — \
                 not suitable for production"
            );
            build_self_signed(&opts)
        }
        TlsConfig::Acme { .. } => {
            // ACME acceptors are built in main.rs via acme::AcmeManager
            // and passed directly to run_tls; build_acceptor is never
            // called with the Acme variant.
            unreachable!("Acme TLS handled by AcmeManager")
        }
    }
}

// Generate an in-memory self-signed certificate valid for
// "localhost".  The certificate is recreated on every server start.
fn build_self_signed(opts: &TlsOptions) -> anyhow::Result<TlsAcceptor> {
    use rcgen::{generate_simple_self_signed, CertifiedKey};

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()])
            .context("generating self-signed certificate")?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(
        PrivatePkcs8KeyDer::from(signing_key.serialize_der()),
    );

    make_acceptor(vec![cert_der], key_der, opts)
}

// Shared acceptor construction from any cert+key source.
// Public so acme.rs can reuse it when loading stored ACME certs.
pub fn make_acceptor(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    opts: &TlsOptions,
) -> anyhow::Result<TlsAcceptor> {
    // Build a provider, optionally restricting the cipher suite list.
    let mut provider =
        rustls::crypto::aws_lc_rs::default_provider();
    if !opts.ciphers.is_empty() {
        provider.cipher_suites = resolve_ciphers(&opts.ciphers)?;
    }

    let versions = protocol_versions(opts.min_version);
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&versions)
            .context("invalid TLS protocol version configuration")?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .context("building TLS ServerConfig")?;

    config.alpn_protocols =
        vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
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
    let provider =
        rustls::crypto::aws_lc_rs::default_provider();
    names.iter().map(|name| {
        let cs = name_to_cipher_suite(name)?;
        provider
            .cipher_suites
            .iter()
            .find(|s| s.suite() == cs)
            .copied()
            .ok_or_else(|| anyhow::anyhow!(
                "cipher suite '{name}' is not available \
                 with the current provider"
            ))
    }).collect()
}

fn name_to_cipher_suite(
    name: &str,
) -> anyhow::Result<rustls::CipherSuite> {
    use rustls::CipherSuite::*;
    Ok(match name {
        "TLS13_AES_256_GCM_SHA384" => {
            TLS13_AES_256_GCM_SHA384
        }
        "TLS13_AES_128_GCM_SHA256" => {
            TLS13_AES_128_GCM_SHA256
        }
        "TLS13_CHACHA20_POLY1305_SHA256" => {
            TLS13_CHACHA20_POLY1305_SHA256
        }
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
        other => anyhow::bail!(
            "unknown cipher suite '{other}'"
        ),
    })
}

pub fn load_cert_and_key(
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<(
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
)> {
    let cert_chain: Vec<CertificateDer<'static>> =
        certs(&mut BufReader::new(
            File::open(cert_path).with_context(|| {
                format!(
                    "opening cert file {}",
                    cert_path.display()
                )
            })?,
        ))
        .collect::<Result<_, _>>()
        .context("reading certificate PEM")?;

    if cert_chain.is_empty() {
        anyhow::bail!(
            "no certificates found in {}",
            cert_path.display()
        );
    }

    let key = private_key(&mut BufReader::new(
        File::open(key_path).with_context(|| {
            format!("opening key file {}", key_path.display())
        })?,
    ))
    .context("reading private key PEM")?
    .with_context(|| {
        format!(
            "no private key found in {}",
            key_path.display()
        )
    })?;

    Ok((cert_chain, key))
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TlsVersion;

    fn install_provider() {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();
    }

    // ── name_to_cipher_suite ─────────────────────────────────────

    #[test]
    fn known_tls13_cipher_names_parse() {
        for name in &[
            "TLS13_AES_256_GCM_SHA384",
            "TLS13_AES_128_GCM_SHA256",
            "TLS13_CHACHA20_POLY1305_SHA256",
        ] {
            assert!(
                name_to_cipher_suite(name).is_ok(),
                "{name} should parse"
            );
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
            assert!(
                name_to_cipher_suite(name).is_ok(),
                "{name} should parse"
            );
        }
    }

    #[test]
    fn unknown_cipher_name_is_error() {
        assert!(name_to_cipher_suite("RC4_MD5").is_err());
        assert!(name_to_cipher_suite("").is_err());
    }

    // ── protocol_versions ────────────────────────────────────────

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
        assert_eq!(
            versions[0].version,
            rustls::ProtocolVersion::TLSv1_3
        );
    }

    // ── build_self_signed ────────────────────────────────────────

    #[tokio::test]
    async fn self_signed_acceptor_builds_without_error() {
        install_provider();
        let opts = TlsOptions::default();
        let result = build_self_signed(&opts);
        assert!(result.is_ok());
    }
}
