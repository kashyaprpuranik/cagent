//! Dynamic certificate generation for MITM TLS interception.
//!
//! Generates per-domain leaf certificates signed by the MITM CA,
//! cached in an async LRU (moka) to avoid regenerating on every request.

use std::sync::Arc;

use moka::future::Cache;
use rcgen::{CertificateParams, DistinguishedName, DnType, DnValue, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// Certificate authority for MITM cert signing.
pub struct MitmCa {
    ca_key_pair: KeyPair,
    ca_cert: rcgen::Certificate,
    ca_cert_der: CertificateDer<'static>,
    cache: Cache<String, Arc<TlsAcceptor>>,
}

impl MitmCa {
    /// Create a new MITM CA from PEM-encoded cert and key.
    pub fn from_pem(ca_cert_pem: &str, ca_key_pem: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let ca_key_pair = KeyPair::from_pem(ca_key_pem)?;
        let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)?;
        let ca_cert = ca_params.self_signed(&ca_key_pair)?;

        // Parse CA cert DER for the TLS chain
        let ca_cert_der = rustls_pemfile::certs(&mut ca_cert_pem.as_bytes())
            .next()
            .ok_or("no cert found in PEM")??;

        let cache = Cache::builder()
            .max_capacity(1_000)
            .time_to_live(std::time::Duration::from_secs(3600))
            .build();

        Ok(Self {
            ca_key_pair,
            ca_cert,
            ca_cert_der,
            cache,
        })
    }

    /// Get or create a TLS acceptor for the given domain.
    ///
    /// Uses moka's `try_get_with` for atomic get-or-insert — concurrent
    /// CONNECT requests for the same domain share a single cert generation
    /// instead of racing.
    pub async fn get_acceptor(&self, domain: &str) -> Result<Arc<TlsAcceptor>, Box<dyn std::error::Error + Send + Sync>> {
        let domain_lower = domain.to_lowercase();
        let domain_for_gen = domain_lower.clone();

        self.cache
            .try_get_with(domain_lower, async {
                let acceptor = self.create_acceptor(&domain_for_gen)?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(Arc::new(acceptor))
            })
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
            })
    }

    /// Generate a leaf cert for the domain and create a TLS acceptor.
    fn create_acceptor(&self, domain: &str) -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
        let (cert_der, key_der) = self.generate_cert(domain)?;

        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert_der, self.ca_cert_der.clone()],
                PrivateKeyDer::Pkcs8(key_der),
            )?;

        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(TlsAcceptor::from(Arc::new(server_config)))
    }

    /// Generate a leaf certificate for the domain, signed by the CA.
    fn generate_cert(
        &self,
        domain: &str,
    ) -> Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>), Box<dyn std::error::Error + Send + Sync>> {
        let mut params = CertificateParams::default();

        // Subject
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, DnValue::Utf8String(domain.to_string()));
        dn.push(DnType::OrganizationName, DnValue::Utf8String("Cagent MITM".to_string()));
        params.distinguished_name = dn;

        // SAN
        params.subject_alt_names = vec![SanType::DnsName(domain.try_into()?)];

        // Short validity — MITM certs are ephemeral and cached for 1h
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(24);

        // Generate leaf key pair
        let leaf_key = KeyPair::generate()?;
        let key_der = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());

        // Sign with CA
        let cert = params.signed_by(&leaf_key, &self.ca_cert, &self.ca_key_pair)?;
        let cert_der: CertificateDer<'static> = cert.into();

        Ok((cert_der, key_der))
    }
}
