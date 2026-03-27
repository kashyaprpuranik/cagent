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
    pub async fn get_acceptor(&self, domain: &str) -> Result<Arc<TlsAcceptor>, Box<dyn std::error::Error + Send + Sync>> {
        let domain = domain.to_lowercase();

        if let Some(acceptor) = self.cache.get(&domain).await {
            return Ok(acceptor);
        }

        let acceptor = Arc::new(self.create_acceptor(&domain)?);
        self.cache.insert(domain, acceptor.clone()).await;
        Ok(acceptor)
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

        // Generate leaf key pair
        let leaf_key = KeyPair::generate()?;
        let key_der = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());

        // Sign with CA
        let cert = params.signed_by(&leaf_key, &self.ca_cert, &self.ca_key_pair)?;
        let cert_der: CertificateDer<'static> = cert.into();

        Ok((cert_der, key_der))
    }
}
