//! cagent-proxy: unified HTTP/HTTPS forward proxy + DNS filter.
//!
//! Phase 1: HTTP forward proxy with domain allowlist, credential injection,
//! path filtering, read-only enforcement. Config pushed by warden via HTTP.

mod certs;
mod config;
mod config_api;
mod dlp;
mod dns;
mod email;
mod mitm;
mod proxy;
mod util;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Semaphore;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::AsyncBufReadExt;
use tokio::net::TcpListener;

/// Proxy listen address (cell connects here).
const PROXY_ADDR: &str = "0.0.0.0:18443";
/// Config API listen address (warden pushes config here).
const CONFIG_ADDR: &str = "0.0.0.0:18080";
/// DNS listen address.
const DNS_ADDR: &str = "0.0.0.0:53";
/// Path to MITM CA cert PEM (mounted from host).
const CA_CERT_PATH: &str = "/etc/cagent/mitm/mitmproxy-ca-cert.pem";
/// Path to MITM CA key PEM (mounted from host).
const CA_KEY_PATH: &str = "/etc/cagent/mitm/mitmproxy-ca.pem";

#[tokio::main]
async fn main() {
    // Initialize logging — JSON output with flattened fields so Vector can
    // extract access-log fields (method, response_code, authority, etc.)
    // directly from the top-level JSON keys.
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cagent_proxy=info".parse().unwrap()),
        )
        .init();

    // Install rustls crypto provider (ring) before any TLS operations
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing::info!("cagent-proxy starting");
    tracing::info!("  proxy: {}", PROXY_ADDR);
    tracing::info!("  config: {}", CONFIG_ADDR);
    tracing::info!("  dns: {}", DNS_ADDR);

    // Surface whether CAGENT_PROXY_TOKEN is set so operators notice
    // unauthenticated config APIs in production deployments.
    config_api::log_auth_status();

    // Load MITM CA (optional — HTTPS interception only works if CA is present)
    let mitm_ca = load_mitm_ca();

    let dns_addr: SocketAddr = DNS_ADDR.parse().expect("invalid DNS_ADDR");

    // Start all listeners concurrently
    tokio::select! {
        res = run_proxy_listener(mitm_ca) => {
            tracing::error!("proxy listener exited: {:?}", res);
        }
        res = run_config_listener() => {
            tracing::error!("config listener exited: {:?}", res);
        }
        res = dns::run_dns_server(dns_addr) => {
            tracing::error!("DNS server exited: {:?}", res);
        }
    }
}

/// Load MITM CA from PEM files. Returns None if files don't exist.
fn load_mitm_ca() -> Option<Arc<certs::MitmCa>> {
    let cert_path = std::env::var("MITM_CA_CERT").unwrap_or_else(|_| CA_CERT_PATH.to_string());
    let key_path = std::env::var("MITM_CA_KEY").unwrap_or_else(|_| CA_KEY_PATH.to_string());

    let cert_pem = match std::fs::read_to_string(&cert_path) {
        Ok(s) => s,
        Err(_) => {
            tracing::warn!("MITM CA cert not found at {}, HTTPS interception disabled", cert_path);
            return None;
        }
    };
    let key_pem = match std::fs::read_to_string(&key_path) {
        Ok(s) => s,
        Err(_) => {
            tracing::warn!("MITM CA key not found at {}, HTTPS interception disabled", key_path);
            return None;
        }
    };

    match certs::MitmCa::from_pem(&cert_pem, &key_pem) {
        Ok(ca) => {
            tracing::info!("MITM CA loaded, HTTPS interception enabled");
            Some(Arc::new(ca))
        }
        Err(e) => {
            tracing::error!("Failed to load MITM CA: {}", e);
            None
        }
    }
}

/// Run the HTTP/HTTPS forward proxy listener.
///
/// Peeks at the first line to detect CONNECT (HTTPS) vs plain HTTP.
/// CONNECT requests get MITM treatment; plain HTTP goes through the normal proxy.
/// Maximum concurrent proxy connections.  Prevents unbounded task spawning
/// if a compromised cell floods the proxy (defense-in-depth on top of the
/// cell's 256-PID limit).
const MAX_PROXY_CONNECTIONS: usize = 1024;

async fn run_proxy_listener(
    mitm_ca: Option<Arc<certs::MitmCa>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = PROXY_ADDR.parse()?;
    let listener = TcpListener::bind(addr).await?;
    let semaphore = Arc::new(Semaphore::new(MAX_PROXY_CONNECTIONS));
    tracing::info!("proxy listening on {} (max {} concurrent)", addr, MAX_PROXY_CONNECTIONS);

    loop {
        let (stream, peer) = listener.accept().await?;
        let ca = mitm_ca.clone();
        let permit = semaphore.clone().acquire_owned().await.unwrap();

        tokio::spawn(async move {
            let _permit = permit; // held until task completes
            // Peek at the first bytes to detect CONNECT
            let mut buf = [0u8; 8];
            let n = match stream.peek(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(peer = %peer, error = %e, "peek failed");
                    return;
                }
            };

            let first_bytes = &buf[..n];
            let is_connect = first_bytes.starts_with(b"CONNECT");

            tracing::info!(
                peer = %peer,
                is_connect = is_connect,
                first_bytes = %String::from_utf8_lossy(first_bytes),
                "new connection"
            );

            if is_connect {
                // CONNECT — read the full request line manually, then do MITM
                if let Some(ca) = ca {
                    handle_connect_stream(stream, ca, peer).await;
                } else {
                    // No MITM CA — reject CONNECT
                    let mut stream = stream;
                    let _ = tokio::io::AsyncWriteExt::write_all(
                        &mut stream,
                        b"HTTP/1.1 503 HTTPS interception not configured\r\n\r\n",
                    ).await;
                }
            } else {
                // Plain HTTP — use hyper
                let io = TokioIo::new(stream);
                if let Err(e) = http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(io, service_fn(proxy::handle_request))
                    .await
                {
                    tracing::debug!(peer = %peer, error = %e, "proxy connection error");
                }
            }
        });
    }
}

/// Handle a CONNECT stream: parse the request line, then hand off to MITM.
async fn handle_connect_stream(
    stream: tokio::net::TcpStream,
    ca: Arc<certs::MitmCa>,
    peer: SocketAddr,
) {
    use tokio::io::BufReader;

    let mut reader = BufReader::new(stream);

    // Read request line: "CONNECT host:port HTTP/1.1\r\n"
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).await.is_err() {
        return;
    }

    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "CONNECT" {
        return;
    }

    let authority = parts[1];

    // Read and discard remaining headers until empty line
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line).await {
            Ok(0) => return, // EOF
            Ok(_) => {
                if line.trim().is_empty() {
                    break; // End of headers
                }
            }
            Err(_) => return,
        }
    }

    // Reject any bytes pipelined after the CONNECT headers but before the
    // 200 response.  A well-behaved client waits for "200 Connection
    // Established" before sending tunnelled data; a compromised cell could
    // smuggle bytes past the TLS handshake otherwise (they'd be buffered
    // inside `BufReader` and silently dropped when we call `into_inner()`).
    if !reader.buffer().is_empty() {
        tracing::warn!(
            peer = %peer,
            residual = reader.buffer().len(),
            "CONNECT rejected: bytes pipelined before handshake complete"
        );
        let mut stream = reader.into_inner();
        let _ = tokio::io::AsyncWriteExt::write_all(
            &mut stream,
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
        ).await;
        return;
    }

    // Get the underlying stream back from the BufReader
    let stream = reader.into_inner();

    let domain = authority.split(':').next().unwrap_or("").to_string();
    let port: u16 = authority.split(':').nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(443);

    // Block cloud metadata endpoint
    if domain == "169.254.169.254" || domain.eq_ignore_ascii_case("metadata.google.internal") {
        tracing::warn!(domain = %domain, "CONNECT blocked: metadata endpoint");
        let mut stream = stream;
        let _ = tokio::io::AsyncWriteExt::write_all(
            &mut stream,
            b"HTTP/1.1 403 Forbidden\r\n\r\n",
        ).await;
        return;
    }

    // Check allowlist
    {
        let config = config::CONFIG.load();
        if !config.is_allowed(&domain) {
            tracing::info!(domain = %domain, "CONNECT blocked: domain not in allowlist");
            let mut stream = stream;
            let _ = tokio::io::AsyncWriteExt::write_all(
                &mut stream,
                b"HTTP/1.1 403 Forbidden\r\n\r\n",
            ).await;
            return;
        }
    }

    // Send 200 Connection Established
    let mut raw = stream;
    if tokio::io::AsyncWriteExt::write_all(
        &mut raw,
        b"HTTP/1.1 200 Connection Established\r\n\r\n",
    ).await.is_err() {
        return;
    }

    // TLS handshake + MITM
    let acceptor = match ca.get_acceptor(&domain).await {
        Ok(a) => a,
        Err(e) => {
            tracing::debug!(domain = %domain, error = %e, "cert generation failed");
            return;
        }
    };

    let tls_stream = match acceptor.accept(raw).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(domain = %domain, error = %e, "MITM TLS handshake failed");
            return;
        }
    };

    tracing::debug!(domain = %domain, peer = %peer, "MITM established");

    // Serve HTTP over decrypted TLS
    let io = TokioIo::new(tls_stream);
    let domain_clone = domain.clone();

    let _ = http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(
            io,
            service_fn(move |req| {
                let domain = domain_clone.clone();
                async move {
                    mitm::handle_intercepted_request(req, &domain, port).await
                }
            }),
        )
        .await;
}

/// Run the config push API listener.
async fn run_config_listener() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = CONFIG_ADDR.parse()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("config API listening on {}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .serve_connection(io, service_fn(config_api::handle_config_request))
                .await
            {
                tracing::debug!(error = %e, "config API connection error");
            }
        });
    }
}
