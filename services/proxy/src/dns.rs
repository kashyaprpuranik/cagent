//! DNS filtering server using Hickory DNS.
//!
//! Embeds a DNS server that:
//! - Allows domains in the allowlist → forwards to upstream resolver
//! - Blocks all other domains → returns NXDOMAIN
//! - Resolves devbox.local aliases → returns proxy IP
//!
//! Shares the domain allowlist with the HTTP proxy via arc-swap CONFIG.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use hickory_proto::op::{Header, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use tokio::net::UdpSocket;

use crate::config::CONFIG;

/// Upstream DNS servers for forwarding allowed queries.
const UPSTREAM_DNS: &[&str] = &["8.8.8.8:53", "8.8.4.4:53"];

/// IP address to return for devbox.local aliases (points to the proxy itself).
/// Defaults to 127.0.0.1; overridden by DEVBOX_LOCAL_IP env var (e.g., 10.200.1.20).
fn devbox_local_ip() -> Ipv4Addr {
    std::env::var("DEVBOX_LOCAL_IP")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(Ipv4Addr::new(127, 0, 0, 1))
}

/// Run the DNS filter server.
pub async fn run_dns_server(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket = UdpSocket::bind(addr).await?;
    tracing::info!("DNS server listening on {}", addr);

    let socket = Arc::new(socket);
    let mut buf = [0u8; 4096];

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "DNS recv error");
                continue;
            }
        };

        let query_data = buf[..len].to_vec();
        let sock = socket.clone();

        tokio::spawn(async move {
            match handle_dns_query(&query_data, src, &sock).await {
                Ok(()) => {}
                Err(e) => tracing::debug!(error = %e, "DNS query handling failed"),
            }
        });
    }
}

/// Handle a single DNS query.
async fn handle_dns_query(
    data: &[u8],
    src: SocketAddr,
    socket: &UdpSocket,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
    use hickory_proto::op::Message;

    let request = Message::from_bytes(data)?;
    let header = request.header();

    // Only handle standard queries
    if header.message_type() != MessageType::Query || header.op_code() != OpCode::Query {
        return Ok(());
    }

    let questions = request.queries();
    if questions.is_empty() {
        return Ok(());
    }

    let question = &questions[0];
    let qname = question.name().to_string();
    let qtype = question.query_type();

    // Strip trailing dot from DNS name
    let domain = qname.trim_end_matches('.');

    // Check if this is a devbox.local query
    if domain.ends_with(".devbox.local") || domain == "devbox.local" {
        let response = build_devbox_response(&request, domain, qtype);
        let response_bytes = response.to_bytes()?;
        socket.send_to(&response_bytes, src).await?;
        tracing::debug!(domain = domain, qtype = %qtype, "DNS: devbox.local → proxy IP");
        return Ok(());
    }

    // Check domain allowlist
    let config = CONFIG.load();
    let base_domain = extract_base_domain(domain);

    if !config.is_allowed(domain) && !config.is_allowed(&base_domain) {
        // Blocked — return NXDOMAIN
        let response = build_nxdomain_response(&request);
        let response_bytes = response.to_bytes()?;
        socket.send_to(&response_bytes, src).await?;
        tracing::info!(domain = domain, "DNS blocked: NXDOMAIN");
        return Ok(());
    }

    // Allowed — forward to upstream DNS
    match forward_dns_query(data).await {
        Ok(response_data) => {
            socket.send_to(&response_data, src).await?;
            tracing::debug!(domain = domain, "DNS allowed: forwarded");
        }
        Err(e) => {
            tracing::warn!(domain = domain, error = %e, "DNS upstream failed");
            let response = build_servfail_response(&request);
            let response_bytes = response.to_bytes()?;
            socket.send_to(&response_bytes, src).await?;
        }
    }

    Ok(())
}

/// Forward a DNS query to upstream resolvers.
async fn forward_dns_query(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let upstream = UdpSocket::bind("0.0.0.0:0").await?;

    for server in UPSTREAM_DNS {
        let addr: SocketAddr = server.parse()?;
        upstream.send_to(data, addr).await?;

        let mut buf = [0u8; 4096];
        match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            upstream.recv_from(&mut buf),
        ).await {
            Ok(Ok((len, _))) => return Ok(buf[..len].to_vec()),
            Ok(Err(e)) => tracing::debug!(server = server, error = %e, "DNS upstream recv error"),
            Err(_) => tracing::debug!(server = server, "DNS upstream timeout"),
        }
    }

    Err("all upstream DNS servers failed".into())
}

/// Build a response for devbox.local queries.
fn build_devbox_response(
    request: &hickory_proto::op::Message,
    _domain: &str,
    qtype: RecordType,
) -> hickory_proto::op::Message {
    use hickory_proto::op::Message;

    let mut response = Message::new();
    let mut header = Header::response_from_request(request.header());
    header.set_authoritative(true);
    response.set_header(header);

    // Copy the question
    for q in request.queries() {
        response.add_query(q.clone());
    }

    match qtype {
        RecordType::A => {
            let name = request.queries()[0].name().clone();
            let record = Record::from_rdata(name, 60, RData::A(A(devbox_local_ip())));
            response.add_answer(record);
        }
        RecordType::AAAA => {
            // Return empty response for AAAA (prevent IPv6 bypass)
            // No answer records = NOERROR with empty answer section
        }
        _ => {
            // For other types, return NOERROR with no answers
        }
    }

    response
}

/// Build an NXDOMAIN response.
fn build_nxdomain_response(request: &hickory_proto::op::Message) -> hickory_proto::op::Message {
    use hickory_proto::op::Message;

    let mut response = Message::new();
    let mut header = Header::response_from_request(request.header());
    header.set_response_code(ResponseCode::NXDomain);
    header.set_authoritative(true);
    response.set_header(header);

    for q in request.queries() {
        response.add_query(q.clone());
    }

    response
}

/// Build a SERVFAIL response.
fn build_servfail_response(request: &hickory_proto::op::Message) -> hickory_proto::op::Message {
    use hickory_proto::op::Message;

    let mut response = Message::new();
    let mut header = Header::response_from_request(request.header());
    header.set_response_code(ResponseCode::ServFail);
    response.set_header(header);

    for q in request.queries() {
        response.add_query(q.clone());
    }

    response
}

/// Extract base domain for wildcard matching.
/// e.g., "sub.api.github.com" → "api.github.com" → "github.com"
fn extract_base_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() > 2 {
        parts[parts.len() - 2..].join(".")
    } else {
        domain.to_string()
    }
}
