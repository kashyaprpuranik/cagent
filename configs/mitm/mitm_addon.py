"""
mitmproxy addon: route decrypted HTTPS through Envoy as plain HTTP.

After mitmproxy terminates TLS from the cell, this addon:
1. Saves the original Host header (the real destination domain)
2. Changes the scheme from https to http
3. Redirects the connection to Envoy (10.200.1.10:8443)
4. Restores the original Host header so Envoy matches the correct virtual host

Envoy sees a plain HTTP forward proxy request and applies all security controls
(domain allowlist, rate limiting, credential injection, path filtering), then
upgrades back to HTTPS when forwarding to the real upstream server.

Used with --mode regular (not upstream) to avoid CONNECT tunnel to Envoy.
"""

from mitmproxy import http

ENVOY_HOST = "10.200.1.10"
ENVOY_PORT = 8443


def request(flow: http.HTTPFlow) -> None:
    # Save original host before we redirect
    original_host = flow.request.pretty_host
    flow.request.scheme = "http"
    flow.request.host = ENVOY_HOST
    flow.request.port = ENVOY_PORT
    # Restore original Host header so Envoy matches the domain virtual host
    flow.request.headers["Host"] = original_host
