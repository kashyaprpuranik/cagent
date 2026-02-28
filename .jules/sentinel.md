## 2024-05-22 - Unrestricted Container Log Access
**Vulnerability:** IDOR in log endpoints allowing access to any container on the host.
**Learning:** `docker_client.containers.get(name)` accepts any container name/ID, not just those managed by the application.
**Prevention:** Always validate user-supplied resource identifiers against a whitelist of allowed resources before accessing them.

## 2025-02-14 - Dependency Availability in Agent Environment

**Vulnerability:** The `docker` python package is not installed in the agent environment, which prevented running a reproduction script that relied on `docker.from_env()`. This is not a security vulnerability in the application code itself, but a limitation in the agent's ability to execute certain reproduction steps.

**Learning:** When creating reproduction scripts or tools, always check for the availability of necessary dependencies in the current environment using `pip list` or similar commands. Do not assume standard packages are present.

**Prevention:** Before running scripts that depend on external libraries, verify their presence. If missing, either install them (if permitted) or adapt the approach to use available tools (e.g., `subprocess` instead of `docker-py`).

## 2025-02-14 - Timing Attack in Token Comparison

**Vulnerability:** The API token verification in `services/warden/warden_auth.py` used string comparison (`!=`) instead of a constant-time comparison, making it vulnerable to timing attacks where an attacker could theoretically guess the token byte-by-byte.

**Learning:** Direct string comparison operations short-circuit and exit early when encountering the first mismatching character. This causes a measurable difference in processing time that correlates with the length of the correctly matched prefix.

**Prevention:** Always use `secrets.compare_digest(a, b)` for comparing secrets, API keys, passwords, and tokens.
