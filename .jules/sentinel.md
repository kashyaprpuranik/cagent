## 2024-03-03 - [Fix timing attack vulnerability in token validation]
**Vulnerability:** String comparison `auth[7:] != WARDEN_API_TOKEN` allowed potential timing attacks against the API token in `verify_warden_token`.
**Learning:** Even internal security-critical tokens should be compared using constant-time comparison methods, not simple equality or inequality.
**Prevention:** Use `secrets.compare_digest` in Python for checking secrets against incoming values to neutralize timing vulnerabilities.
