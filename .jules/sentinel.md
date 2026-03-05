## 2024-03-05 - Fix timing attack in token verification
**Vulnerability:** The `verify_warden_token` function used the `!=` operator to compare the provided `Authorization` token against the `WARDEN_API_TOKEN`. This allows an attacker to guess the token character by character via timing attacks.
**Learning:** String comparison with `==` or `!=` terminates early on the first character difference, exposing execution time differences based on token similarity. This is especially risky when authenticating programmatic APIs.
**Prevention:** Always use `secrets.compare_digest()` for comparing security tokens or passwords, as it executes in constant time regardless of string similarity.
