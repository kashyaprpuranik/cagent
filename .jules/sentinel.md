## 2024-05-30 - Prevent Timing Attacks on Token Verification
**Vulnerability:** A standard string equality check (`!=`) was used to compare the provided bearer token (`auth[7:]`) against `WARDEN_API_TOKEN` in `warden_auth.py`.
**Learning:** Standard string comparisons in Python return early on the first mismatched character. This allows attackers to deduce the token character-by-character based on minute differences in response times, known as a timing attack.
**Prevention:** Always use `secrets.compare_digest()` for comparing sensitive tokens, hashes, or passwords. It performs comparison in constant time regardless of where the mismatch occurs.
