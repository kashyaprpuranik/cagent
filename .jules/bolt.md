
## 2024-05-28 - [Performance] Cache parsed YAML files using `st_mtime`
**Learning:** Parsing YAML configuration files repeatedly without checking file modification time creates a significant performance bottleneck due to continuous file I/O and text parsing, especially in high-frequency endpoints like ext_authz checks.
**Action:** Use an in-memory dictionary cache paired with `Path(file).stat().st_mtime` to invalidate the cache. This eliminates continuous synchronous IO and text parsing but reacts instantly to configuration changes without introducing circular dependency issues.
