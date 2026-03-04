## 2026-03-04 - Cached cagent.yaml config based on file mtime
**Learning:** Parsing YAML configuration files (like `cagent.yaml`) repeatedly without checking file modification time can be a significant performance bottleneck due to continuous file I/O and text parsing.
**Action:** Caching the parsed dictionary and using `st_mtime` for invalidation significantly improves performance while avoiding circular dependency issues.
