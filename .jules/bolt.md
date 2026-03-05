## 2024-05-24 - File Parsing Bottleneck

**Learning:** Parsing YAML configuration files (like `cagent.yaml`) repeatedly without checking file modification time can be a significant performance bottleneck due to continuous file I/O and text parsing. Caching the parsed dictionary and using `st_mtime` for invalidation significantly improves performance while avoiding circular dependency issues.
**Action:** Always consider using file modification time (`mtime`) to cache the parsed output of configuration files when they are frequently accessed and infrequently updated.
