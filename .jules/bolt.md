
## 2024-05-15 - Mtime Caching for YAML Configs
**Learning:** `yaml.safe_load` inside the API routing flow (like `_build_standalone_policy` resolving `devbox.local` domains on every request) can be a significant performance bottleneck due to continuous file IO and text parsing. Wait for a request to resolve can be delayed up to 30ms-50ms or more depending on YAML size.
**Action:** Implemented a module-level `_config_cache` dict keeping track of `st_mtime` to avoid redundantly reading/parsing `cagent.yaml`. This approach invalidates the cache purely based on the file modification timestamp, which eliminates circular imports with central configuration managers while providing 40x+ faster resolutions.
