# =============================================================================
# HashiCorp Vault Configuration
# Secrets management for AI Devbox
# =============================================================================

# Storage backend - using file for simplicity, use Consul/etcd for production
storage "file" {
  path = "/vault/data"
}

# Listener configuration
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true  # Enable TLS in production!
}

# API address
api_addr = "http://vault:8200"
cluster_addr = "http://vault:8201"

# UI
ui = true

# Logging
log_level = "info"
log_format = "json"

# Disable memory locking (for Docker)
disable_mlock = true

# Telemetry
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname          = true
}
