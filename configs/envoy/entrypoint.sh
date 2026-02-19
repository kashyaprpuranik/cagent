#!/bin/sh
# Envoy entrypoint - ensures config exists before starting

CONFIG_PATH="/etc/envoy/envoy.yaml"
DEFAULT_PATH="/etc/envoy/envoy.default.yaml"

# If generated config doesn't exist, copy the default
if [ ! -f "$CONFIG_PATH" ]; then
    echo "No generated config found, using default..."
    if [ -f "$DEFAULT_PATH" ]; then
        cp "$DEFAULT_PATH" "$CONFIG_PATH"
        echo "Copied default config to $CONFIG_PATH"
    else
        echo "ERROR: No config available at $CONFIG_PATH or $DEFAULT_PATH"
        exit 1
    fi
fi

echo "Starting Envoy with config: $CONFIG_PATH"
exec /usr/local/bin/envoy -c "$CONFIG_PATH" "$@"
