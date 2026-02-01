#!/bin/bash
set -e

# =============================================================================
# Agent Container Entrypoint
# Starts SSH server and keeps container running
# =============================================================================

USER_NAME="${USER_NAME:-agent}"
USER_HOME="/home/$USER_NAME"

# Setup SSH authorized keys from environment or mounted file
setup_ssh_keys() {
    local auth_keys_file="$USER_HOME/.ssh/authorized_keys"

    # From environment variable
    if [ -n "$SSH_AUTHORIZED_KEYS" ]; then
        echo "Setting up SSH keys from environment..."
        echo "$SSH_AUTHORIZED_KEYS" > "$auth_keys_file"
    fi

    # From mounted file (appends if env keys exist)
    if [ -f "/ssh-keys/authorized_keys" ]; then
        echo "Appending SSH keys from mounted file..."
        cat /ssh-keys/authorized_keys >> "$auth_keys_file"
    fi

    # Set permissions
    if [ -f "$auth_keys_file" ]; then
        chmod 600 "$auth_keys_file"
        chown "$USER_NAME:$USER_NAME" "$auth_keys_file"
        echo "SSH keys configured for user $USER_NAME"
    else
        echo "WARNING: No SSH keys configured. SSH login will fail."
        echo "Set SSH_AUTHORIZED_KEYS env var or mount keys to /ssh-keys/authorized_keys"
    fi
}

# Generate host keys if missing
setup_host_keys() {
    if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
        echo "Generating SSH host keys..."
        ssh-keygen -A
    fi
}

# Main
echo "=== AI Agent Container Starting ==="
echo "Variant: ${VARIANT:-lean}"
echo "User: $USER_NAME"

setup_host_keys
setup_ssh_keys

# Start SSH daemon
echo "Starting SSH server..."
/usr/sbin/sshd

# Keep container running
echo "Agent ready. SSH available on port 22."
exec tail -f /dev/null
