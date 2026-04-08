# cagent-mcp-server

MCP server for managing [Cagent](https://github.com/kashyaprpuranik/cagent) secure sandboxes from Claude Code and other MCP-compatible clients.

Uses the [cagent Python SDK](../sdk/) for API communication.

## Setup

```bash
pip install cagent-mcp-server
```

## Configuration

Add to your Claude Code MCP settings:

```json
{
  "mcpServers": {
    "cagent": {
      "command": "cagent-mcp",
      "env": {
        "CAGENT_API_URL": "https://app.cagent-control.com",
        "CAGENT_API_TOKEN": "your-api-token"
      }
    }
  }
}
```

## Available Tools

| Tool | Description |
|------|-------------|
| `create_sandbox` | Create a new secure sandbox |
| `list_sandboxes` | List sandboxes with filters (status, online) |
| `get_sandbox_status` | Get detailed status and metrics |
| `delete_sandbox` | Delete a sandbox and clean up infra |
| `start_sandbox` | Start a stopped sandbox |
| `stop_sandbox` | Stop a running sandbox |
| `restart_sandbox` | Restart a sandbox |
| `list_domain_policies` | List allowed egress domains |
| `add_domain_policy` | Allow a new domain for egress |
| `delete_domain_policy` | Remove a domain from the allowlist |
| `get_audit_log` | Query the audit trail |
