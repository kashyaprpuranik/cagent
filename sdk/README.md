# cagent

Python SDK for the [Cagent](https://cagent.app) Control Plane API — secure sandboxes for AI agents.

## Installation

```bash
pip install cagent
```

## Quick Start

```python
from cagent import CagentClient

# Initialize with your API token (or set CAGENT_API_TOKEN env var)
client = CagentClient(api_token="cag_...")

# List your security profiles
profiles = client.profiles.list()
for p in profiles.items:
    print(f"{p.name} ({p.policy_count} policies, {p.cell_count} cells)")

# Apply a community profile (e.g. for a research agent)
result = client.profiles.apply("research-agent")
print(f"Imported {result.domain_policies_created} domain policies")

# List your cells
cells = client.cells.list()
for c in cells.items:
    print(f"{c.cell_id}: {c.status} (online={c.online})")

# Get detailed cell status
status = client.cells.get("my-cell-id")
print(f"CPU: {status.cpu_percent}%, Memory: {status.memory_mb}MB")
```

## Async Usage

```python
from cagent.async_client import AsyncCagentClient

async with AsyncCagentClient(api_token="cag_...") as client:
    profiles = await client.profiles.list()
    cells = await client.cells.list()
```

## Community Profiles

Browse and apply pre-configured security profiles for common agent types:

```python
# List available community profiles
for p in client.profiles.list_community():
    print(f"{p.name}: {p.description} ({p.domains} domains)")

# Apply one to your default profile
client.profiles.apply("research-agent")

# Or apply from any URL
client.profiles.apply_url("https://example.com/my-profile.json")
```

Available profiles: `claw-default`, `research-agent`, `code-review`, `customer-support`, `data-pipeline`, `web-browsing`, `devops`, `minimal`.

## API Reference

### Profiles

| Method | Description |
|--------|-------------|
| `client.profiles.list()` | List security profiles |
| `client.profiles.get(id)` | Get a profile |
| `client.profiles.create(name=...)` | Create a profile |
| `client.profiles.update(id, ...)` | Update a profile |
| `client.profiles.delete(id)` | Delete a profile |
| `client.profiles.export(id)` | Export profile config (JSON) |
| `client.profiles.import_data(id, data)` | Import profile config |
| `client.profiles.list_community()` | List community profiles |
| `client.profiles.apply(name)` | Apply a community profile |
| `client.profiles.apply_url(url)` | Apply profile from URL |

### Cells

| Method | Description |
|--------|-------------|
| `client.cells.list()` | List cells |
| `client.cells.get(cell_id)` | Get cell status |
| `client.cells.wipe(cell_id)` | Wipe a cell |
| `client.cells.restart(cell_id)` | Restart a cell |
| `client.cells.stop(cell_id)` | Stop a cell |
| `client.cells.start(cell_id)` | Start a cell |
| `client.cells.assign_profile(cell_id, profile_id)` | Assign profile |
| `client.cells.unassign_profile(cell_id)` | Unassign profile |

## License

MIT
