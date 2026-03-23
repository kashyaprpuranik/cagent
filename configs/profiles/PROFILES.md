# Community Profiles

Ready-to-use security profiles for common AI agent use cases. Import any profile
directly into cagent from the Profiles page using the Import button.

## Available Profiles

| Profile | Description | Domains | DLP | Security |
|---------|-------------|---------|-----|----------|
| [claw-default](claw_profile.json) | LLM providers, GitHub, registries, messaging | 42 | block | hardened |
| [research-agent](research-agent.json) | arxiv, Scholar, HuggingFace, Semantic Scholar | 8 | block | hardened |
| [code-review](code-review.json) | GitHub, GitLab, package registries | 9 | block | hardened |
| [customer-support](customer-support.json) | Zendesk, Intercom, Freshdesk, Slack | 5 | block | hardened |
| [data-pipeline](data-pipeline.json) | Cloud storage, databases, data warehouses | 8 | log | standard |
| [web-browsing](web-browsing.json) | Search engines, scraping, browsing | 8 | block | hardened |
| [devops](devops.json) | Cloud providers, monitoring, CI/CD | 8 | block | standard |
| [minimal](minimal.json) | No domains — locked-down baseline | 0 | block | hardened |

## How to Use

1. Go to **Profiles** in the cagent control plane
2. Click the **Import** button on any profile
3. Choose **Community Profiles** and select one, or paste the raw URL
4. Click **Import** — all policies are applied instantly

## Contributing

Add a new profile by creating a JSON file in this directory and submitting a PR.

### Required format

```json
{
  "name": "my-profile",
  "description": "Short description of what this profile is for",
  "security": {
    "runtime_policy": "hardened"
  },
  "resource_limits": {
    "cpu_limit": 1.0,
    "memory_limit_mb": 2048,
    "pids_limit": 128
  },
  "domain_policies": [
    {
      "domain": "api.example.com",
      "description": "Example API",
      "requests_per_minute": 60,
      "burst_size": 10
    }
  ],
  "dlp": {
    "enabled": true,
    "mode": "block",
    "skip_domains": [],
    "custom_patterns": []
  },
  "email_policies": []
}
```

### Guidelines

- Use lowercase, hyphenated names (e.g., `my-profile.json`)
- Include a clear description
- Set DLP to `block` mode unless the use case requires data movement
- Use `hardened` security unless the agent needs elevated privileges
- Set `read_only: true` on domains that don't need write access
- Never include credentials in profile files
- Update `profiles-manifest.json` with your new entry
