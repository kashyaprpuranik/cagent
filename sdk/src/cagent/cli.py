"""Cagent CLI — manage secure sandboxes from the terminal."""

from __future__ import annotations

import functools
import json
from typing import Callable, Optional

import typer

from cagent.client import CagentClient
from cagent.exceptions import ApiError, CagentError

app = typer.Typer(help="Cagent — secure sandboxes for AI agents", no_args_is_help=True)
profile_app = typer.Typer(help="Manage security profiles", no_args_is_help=True)
cell_app = typer.Typer(help="Manage cells (sandboxes)", no_args_is_help=True)
domain_app = typer.Typer(help="Manage domain policies", no_args_is_help=True)

app.add_typer(profile_app, name="profile")
app.add_typer(cell_app, name="cell")
app.add_typer(domain_app, name="domain")


def _client(base_url: Optional[str] = None) -> CagentClient:
    kwargs = {}
    if base_url:
        kwargs["base_url"] = base_url
    return CagentClient(**kwargs)


def _die(msg: str) -> None:
    typer.echo(f"Error: {msg}", err=True)
    raise typer.Exit(1)


def handle_errors(fn: Callable) -> Callable:
    """Decorator that catches CagentError and exits with a friendly message."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except CagentError as e:
            _die(str(e))

    return wrapper


# -- Profile commands --


@profile_app.command("list")
@handle_errors
def profile_list(
    base_url: Optional[str] = typer.Option(None, "--api-url", envvar="CAGENT_API_URL", help="CP API URL"),
):
    """List your security profiles."""
    with _client(base_url) as c:
        result = c.profiles.list()
    for p in result.items:
        typer.echo(f"  {p.id:>4}  {p.name:<30} {p.description or ''}")
    typer.echo(f"\n{result.total} profile(s)")


@profile_app.command("show")
@handle_errors
def profile_show(
    name_or_id: str = typer.Argument(help="Profile name or ID"),
    base_url: Optional[str] = typer.Option(None, "--api-url", envvar="CAGENT_API_URL"),
):
    """Show details for a security profile."""
    with _client(base_url) as c:
        # Try as int (ID) first, then search by name
        try:
            profile = c.profiles.get(int(name_or_id))
        except (ValueError, ApiError):
            # Paginate through all profiles to find by name
            profile = None
            offset = 0
            while True:
                page = c.profiles.list(limit=100, offset=offset)
                for p in page.items:
                    if p.name == name_or_id:
                        profile = p
                        break
                if profile or offset + len(page.items) >= page.total:
                    break
                offset += len(page.items)
            if not profile:
                _die(f"Profile '{name_or_id}' not found")
    typer.echo(json.dumps(profile.model_dump(), indent=2, default=str))


@profile_app.command("community")
@handle_errors
def profile_community():
    """List available community profiles."""
    with _client() as c:
        profiles = c.profiles.list_community()
    for p in profiles:
        tags = ", ".join(p.tags) if p.tags else ""
        typer.echo(f"  {p.icon} {p.name:<25} {p.description:<50} [{tags}]")
    typer.echo(f"\n{len(profiles)} community profile(s)")


@profile_app.command("apply")
@handle_errors
def profile_apply(
    name: str = typer.Argument(help="Community profile name (e.g. 'research-agent')"),
    profile_id: Optional[int] = typer.Option(None, "--profile-id", "-p", help="Target profile ID (default: your default profile)"),
    url: Optional[str] = typer.Option(None, "--url", help="Apply from URL instead of community name"),
    base_url: Optional[str] = typer.Option(None, "--api-url", envvar="CAGENT_API_URL"),
):
    """Apply a community profile to your sandbox."""
    with _client(base_url) as c:
        if url:
            result = c.profiles.apply_url(url, profile_id=profile_id)
        else:
            result = c.profiles.apply(name, profile_id=profile_id)
    typer.echo(f"Applied to profile '{result.profile_name}' (id={result.profile_id})")
    typer.echo(f"  domain policies created: {result.domain_policies_created}")
    typer.echo(f"  email policies created:  {result.email_policies_created}")
    typer.echo(f"  DLP updated:             {result.dlp_updated}")


@profile_app.command("export")
@handle_errors
def profile_export(
    profile_id: int = typer.Argument(help="Profile ID to export"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file (default: stdout)"),
    base_url: Optional[str] = typer.Option(None, "--api-url", envvar="CAGENT_API_URL"),
):
    """Export a profile as JSON."""
    with _client(base_url) as c:
        data = c.profiles.export(profile_id)
    text = json.dumps(data.model_dump(), indent=2, default=str)
    if output:
        try:
            with open(output, "w") as f:
                f.write(text)
        except OSError as e:
            _die(f"Failed to write to {output}: {e}")
        typer.echo(f"Exported to {output}")
    else:
        typer.echo(text)


# -- Cell commands --


@cell_app.command("list")
@handle_errors
def cell_list(
    base_url: Optional[str] = typer.Option(None, "--api-url", envvar="CAGENT_API_URL"),
):
    """List your cells (sandboxes)."""
    with _client(base_url) as c:
        result = c.cells.list()
    if not result.items:
        typer.echo("No cells found.")
        return
    for cell in result.items:
        status_icon = "●" if cell.online else "○"
        profile = cell.security_profile_name or "-"
        typer.echo(f"  {status_icon} {cell.cell_id:<30} {cell.status:<14} {profile}")
    typer.echo(f"\n{result.total} cell(s)")


@cell_app.command("status")
@handle_errors
def cell_status(
    cell_id: str = typer.Argument(help="Cell ID"),
    base_url: Optional[str] = typer.Option(None, "--api-url", envvar="CAGENT_API_URL"),
):
    """Get detailed status for a cell."""
    with _client(base_url) as c:
        status = c.cells.get(cell_id)
    typer.echo(json.dumps(status.model_dump(), indent=2, default=str))


@cell_app.command("stop")
@handle_errors
def cell_stop(
    cell_id: str = typer.Argument(help="Cell ID"),
    base_url: Optional[str] = typer.Option(None, "--api-url", envvar="CAGENT_API_URL"),
):
    """Stop a running cell."""
    with _client(base_url) as c:
        c.cells.stop(cell_id)
    typer.echo(f"Stop command sent to {cell_id}")


@cell_app.command("start")
@handle_errors
def cell_start(
    cell_id: str = typer.Argument(help="Cell ID"),
    base_url: Optional[str] = typer.Option(None, "--api-url", envvar="CAGENT_API_URL"),
):
    """Start a stopped cell."""
    with _client(base_url) as c:
        c.cells.start(cell_id)
    typer.echo(f"Start command sent to {cell_id}")


@cell_app.command("restart")
@handle_errors
def cell_restart(
    cell_id: str = typer.Argument(help="Cell ID"),
    base_url: Optional[str] = typer.Option(None, "--api-url", envvar="CAGENT_API_URL"),
):
    """Restart a cell."""
    with _client(base_url) as c:
        c.cells.restart(cell_id)
    typer.echo(f"Restart command sent to {cell_id}")


@cell_app.command("wipe")
@handle_errors
def cell_wipe(
    cell_id: str = typer.Argument(help="Cell ID"),
    workspace: bool = typer.Option(False, "--workspace", "-w", help="Also wipe workspace"),
    base_url: Optional[str] = typer.Option(None, "--api-url", envvar="CAGENT_API_URL"),
):
    """Wipe a cell (reset to clean state)."""
    with _client(base_url) as c:
        c.cells.wipe(cell_id, workspace=workspace)
    msg = "Wipe (with workspace)" if workspace else "Wipe"
    typer.echo(f"{msg} command sent to {cell_id}")


# -- Domain commands --


@domain_app.command("list")
@handle_errors
def domain_list(
    base_url: Optional[str] = typer.Option(None, "--api-url", envvar="CAGENT_API_URL"),
):
    """List allowed domains."""
    with _client(base_url) as c:
        result = c.domain_policies.list()
    if not result.items:
        typer.echo("No domain policies found.")
        return
    for d in result.items:
        enabled = "✓" if d.enabled else "✗"
        rpm = f"{d.requests_per_minute} rpm" if d.requests_per_minute else "-"
        cred = "🔑" if d.has_credential else "  "
        typer.echo(f"  {enabled} {d.id:>4}  {d.domain:<40} {rpm:<12} {cred} {d.alias or ''}")
    typer.echo(f"\n{result.total} domain policy(ies)")


@domain_app.command("add")
@handle_errors
def domain_add(
    domain: str = typer.Argument(help="Domain to allow (e.g. 'api.openai.com')"),
    description: Optional[str] = typer.Option(None, "--description", "-d"),
    rpm: Optional[int] = typer.Option(None, "--rpm", help="Requests per minute limit"),
    base_url: Optional[str] = typer.Option(None, "--api-url", envvar="CAGENT_API_URL"),
):
    """Allow a domain for egress traffic."""
    with _client(base_url) as c:
        result = c.domain_policies.create(
            domain=domain,
            description=description,
            requests_per_minute=rpm,
        )
    typer.echo(f"Added domain policy: {result.domain} (id={result.id})")


@domain_app.command("remove")
@handle_errors
def domain_remove(
    policy_id: int = typer.Argument(help="Domain policy ID to remove"),
    base_url: Optional[str] = typer.Option(None, "--api-url", envvar="CAGENT_API_URL"),
):
    """Remove a domain from the allowlist."""
    with _client(base_url) as c:
        c.domain_policies.delete(policy_id)
    typer.echo(f"Removed domain policy {policy_id}")


def main():
    app()


if __name__ == "__main__":
    main()
