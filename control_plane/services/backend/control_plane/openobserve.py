"""OpenObserve client for multi-tenant org provisioning, auth selection, and URL building."""

import json
import secrets
from typing import Optional, Tuple

import httpx

from control_plane.config import (
    logger,
    OPENOBSERVE_URL,
    OPENOBSERVE_USER,
    OPENOBSERVE_PASSWORD,
    OPENOBSERVE_ROOT_USER,
    OPENOBSERVE_ROOT_PASSWORD,
    OPENOBSERVE_MULTI_TENANT,
)
from control_plane.crypto import encrypt_secret, decrypt_secret


def _generate_password() -> str:
    return secrets.token_urlsafe(24)


async def provision_tenant_org(slug: str) -> Tuple[str, str, str, str]:
    """Create writer + reader users in an OpenObserve org (org created implicitly).

    Returns (writer_email, writer_pw, reader_email, reader_pw).
    """
    writer_email = f"writer@{slug}.cagent"
    writer_pw = _generate_password()
    reader_email = f"reader@{slug}.cagent"
    reader_pw = _generate_password()

    async with httpx.AsyncClient() as client:
        for email, pw, role in [
            (writer_email, writer_pw, "admin"),
            (reader_email, reader_pw, "admin"),
        ]:
            resp = await client.post(
                f"{OPENOBSERVE_URL}/api/{slug}/users",
                json={
                    "email": email,
                    "password": pw,
                    "role": role,
                    "first_name": slug,
                    "last_name": role,
                },
                auth=(OPENOBSERVE_ROOT_USER, OPENOBSERVE_ROOT_PASSWORD),
                timeout=10.0,
            )
            if resp.status_code not in (200, 201):
                raise RuntimeError(
                    f"Failed to create OpenObserve user {email} in org {slug}: "
                    f"{resp.status_code} {resp.text}"
                )

    logger.info(f"Provisioned OpenObserve org '{slug}' with writer + reader users")
    return writer_email, writer_pw, reader_email, reader_pw


async def delete_tenant_org(slug: str) -> None:
    """Best-effort deletion of writer/reader users from an OpenObserve org."""
    async with httpx.AsyncClient() as client:
        for email in [f"writer@{slug}.cagent", f"reader@{slug}.cagent"]:
            try:
                resp = await client.delete(
                    f"{OPENOBSERVE_URL}/api/{slug}/users/{email}",
                    auth=(OPENOBSERVE_ROOT_USER, OPENOBSERVE_ROOT_PASSWORD),
                    timeout=10.0,
                )
                if resp.status_code not in (200, 204):
                    logger.warning(
                        f"Failed to delete OpenObserve user {email}: "
                        f"{resp.status_code} {resp.text}"
                    )
            except Exception as e:
                logger.warning(f"Error deleting OpenObserve user {email}: {e}")


def get_ingest_auth(tenant_settings: Optional[dict]) -> Tuple[str, str]:
    """Return (email, password) for ingestion.

    Uses per-tenant writer credentials when available, else falls back to legacy.
    """
    if OPENOBSERVE_MULTI_TENANT and tenant_settings:
        writer_email = tenant_settings.get("openobserve_writer_email")
        writer_pw = tenant_settings.get("openobserve_writer_password")
        if writer_email and writer_pw:
            return writer_email, decrypt_secret(writer_pw)
    return OPENOBSERVE_USER, OPENOBSERVE_PASSWORD


def get_query_auth(tenant_settings: Optional[dict]) -> Tuple[str, str]:
    """Return (email, password) for queries.

    Uses per-tenant reader credentials when available, else falls back to legacy.
    """
    if OPENOBSERVE_MULTI_TENANT and tenant_settings:
        reader_email = tenant_settings.get("openobserve_reader_email")
        reader_pw = tenant_settings.get("openobserve_reader_password")
        if reader_email and reader_pw:
            return reader_email, decrypt_secret(reader_pw)
    return OPENOBSERVE_USER, OPENOBSERVE_PASSWORD


def get_ingest_url(tenant_slug: str, stream: str) -> str:
    """Build ingest URL — per-tenant org + per-source stream, or legacy default."""
    if OPENOBSERVE_MULTI_TENANT:
        return f"{OPENOBSERVE_URL}/api/{tenant_slug}/{stream}/_json"
    return f"{OPENOBSERVE_URL}/api/default/default/_json"


def get_query_url(tenant_slug: str) -> str:
    """Build query URL — per-tenant org, or legacy default."""
    if OPENOBSERVE_MULTI_TENANT:
        return f"{OPENOBSERVE_URL}/api/{tenant_slug}/_search"
    return f"{OPENOBSERVE_URL}/api/default/_search"


def get_tenant_settings(tenant) -> Optional[dict]:
    """Parse tenant.settings JSON. Returns None if empty."""
    if not tenant.settings:
        return None
    try:
        return json.loads(tenant.settings)
    except (json.JSONDecodeError, TypeError):
        logger.warning(f"Invalid tenant settings JSON for tenant {tenant.id}")
        return None


def set_tenant_settings(tenant, settings: dict, db) -> None:
    """Serialize settings dict to tenant.settings and commit."""
    tenant.settings = json.dumps(settings)
    db.add(tenant)
    db.commit()


def store_org_credentials(
    tenant, db,
    writer_email: str, writer_pw: str,
    reader_email: str, reader_pw: str,
) -> None:
    """Store OpenObserve org credentials in tenant.settings (passwords encrypted)."""
    settings = get_tenant_settings(tenant) or {}
    settings.update({
        "openobserve_org": tenant.slug,
        "openobserve_writer_email": writer_email,
        "openobserve_writer_password": encrypt_secret(writer_pw),
        "openobserve_reader_email": reader_email,
        "openobserve_reader_password": encrypt_secret(reader_pw),
    })
    set_tenant_settings(tenant, settings, db)
