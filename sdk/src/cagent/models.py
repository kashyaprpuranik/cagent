"""Pydantic models mirroring the CP API schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Generic, List, Optional, TypeVar

from pydantic import BaseModel, ConfigDict

T = TypeVar("T")


# -- Security Profiles --


class SecurityProfile(BaseModel):
    """Security profile response from CP API."""

    model_config = ConfigDict(extra="ignore")

    id: int
    tenant_id: int
    name: str
    description: Optional[str] = None
    runtime_policy: str = "hardened"
    pids_limit: Optional[int] = None
    cell_count: int = 0
    policy_count: int = 0
    created_at: datetime
    updated_at: datetime


# -- Profile Export/Import --


class ExportDomainPolicy(BaseModel):
    """Domain policy in a profile export (subset of fields, no IDs)."""

    model_config = ConfigDict(extra="ignore")

    domain: str
    alias: Optional[str] = None
    description: Optional[str] = None
    allowed_paths: Optional[List[str]] = None
    requests_per_minute: Optional[int] = None
    burst_size: Optional[int] = None
    timeout: Optional[str] = None
    read_only: Optional[bool] = None


# Keep backward compat alias
DomainPolicy = ExportDomainPolicy


class EmailPolicy(BaseModel):
    """Email policy in a profile export."""

    model_config = ConfigDict(extra="ignore")

    name: str
    provider: str
    email: str
    imap_server: Optional[str] = None
    imap_port: Optional[int] = None
    smtp_server: Optional[str] = None
    smtp_port: Optional[int] = None
    allowed_recipients: Optional[List[str]] = None
    allowed_senders: Optional[List[str]] = None
    sends_per_hour: Optional[int] = None
    reads_per_hour: Optional[int] = None


class DlpConfig(BaseModel):
    """DLP config in a profile export."""

    model_config = ConfigDict(extra="ignore")

    enabled: bool = False
    mode: str = "log"
    skip_domains: List[str] = []
    custom_patterns: List[dict] = []


class ProfileExportData(BaseModel):
    """Full profile export/import format."""

    model_config = ConfigDict(extra="ignore")

    name: str
    description: Optional[str] = None
    security: dict
    resource_limits: dict
    domain_policies: List[DomainPolicy] = []
    dlp: Optional[DlpConfig] = None
    email_policies: List[EmailPolicy] = []


class ProfileImportResult(BaseModel):
    """Result of a profile import operation."""

    model_config = ConfigDict(extra="ignore")

    profile_id: int
    profile_name: str
    domain_policies_created: int
    email_policies_created: int
    dlp_updated: bool
    profile_updated: bool


# -- Cells --


class Cell(BaseModel):
    """Cell summary from list endpoint."""

    model_config = ConfigDict(extra="ignore")

    cell_id: str
    status: str
    online: bool
    tenant_id: Optional[int] = None
    last_heartbeat: Optional[datetime] = None
    security_profile_name: Optional[str] = None


class CellStatus(BaseModel):
    """Detailed cell status."""

    model_config = ConfigDict(extra="ignore")

    cell_id: str
    status: str
    container_id: Optional[str] = None
    uptime_seconds: Optional[int] = None
    cpu_percent: Optional[int] = None
    memory_mb: Optional[int] = None
    memory_limit_mb: Optional[int] = None
    last_heartbeat: Optional[datetime] = None
    pending_command: Optional[str] = None
    last_command: Optional[str] = None
    last_command_result: Optional[str] = None
    last_command_at: Optional[datetime] = None
    online: bool = False
    runtime_policy: Optional[str] = None
    security_profile_id: Optional[int] = None
    security_profile_name: Optional[str] = None
    public_ip: Optional[str] = None


# -- Community Profiles --


class CommunityProfile(BaseModel):
    """Community profile metadata from the manifest."""

    model_config = ConfigDict(extra="ignore")

    file: str
    name: str
    description: str
    icon: str = ""
    domains: int = 0
    tags: List[str] = []


# -- Pagination --


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated API response."""

    model_config = ConfigDict(extra="ignore")

    items: List[T]
    total: int
    limit: int
    offset: int


# -- Domain Policies (full API response) --


class DomainPolicyResponse(BaseModel):
    """Full domain policy response from the CP API."""

    model_config = ConfigDict(extra="ignore")

    id: int
    tenant_id: Optional[int] = None
    domain: str
    alias: Optional[str] = None
    description: Optional[str] = None
    enabled: bool = True
    profile_id: int = 0
    allowed_paths: List[str] = []
    requests_per_minute: Optional[int] = None
    burst_size: Optional[int] = None
    timeout: Optional[str] = None
    read_only: Optional[bool] = None
    expires_at: Optional[datetime] = None
    has_credential: bool = False
    credential_header: Optional[str] = None
    credential_format: Optional[str] = None
    credential_rotated_at: Optional[datetime] = None
    created_at: datetime = datetime.min
    updated_at: datetime = datetime.min


# -- DLP Policies (full API response) --


class DlpPolicyResponse(BaseModel):
    """DLP policy response from the CP API."""

    model_config = ConfigDict(extra="ignore")

    id: int
    tenant_id: Optional[int] = None
    profile_id: int = 0
    enabled: bool = False
    mode: str = "log"
    skip_domains: list = []
    custom_patterns: list = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


# -- Auth --


class AuthInfo(BaseModel):
    """Response from /auth/me."""

    model_config = ConfigDict(extra="ignore")

    token_type: str = ""
    cell_id: Optional[str] = None
    tenant_id: Optional[int] = None
    tenant_name: Optional[str] = None
    tenant_slug: Optional[str] = None
    is_super_admin: bool = False
    role: Optional[str] = None
    plan: str = "free"
    onboarding_complete: bool = False
    max_agent_tokens: int = 1
    hosting_mode: Optional[str] = None
    multi_user: bool = False
    user: Optional[dict] = None


# -- Logs / Audit Trail --


class AuditEntry(BaseModel):
    """Audit trail entry."""

    model_config = ConfigDict(extra="ignore")

    id: int
    tenant_id: Optional[int] = None
    event_type: str = ""
    action: str = ""
    user: Optional[str] = None
    severity: str = "INFO"
    details: Optional[str] = None
    container_id: Optional[str] = None
    timestamp: Optional[datetime] = None
