"""Tests for Security Profiles: tenant-scoped policy bundles."""

import pytest


# =============================================================================
# Helpers
# =============================================================================

def _create_profile(client, headers, name="test-profile", **overrides):
    """Helper to create a security profile."""
    body = {"name": name, **overrides}
    resp = client.post("/api/v1/security-profiles", json=body, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _create_agent(db_session, agent_id, tenant_id):
    """Helper to create an agent state record."""
    from control_plane.models import AgentState
    from datetime import datetime, timezone
    agent = AgentState(
        agent_id=agent_id,
        tenant_id=tenant_id,
        status="running",
        approved=True,
        last_heartbeat=datetime.now(timezone.utc),
    )
    db_session.add(agent)
    db_session.commit()
    db_session.refresh(agent)
    return agent


def _create_agent_token(db_session, agent_id, tenant_id, token_value):
    """Helper to create an agent API token."""
    from control_plane.models import ApiToken
    from control_plane.crypto import hash_token
    token = ApiToken(
        name=f"token-{agent_id}",
        token_hash=hash_token(token_value),
        token_type="agent",
        agent_id=agent_id,
        tenant_id=tenant_id,
        enabled=True,
    )
    db_session.add(token)
    db_session.commit()
    return token


def _get_default_tenant_id(db_session):
    """Get the ID of the default tenant."""
    from control_plane.models import Tenant
    tenant = db_session.query(Tenant).filter(Tenant.slug == "default").first()
    return tenant.id


def _get_acme_tenant_id(db_session):
    """Get the ID of the Acme Corp tenant."""
    from control_plane.models import Tenant
    tenant = db_session.query(Tenant).filter(Tenant.slug == "acme").first()
    return tenant.id


# =============================================================================
# CRUD Tests
# =============================================================================

class TestSecurityProfileCRUD:
    def test_create_profile(self, client, auth_headers):
        profile = _create_profile(client, auth_headers, name="my-profile", description="Test profile")
        assert profile["name"] == "my-profile"
        assert profile["description"] == "Test profile"
        assert profile["seccomp_profile"] == "standard"
        assert profile["agent_count"] == 0
        assert profile["policy_count"] == 0

    def test_list_profiles(self, client, auth_headers):
        _create_profile(client, auth_headers, name="profile-a")
        _create_profile(client, auth_headers, name="profile-b")
        resp = client.get("/api/v1/security-profiles", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        names = [p["name"] for p in data["items"]]
        assert "profile-a" in names
        assert "profile-b" in names

    def test_get_profile(self, client, auth_headers):
        created = _create_profile(client, auth_headers, name="get-me")
        resp = client.get(f"/api/v1/security-profiles/{created['id']}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["name"] == "get-me"

    def test_update_profile(self, client, auth_headers):
        created = _create_profile(client, auth_headers, name="update-me")
        resp = client.put(
            f"/api/v1/security-profiles/{created['id']}",
            json={"name": "updated-name", "seccomp_profile": "hardened"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "updated-name"
        assert data["seccomp_profile"] == "hardened"

    def test_delete_profile(self, client, auth_headers):
        created = _create_profile(client, auth_headers, name="delete-me")
        resp = client.delete(f"/api/v1/security-profiles/{created['id']}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True

        # Verify it's gone
        resp = client.get(f"/api/v1/security-profiles/{created['id']}", headers=auth_headers)
        assert resp.status_code == 404

    def test_duplicate_name_rejected(self, client, auth_headers):
        _create_profile(client, auth_headers, name="unique-name")
        resp = client.post("/api/v1/security-profiles", json={"name": "unique-name"}, headers=auth_headers)
        assert resp.status_code == 400
        assert "already exists" in resp.json()["detail"]

    def test_update_duplicate_name_rejected(self, client, auth_headers):
        _create_profile(client, auth_headers, name="name-a")
        b = _create_profile(client, auth_headers, name="name-b")
        resp = client.put(
            f"/api/v1/security-profiles/{b['id']}",
            json={"name": "name-a"},
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert "already exists" in resp.json()["detail"]

    def test_pagination(self, client, auth_headers):
        for i in range(5):
            _create_profile(client, auth_headers, name=f"page-{i}")
        resp = client.get("/api/v1/security-profiles?limit=2&offset=0", headers=auth_headers)
        data = resp.json()
        assert data["total"] == 5
        assert len(data["items"]) == 2
        assert data["limit"] == 2
        assert data["offset"] == 0

    def test_get_nonexistent_profile(self, client, auth_headers):
        resp = client.get("/api/v1/security-profiles/99999", headers=auth_headers)
        assert resp.status_code == 404

    def test_create_with_seccomp(self, client, auth_headers):
        profile = _create_profile(client, auth_headers, name="hardened-profile", seccomp_profile="hardened")
        assert profile["seccomp_profile"] == "hardened"


# =============================================================================
# Default Profile Tests
# =============================================================================

class TestSecurityProfileDefaults:
    def test_cannot_delete_default_profile(self, client, auth_headers):
        """Profile named 'default' cannot be deleted."""
        profile = _create_profile(client, auth_headers, name="default")
        resp = client.delete(f"/api/v1/security-profiles/{profile['id']}", headers=auth_headers)
        assert resp.status_code == 400
        assert "default" in resp.json()["detail"].lower()

    def test_can_delete_non_default_profile(self, client, auth_headers):
        """Non-default profiles can be deleted normally."""
        profile = _create_profile(client, auth_headers, name="deletable")
        resp = client.delete(f"/api/v1/security-profiles/{profile['id']}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True


# =============================================================================
# Agent Profile Assignment Tests
# =============================================================================

class TestAgentProfileAssignment:
    def test_assign_profile_to_agent(self, client, auth_headers, db_session):
        tenant_id = _get_default_tenant_id(db_session)
        agent = _create_agent(db_session, "assign-agent", tenant_id)
        profile = _create_profile(client, auth_headers, name="assign-profile")

        resp = client.put(
            f"/api/v1/agents/{agent.agent_id}/profile",
            json={"profile_id": profile["id"]},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["profile_id"] == profile["id"]

    def test_unassign_profile(self, client, auth_headers, db_session):
        tenant_id = _get_default_tenant_id(db_session)
        agent = _create_agent(db_session, "unassign-agent", tenant_id)
        profile = _create_profile(client, auth_headers, name="unassign-profile")

        # Assign
        client.put(
            f"/api/v1/agents/{agent.agent_id}/profile",
            json={"profile_id": profile["id"]},
            headers=auth_headers,
        )
        # Unassign
        resp = client.delete(f"/api/v1/agents/{agent.agent_id}/profile", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["profile_id"] is None

    def test_heartbeat_returns_profile_seccomp(self, client, auth_headers, db_session):
        from control_plane.auth import clear_token_cache
        tenant_id = _get_default_tenant_id(db_session)
        agent = _create_agent(db_session, "hb-seccomp-agent", tenant_id)
        token_value = "hb-seccomp-agent-token-test"
        _create_agent_token(db_session, agent.agent_id, tenant_id, token_value)
        clear_token_cache()

        # Create profile with hardened seccomp
        profile = _create_profile(client, auth_headers, name="hardened-hb", seccomp_profile="hardened")

        # Assign profile
        client.put(
            f"/api/v1/agents/{agent.agent_id}/profile",
            json={"profile_id": profile["id"]},
            headers=auth_headers,
        )

        # Heartbeat should return hardened seccomp
        resp = client.post(
            "/api/v1/agent/heartbeat",
            json={"status": "running"},
            headers={"Authorization": f"Bearer {token_value}"},
        )
        assert resp.status_code == 200
        assert resp.json()["seccomp_profile"] == "hardened"

    def test_agent_status_includes_profile(self, client, auth_headers, db_session):
        tenant_id = _get_default_tenant_id(db_session)
        agent = _create_agent(db_session, "status-profile-agent", tenant_id)
        profile = _create_profile(client, auth_headers, name="status-profile")

        client.put(
            f"/api/v1/agents/{agent.agent_id}/profile",
            json={"profile_id": profile["id"]},
            headers=auth_headers,
        )

        resp = client.get(f"/api/v1/agents/{agent.agent_id}/status", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["security_profile_id"] == profile["id"]
        assert data["security_profile_name"] == "status-profile"

    def test_reassign_profile(self, client, auth_headers, db_session):
        tenant_id = _get_default_tenant_id(db_session)
        agent = _create_agent(db_session, "reassign-agent", tenant_id)
        p1 = _create_profile(client, auth_headers, name="profile-1")
        p2 = _create_profile(client, auth_headers, name="profile-2")

        client.put(
            f"/api/v1/agents/{agent.agent_id}/profile",
            json={"profile_id": p1["id"]},
            headers=auth_headers,
        )
        resp = client.put(
            f"/api/v1/agents/{agent.agent_id}/profile",
            json={"profile_id": p2["id"]},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["profile_id"] == p2["id"]

    def test_delete_profile_reassigns_agents_to_default(self, client, auth_headers, db_session):
        """Deleting a profile should reassign its agents to the 'default' profile."""
        tenant_id = _get_default_tenant_id(db_session)
        agent = _create_agent(db_session, "reassign-delete-agent", tenant_id)
        default_profile = _create_profile(client, auth_headers, name="default")
        profile = _create_profile(client, auth_headers, name="delete-reassign-profile")

        client.put(
            f"/api/v1/agents/{agent.agent_id}/profile",
            json={"profile_id": profile["id"]},
            headers=auth_headers,
        )

        # Delete the profile — agents should move to "default"
        resp = client.delete(f"/api/v1/security-profiles/{profile['id']}", headers=auth_headers)
        assert resp.status_code == 200

        # Verify agent is now on the default profile
        resp = client.get(f"/api/v1/agents/{agent.agent_id}/status", headers=auth_headers)
        assert resp.json()["security_profile_id"] == default_profile["id"]
        assert resp.json()["security_profile_name"] == "default"

    def test_cannot_assign_cross_tenant_profile(self, client, auth_headers, acme_admin_headers, db_session):
        # Create profile in default tenant
        profile = _create_profile(client, auth_headers, name="default-tenant-profile")

        # Create agent in acme tenant
        acme_tenant_id = _get_acme_tenant_id(db_session)
        agent = _create_agent(db_session, "acme-cross-agent", acme_tenant_id)

        # Try to assign default tenant's profile to acme agent
        resp = client.put(
            f"/api/v1/agents/{agent.agent_id}/profile",
            json={"profile_id": profile["id"]},
            headers=acme_admin_headers,
        )
        assert resp.status_code == 400
        assert "same tenant" in resp.json()["detail"].lower()

    def test_profile_agent_count(self, client, auth_headers, db_session):
        tenant_id = _get_default_tenant_id(db_session)
        agent1 = _create_agent(db_session, "count-agent-1", tenant_id)
        agent2 = _create_agent(db_session, "count-agent-2", tenant_id)
        profile = _create_profile(client, auth_headers, name="count-profile")

        client.put(f"/api/v1/agents/{agent1.agent_id}/profile", json={"profile_id": profile["id"]}, headers=auth_headers)
        client.put(f"/api/v1/agents/{agent2.agent_id}/profile", json={"profile_id": profile["id"]}, headers=auth_headers)

        resp = client.get(f"/api/v1/security-profiles/{profile['id']}", headers=auth_headers)
        assert resp.json()["agent_count"] == 2


# =============================================================================
# Profile Domain Policies Tests
# =============================================================================

class TestProfileDomainPolicies:
    def test_create_policy_with_profile_id(self, client, auth_headers):
        profile = _create_profile(client, auth_headers, name="policy-profile")
        resp = client.post(
            "/api/v1/domain-policies",
            json={"domain": "profile-test.example.com", "profile_id": profile["id"]},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["profile_id"] == profile["id"]

    def test_list_filtered_by_profile(self, client, auth_headers):
        profile = _create_profile(client, auth_headers, name="filter-profile")

        # Create baseline policy (no profile)
        client.post("/api/v1/domain-policies", json={"domain": "baseline.example.com"}, headers=auth_headers)
        # Create profile-specific policy
        client.post("/api/v1/domain-policies", json={"domain": "scoped.example.com", "profile_id": profile["id"]}, headers=auth_headers)

        # List with profile filter
        resp = client.get(f"/api/v1/domain-policies?profile_id={profile['id']}", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        domains = [p["domain"] for p in data["items"]]
        assert "scoped.example.com" in domains
        assert "baseline.example.com" not in domains

    def test_cannot_delete_profile_with_policies(self, client, auth_headers):
        profile = _create_profile(client, auth_headers, name="has-policies")
        client.post(
            "/api/v1/domain-policies",
            json={"domain": "policy-block.example.com", "profile_id": profile["id"]},
            headers=auth_headers,
        )
        resp = client.delete(f"/api/v1/security-profiles/{profile['id']}", headers=auth_headers)
        assert resp.status_code == 400
        assert "policies" in resp.json()["detail"].lower()

    def test_profile_policy_count(self, client, auth_headers):
        profile = _create_profile(client, auth_headers, name="pcount-profile")
        client.post("/api/v1/domain-policies", json={"domain": "pc1.example.com", "profile_id": profile["id"]}, headers=auth_headers)
        client.post("/api/v1/domain-policies", json={"domain": "pc2.example.com", "profile_id": profile["id"]}, headers=auth_headers)

        resp = client.get(f"/api/v1/security-profiles/{profile['id']}", headers=auth_headers)
        assert resp.json()["policy_count"] == 2

    def test_same_domain_different_profiles(self, client, auth_headers):
        """Same domain can exist in different profiles (unique constraint includes profile_id)."""
        p1 = _create_profile(client, auth_headers, name="dup-p1")
        p2 = _create_profile(client, auth_headers, name="dup-p2")

        resp1 = client.post("/api/v1/domain-policies", json={"domain": "shared.example.com", "profile_id": p1["id"]}, headers=auth_headers)
        assert resp1.status_code == 200

        resp2 = client.post("/api/v1/domain-policies", json={"domain": "shared.example.com", "profile_id": p2["id"]}, headers=auth_headers)
        assert resp2.status_code == 200


# =============================================================================
# Profile-Scoped Policy Resolution Tests
# =============================================================================

class TestProfilePolicyResolution:
    def test_agent_with_profile_gets_profile_policies(self, client, auth_headers, db_session):
        """Agent with an assigned profile should only see that profile's policies."""
        from control_plane.auth import clear_token_cache
        tenant_id = _get_default_tenant_id(db_session)

        agent = _create_agent(db_session, "profile-res-agent", tenant_id)
        token_value = "profile-res-agent-token-test"
        _create_agent_token(db_session, agent.agent_id, tenant_id, token_value)
        clear_token_cache()

        # Create two profiles
        profile_a = _create_profile(client, auth_headers, name="resolve-a")
        profile_b = _create_profile(client, auth_headers, name="resolve-b")

        # Assign profile-a to agent
        client.put(f"/api/v1/agents/{agent.agent_id}/profile", json={"profile_id": profile_a["id"]}, headers=auth_headers)

        # Create policies in both profiles
        client.post("/api/v1/domain-policies", json={"domain": "resolve-a.example.com", "profile_id": profile_a["id"]}, headers=auth_headers)
        client.post("/api/v1/domain-policies", json={"domain": "resolve-b.example.com", "profile_id": profile_b["id"]}, headers=auth_headers)

        # Export should only include profile-a policies
        resp = client.get("/api/v1/domain-policies/export", headers={"Authorization": f"Bearer {token_value}"})
        assert resp.status_code == 200
        domains = resp.json()["domains"]
        assert "resolve-a.example.com" in domains
        assert "resolve-b.example.com" not in domains

    def test_agent_without_profile_falls_back_to_default(self, client, auth_headers, db_session):
        """Agent without an assigned profile should fall back to the 'default' profile."""
        from control_plane.auth import clear_token_cache
        tenant_id = _get_default_tenant_id(db_session)

        agent = _create_agent(db_session, "fallback-agent", tenant_id)
        token_value = "fallback-agent-token-test"
        _create_agent_token(db_session, agent.agent_id, tenant_id, token_value)
        clear_token_cache()

        # Create "default" profile and add a policy to it
        default_profile = _create_profile(client, auth_headers, name="default")
        client.post("/api/v1/domain-policies", json={"domain": "default-fb.example.com", "profile_id": default_profile["id"]}, headers=auth_headers)

        # Create another profile with different policy
        other_profile = _create_profile(client, auth_headers, name="other-fb")
        client.post("/api/v1/domain-policies", json={"domain": "other-fb.example.com", "profile_id": other_profile["id"]}, headers=auth_headers)

        # Export without assigned profile should get default profile policies
        resp = client.get("/api/v1/domain-policies/export", headers={"Authorization": f"Bearer {token_value}"})
        assert resp.status_code == 200
        domains = resp.json()["domains"]
        assert "default-fb.example.com" in domains
        assert "other-fb.example.com" not in domains

    def test_for_domain_uses_profile_resolution(self, client, auth_headers, db_session):
        """for-domain endpoint should resolve policies through the agent's profile."""
        from control_plane.auth import clear_token_cache
        tenant_id = _get_default_tenant_id(db_session)

        agent = _create_agent(db_session, "for-domain-agent", tenant_id)
        token_value = "for-domain-agent-token-test"
        _create_agent_token(db_session, agent.agent_id, tenant_id, token_value)
        clear_token_cache()

        profile = _create_profile(client, auth_headers, name="for-domain-profile")
        client.put(f"/api/v1/agents/{agent.agent_id}/profile", json={"profile_id": profile["id"]}, headers=auth_headers)

        # Create policy in the profile
        client.post("/api/v1/domain-policies", json={
            "domain": "for-domain-test.example.com",
            "profile_id": profile["id"],
            "requests_per_minute": 42,
        }, headers=auth_headers)

        # for-domain should match via profile
        resp = client.get(
            "/api/v1/domain-policies/for-domain?domain=for-domain-test.example.com",
            headers={"Authorization": f"Bearer {token_value}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["matched"] is True
        assert data["requests_per_minute"] == 42

    def test_for_domain_no_match_outside_profile(self, client, auth_headers, db_session):
        """for-domain should not match policies from other profiles."""
        from control_plane.auth import clear_token_cache
        tenant_id = _get_default_tenant_id(db_session)

        agent = _create_agent(db_session, "outside-agent", tenant_id)
        token_value = "outside-agent-token-test"
        _create_agent_token(db_session, agent.agent_id, tenant_id, token_value)
        clear_token_cache()

        profile_a = _create_profile(client, auth_headers, name="outside-a")
        profile_b = _create_profile(client, auth_headers, name="outside-b")
        client.put(f"/api/v1/agents/{agent.agent_id}/profile", json={"profile_id": profile_a["id"]}, headers=auth_headers)

        # Policy in profile_b only
        client.post("/api/v1/domain-policies", json={
            "domain": "outside-test.example.com",
            "profile_id": profile_b["id"],
        }, headers=auth_headers)

        # for-domain should NOT match since agent is on profile_a
        resp = client.get(
            "/api/v1/domain-policies/for-domain?domain=outside-test.example.com",
            headers={"Authorization": f"Bearer {token_value}"},
        )
        assert resp.status_code == 200
        assert resp.json()["matched"] is False

    def test_agent_no_profile_no_default_gets_nothing(self, client, auth_headers, db_session):
        """Agent without profile and no 'default' profile sees no policies."""
        from control_plane.auth import clear_token_cache
        tenant_id = _get_default_tenant_id(db_session)

        agent = _create_agent(db_session, "empty-agent", tenant_id)
        token_value = "empty-agent-token-test"
        _create_agent_token(db_session, agent.agent_id, tenant_id, token_value)
        clear_token_cache()

        # Create a policy with no profile_id (orphaned)
        client.post("/api/v1/domain-policies", json={"domain": "orphan.example.com"}, headers=auth_headers)

        # Export should return empty since no profile assigned and no "default" profile exists
        resp = client.get("/api/v1/domain-policies/export", headers={"Authorization": f"Bearer {token_value}"})
        assert resp.status_code == 200
        domains = resp.json()["domains"]
        assert "orphan.example.com" not in domains


# =============================================================================
# Multi-Tenancy Tests
# =============================================================================

class TestMultiTenancy:
    def test_cross_tenant_isolation(self, client, auth_headers, acme_admin_headers):
        """Default tenant admin cannot see Acme profiles and vice versa."""
        default_profile = _create_profile(client, auth_headers, name="default-iso")
        acme_profile = _create_profile(client, acme_admin_headers, name="acme-iso")

        # Default admin lists profiles
        resp = client.get("/api/v1/security-profiles", headers=auth_headers)
        names = [p["name"] for p in resp.json()["items"]]
        assert "default-iso" in names
        assert "acme-iso" not in names

        # Acme admin lists profiles
        resp = client.get("/api/v1/security-profiles", headers=acme_admin_headers)
        names = [p["name"] for p in resp.json()["items"]]
        assert "acme-iso" in names
        assert "default-iso" not in names

        # Default admin can't access Acme profile by ID
        resp = client.get(f"/api/v1/security-profiles/{acme_profile['id']}", headers=auth_headers)
        assert resp.status_code == 404

    def test_super_admin_sees_all(self, client, auth_headers, acme_admin_headers, super_admin_headers):
        _create_profile(client, auth_headers, name="sa-default")
        _create_profile(client, acme_admin_headers, name="sa-acme")

        resp = client.get("/api/v1/security-profiles", headers=super_admin_headers)
        names = [p["name"] for p in resp.json()["items"]]
        assert "sa-default" in names
        assert "sa-acme" in names

    def test_super_admin_creates_with_tenant_id(self, client, super_admin_headers, db_session):
        tenant_id = _get_default_tenant_id(db_session)
        resp = client.post(
            f"/api/v1/security-profiles?tenant_id={tenant_id}",
            json={"name": "sa-created"},
            headers=super_admin_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["tenant_id"] == tenant_id

    def test_super_admin_requires_tenant_id(self, client, super_admin_headers):
        resp = client.post("/api/v1/security-profiles", json={"name": "no-tenant"}, headers=super_admin_headers)
        assert resp.status_code == 400
        assert "tenant_id" in resp.json()["detail"]


# =============================================================================
# RBAC Tests
# =============================================================================

class TestRBAC:
    def test_developer_can_list(self, client, dev_headers, auth_headers):
        """Developers cannot list security profiles (admin role required)."""
        resp = client.get("/api/v1/security-profiles", headers=dev_headers)
        assert resp.status_code == 403

    def test_developer_cannot_create(self, client, dev_headers):
        resp = client.post("/api/v1/security-profiles", json={"name": "dev-profile"}, headers=dev_headers)
        assert resp.status_code == 403

    def test_developer_cannot_delete(self, client, dev_headers, auth_headers):
        profile = _create_profile(client, auth_headers, name="dev-delete")
        resp = client.delete(f"/api/v1/security-profiles/{profile['id']}", headers=dev_headers)
        assert resp.status_code == 403


# =============================================================================
# Audit Trail Tests
# =============================================================================

class TestAuditTrail:
    def test_create_audit(self, client, auth_headers):
        _create_profile(client, auth_headers, name="audit-create")
        resp = client.get("/api/v1/audit-trail?event_type=security_profile_created", headers=auth_headers)
        assert resp.status_code == 200
        events = resp.json()["items"]
        assert any("audit-create" in e["action"] for e in events)

    def test_update_audit(self, client, auth_headers):
        profile = _create_profile(client, auth_headers, name="audit-update")
        client.put(
            f"/api/v1/security-profiles/{profile['id']}",
            json={"description": "updated"},
            headers=auth_headers,
        )
        resp = client.get("/api/v1/audit-trail?event_type=security_profile_updated", headers=auth_headers)
        events = resp.json()["items"]
        assert any("audit-update" in e["action"] for e in events)

    def test_delete_audit(self, client, auth_headers):
        profile = _create_profile(client, auth_headers, name="audit-delete")
        client.delete(f"/api/v1/security-profiles/{profile['id']}", headers=auth_headers)
        resp = client.get("/api/v1/audit-trail?event_type=security_profile_deleted", headers=auth_headers)
        events = resp.json()["items"]
        assert any("audit-delete" in e["action"] for e in events)

    def test_assign_audit(self, client, auth_headers, db_session):
        tenant_id = _get_default_tenant_id(db_session)
        agent = _create_agent(db_session, "audit-assign-agent", tenant_id)
        profile = _create_profile(client, auth_headers, name="audit-assign-profile")
        client.put(
            f"/api/v1/agents/{agent.agent_id}/profile",
            json={"profile_id": profile["id"]},
            headers=auth_headers,
        )
        resp = client.get("/api/v1/audit-trail?event_type=agent_profile_assigned", headers=auth_headers)
        events = resp.json()["items"]
        assert any("audit-assign-agent" in (e.get("action") or "") for e in events)


# =============================================================================
# Resource Limit Tests
# =============================================================================

class TestResourceLimits:
    def test_create_profile_with_resource_limits(self, client, auth_headers):
        profile = _create_profile(
            client, auth_headers, name="resource-profile",
            cpu_limit=2.0, memory_limit_mb=4096, pids_limit=512,
        )
        assert profile["cpu_limit"] == 2.0
        assert profile["memory_limit_mb"] == 4096
        assert profile["pids_limit"] == 512

    def test_create_profile_without_resource_limits(self, client, auth_headers):
        profile = _create_profile(client, auth_headers, name="no-resources")
        assert profile["cpu_limit"] is None
        assert profile["memory_limit_mb"] is None
        assert profile["pids_limit"] is None

    def test_update_resource_limits(self, client, auth_headers):
        profile = _create_profile(client, auth_headers, name="update-resources")
        resp = client.put(
            f"/api/v1/security-profiles/{profile['id']}",
            json={"cpu_limit": 1.5, "memory_limit_mb": 2048, "pids_limit": 256},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["cpu_limit"] == 1.5
        assert data["memory_limit_mb"] == 2048
        assert data["pids_limit"] == 256

    def test_clear_resource_limits_with_zero(self, client, auth_headers):
        """Setting a resource limit to 0 clears it (sets to None)."""
        profile = _create_profile(
            client, auth_headers, name="clear-resources",
            cpu_limit=2.0, memory_limit_mb=4096, pids_limit=256,
        )
        resp = client.put(
            f"/api/v1/security-profiles/{profile['id']}",
            json={"cpu_limit": 0, "memory_limit_mb": 0, "pids_limit": 0},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["cpu_limit"] is None
        assert data["memory_limit_mb"] is None
        assert data["pids_limit"] is None

    def test_partial_resource_limits(self, client, auth_headers):
        """Can set only some resource limits."""
        profile = _create_profile(
            client, auth_headers, name="partial-resources",
            cpu_limit=1.0,
        )
        assert profile["cpu_limit"] == 1.0
        assert profile["memory_limit_mb"] is None
        assert profile["pids_limit"] is None

    def test_heartbeat_returns_resource_limits(self, client, auth_headers, db_session):
        from control_plane.auth import clear_token_cache
        tenant_id = _get_default_tenant_id(db_session)
        agent = _create_agent(db_session, "hb-resource-agent", tenant_id)
        token_value = "hb-resource-agent-token-test"
        _create_agent_token(db_session, agent.agent_id, tenant_id, token_value)
        clear_token_cache()

        # Create profile with resource limits
        profile = _create_profile(
            client, auth_headers, name="hb-resource-profile",
            cpu_limit=2.0, memory_limit_mb=4096, pids_limit=512,
        )

        # Assign profile
        client.put(
            f"/api/v1/agents/{agent.agent_id}/profile",
            json={"profile_id": profile["id"]},
            headers=auth_headers,
        )

        # Heartbeat should return resource limits
        resp = client.post(
            "/api/v1/agent/heartbeat",
            json={"status": "running"},
            headers={"Authorization": f"Bearer {token_value}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["cpu_limit"] == 2.0
        assert data["memory_limit_mb"] == 4096
        assert data["pids_limit"] == 512

    def test_heartbeat_no_profile_no_resource_limits(self, client, auth_headers, db_session):
        from control_plane.auth import clear_token_cache
        tenant_id = _get_default_tenant_id(db_session)
        agent = _create_agent(db_session, "hb-noresource-agent", tenant_id)
        token_value = "hb-noresource-agent-token-test"
        _create_agent_token(db_session, agent.agent_id, tenant_id, token_value)
        clear_token_cache()

        # Heartbeat with no profile should have null resource limits
        resp = client.post(
            "/api/v1/agent/heartbeat",
            json={"status": "running"},
            headers={"Authorization": f"Bearer {token_value}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["cpu_limit"] is None
        assert data["memory_limit_mb"] is None
        assert data["pids_limit"] is None

    def test_update_profile_resources_preserved_on_other_updates(self, client, auth_headers):
        """Updating other fields doesn't clear resource limits."""
        profile = _create_profile(
            client, auth_headers, name="preserve-resources",
            cpu_limit=2.0, memory_limit_mb=4096,
        )
        # Update only the name
        resp = client.put(
            f"/api/v1/security-profiles/{profile['id']}",
            json={"name": "preserve-resources-renamed"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["cpu_limit"] == 2.0
        assert data["memory_limit_mb"] == 4096
