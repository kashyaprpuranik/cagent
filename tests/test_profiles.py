"""Validate community profile JSON files and manifest consistency.

Runs as part of pre-push to catch broken profiles before they reach users.
"""
import json
from pathlib import Path

import pytest

PROFILES_DIR = Path(__file__).parent.parent / "configs" / "profiles"
MANIFEST_PATH = PROFILES_DIR / "manifest.json"

REQUIRED_PROFILE_KEYS = {"name", "description", "domain_policies"}
OPTIONAL_PROFILE_KEYS = {"security", "resource_limits", "dlp", "email_policies"}
ALL_PROFILE_KEYS = REQUIRED_PROFILE_KEYS | OPTIONAL_PROFILE_KEYS

VALID_RUNTIME_POLICIES = {"standard", "hardened", "permissive"}

REQUIRED_MANIFEST_ENTRY_KEYS = {"file", "name", "description", "icon", "domains", "tags"}

REQUIRED_DOMAIN_KEYS = {"domain"}
OPTIONAL_DOMAIN_KEYS = {
    "alias", "description", "timeout", "requests_per_minute", "burst_size",
    "allowed_paths", "read_only", "expires_at",
}


class TestManifest:
    """Validate profiles-manifest.json."""

    def test_manifest_is_valid_json(self):
        data = json.loads(MANIFEST_PATH.read_text())
        assert isinstance(data, list), "Manifest must be a JSON array"
        assert len(data) > 0, "Manifest must not be empty"

    def test_manifest_entries_have_required_keys(self):
        entries = json.loads(MANIFEST_PATH.read_text())
        for entry in entries:
            missing = REQUIRED_MANIFEST_ENTRY_KEYS - set(entry.keys())
            assert not missing, f"Manifest entry '{entry.get('name', '?')}' missing keys: {missing}"

    def test_manifest_files_exist(self):
        entries = json.loads(MANIFEST_PATH.read_text())
        for entry in entries:
            profile_path = PROFILES_DIR / entry["file"]
            assert profile_path.exists(), (
                f"Manifest references '{entry['file']}' but file does not exist in configs/profiles/"
            )

    def test_manifest_names_match_profile_names(self):
        entries = json.loads(MANIFEST_PATH.read_text())
        for entry in entries:
            profile_path = PROFILES_DIR / entry["file"]
            if not profile_path.exists():
                continue
            profile = json.loads(profile_path.read_text())
            assert entry["name"] == profile["name"], (
                f"Manifest name '{entry['name']}' != profile name '{profile['name']}' in {entry['file']}"
            )

    def test_manifest_domain_counts_match(self):
        entries = json.loads(MANIFEST_PATH.read_text())
        for entry in entries:
            profile_path = PROFILES_DIR / entry["file"]
            if not profile_path.exists():
                continue
            profile = json.loads(profile_path.read_text())
            actual = len(profile.get("domain_policies", []))
            assert entry["domains"] == actual, (
                f"Manifest says {entry['domains']} domains for '{entry['name']}' "
                f"but profile has {actual}"
            )

    def test_no_orphan_profile_files(self):
        """Every .json profile file in the directory should be in the manifest."""
        entries = json.loads(MANIFEST_PATH.read_text())
        manifest_files = {e["file"] for e in entries}
        for path in PROFILES_DIR.glob("*.json"):
            if path.name == "manifest.json":
                continue
            assert path.name in manifest_files, (
                f"Profile file '{path.name}' exists but is not in manifest.json"
            )

    def test_no_duplicate_names(self):
        entries = json.loads(MANIFEST_PATH.read_text())
        names = [e["name"] for e in entries]
        assert len(names) == len(set(names)), f"Duplicate names in manifest: {names}"

    def test_no_duplicate_files(self):
        entries = json.loads(MANIFEST_PATH.read_text())
        files = [e["file"] for e in entries]
        assert len(files) == len(set(files)), f"Duplicate files in manifest: {files}"


def _load_profiles():
    """Load all profile files referenced by the manifest."""
    entries = json.loads(MANIFEST_PATH.read_text())
    profiles = []
    for entry in entries:
        path = PROFILES_DIR / entry["file"]
        if path.exists():
            profiles.append((entry["file"], json.loads(path.read_text())))
    return profiles


class TestProfileSchema:
    """Validate individual profile JSON files."""

    @pytest.fixture(params=_load_profiles(), ids=lambda p: p[0])
    def profile(self, request):
        return request.param

    def test_has_required_keys(self, profile):
        filename, data = profile
        missing = REQUIRED_PROFILE_KEYS - set(data.keys())
        assert not missing, f"{filename} missing required keys: {missing}"

    def test_no_unknown_keys(self, profile):
        filename, data = profile
        unknown = set(data.keys()) - ALL_PROFILE_KEYS
        assert not unknown, f"{filename} has unknown top-level keys: {unknown}"

    def test_name_is_nonempty_string(self, profile):
        filename, data = profile
        assert isinstance(data["name"], str) and data["name"].strip(), (
            f"{filename}: name must be a non-empty string"
        )

    def test_domain_policies_is_list(self, profile):
        filename, data = profile
        assert isinstance(data["domain_policies"], list), (
            f"{filename}: domain_policies must be a list"
        )

    def test_domain_entries_have_domain_key(self, profile):
        filename, data = profile
        for i, entry in enumerate(data["domain_policies"]):
            assert "domain" in entry, (
                f"{filename}: domain_policies[{i}] missing 'domain' key"
            )
            assert isinstance(entry["domain"], str) and entry["domain"].strip(), (
                f"{filename}: domain_policies[{i}].domain must be a non-empty string"
            )

    def test_no_duplicate_domains(self, profile):
        filename, data = profile
        domains = [d["domain"] for d in data["domain_policies"]]
        seen = set()
        dupes = []
        for d in domains:
            if d in seen:
                dupes.append(d)
            seen.add(d)
        assert not dupes, f"{filename} has duplicate domains: {dupes}"

    def test_security_policy_values(self, profile):
        filename, data = profile
        security = data.get("security", {})
        if "runtime_policy" in security:
            assert security["runtime_policy"] in VALID_RUNTIME_POLICIES, (
                f"{filename}: invalid runtime_policy '{security['runtime_policy']}'"
            )

    def test_resource_limits_are_positive(self, profile):
        filename, data = profile
        limits = data.get("resource_limits", {})
        for key in ("cpu_limit", "memory_limit_mb", "pids_limit"):
            if key in limits:
                assert isinstance(limits[key], (int, float)) and limits[key] > 0, (
                    f"{filename}: resource_limits.{key} must be positive, got {limits[key]}"
                )

    def test_rate_limits_are_positive(self, profile):
        filename, data = profile
        for i, entry in enumerate(data.get("domain_policies", [])):
            for key in ("requests_per_minute", "burst_size"):
                if key in entry:
                    assert isinstance(entry[key], (int, float)) and entry[key] > 0, (
                        f"{filename}: domain_policies[{i}].{key} must be positive"
                    )
