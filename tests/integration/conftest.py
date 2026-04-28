"""Integration test fixtures — shared authenticated connections for live-appliance tests."""

from __future__ import annotations

import uuid

import pytest

from pysafeguard import AsyncSafeguardClient, PasswordAuth, PkceAuth, SafeguardClient, Service

_ROG_SETTING_NAME = "Allowed OAuth2 Grant Types"


# ---------------------------------------------------------------------------
# Preflight: ensure Resource Owner Grant is enabled
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session", autouse=True)
def _ensure_resource_owner_grant(spp_host, spp_username, spp_password, spp_verify):
    """Check that the Resource Owner password grant is enabled on the appliance.

    Modern SPP versions (8.0+) may ship with the Resource Owner grant disabled.
    If disabled, this fixture uses PKCE (which does not require ROG) to
    authenticate, enables the grant via the Settings API, runs the test
    session, then restores the original setting.

    This matches the preflight pattern used by SafeguardDotNet and safeguard-ps.
    """
    if not spp_host:
        yield
        return

    # Probe: try PasswordAuth login
    probe = SafeguardClient(spp_host, auth=PasswordAuth("local", spp_username, spp_password), verify=spp_verify)
    try:
        probe.login()
        probe.close()
        # ROG is enabled — nothing to do
        yield
        return
    except Exception:
        probe.close()
        # ROG may be disabled — attempt PKCE remediation

    # Remediate: use PKCE to log in and enable ROG
    original_value: str | None = None
    setting_id: str | None = None
    try:
        pkce_client = SafeguardClient(spp_host, auth=PkceAuth("local", spp_username, spp_password), verify=spp_verify)
        pkce_client.login()

        resp = pkce_client.get(Service.CORE, "Settings")
        settings = resp.json()
        for s in settings:
            if s.get("Name") == _ROG_SETTING_NAME:
                original_value = s.get("Value", "")
                setting_id = s.get("Name")
                break

        if setting_id is None:
            pkce_client.close()
            pytest.exit(f"Could not find '{_ROG_SETTING_NAME}' in appliance settings — cannot enable ROG", returncode=1)

        grant_types = [g.strip() for g in original_value.split(",") if g.strip()] if original_value else []
        if not any(g.lower() == "resourceowner" for g in grant_types):
            grant_types.append("ResourceOwner")
            new_value = ", ".join(grant_types)
            pkce_client.put(Service.CORE, f"Settings/{_ROG_SETTING_NAME}", json={"Value": new_value})
            print(f"\n[preflight] Enabled Resource Owner grant (was: '{original_value}')")
        else:
            # ROG is in the setting but PasswordAuth still failed — different problem
            pkce_client.close()
            pytest.exit(
                "Resource Owner grant is listed in settings but PasswordAuth login failed. Check credentials or appliance configuration.",
                returncode=1,
            )

        pkce_client.close()
    except SystemExit:
        raise
    except Exception as exc:
        pytest.exit(f"Failed to enable Resource Owner grant via PKCE: {exc}", returncode=1)

    # Run the test session
    yield

    # Restore: put the original setting back
    if original_value is not None:
        try:
            restore_client = SafeguardClient(spp_host, auth=PkceAuth("local", spp_username, spp_password), verify=spp_verify)
            restore_client.login()
            restore_client.put(Service.CORE, f"Settings/{_ROG_SETTING_NAME}", json={"Value": original_value})
            restore_client.close()
            print(f"\n[preflight] Restored Resource Owner grant setting to: '{original_value}'")
        except Exception as exc:
            print(f"\n[preflight] Warning: failed to restore ROG setting: {exc}")


@pytest.fixture()
def sync_connection(spp_host, spp_username, spp_password, spp_verify):
    """Authenticated sync SafeguardClient (function-scoped)."""
    client = SafeguardClient(
        spp_host,
        auth=PasswordAuth("local", spp_username, spp_password),
        verify=spp_verify,
    )
    client.login()
    return client


@pytest.fixture()
async def async_connection(spp_host, spp_username, spp_password, spp_verify):
    """Authenticated async AsyncSafeguardClient (function-scoped)."""
    client = AsyncSafeguardClient(
        spp_host,
        auth=PasswordAuth("local", spp_username, spp_password),
        verify=spp_verify,
    )
    await client.login()
    return client


@pytest.fixture()
def unique_name():
    """Generate a unique name for test resources to prevent collisions.

    All test-created objects use a ``PySg_`` prefix so they are easily
    recognizable on a shared appliance (consistent with safeguard-ps,
    safeguarddotnet, safeguardjava, and safeguard-bash conventions).
    """
    short_id = uuid.uuid4().hex[:8]
    return f"PySg_{short_id}"


def delete_user_sync(client, user_id):
    """Best-effort user cleanup — ignores 'not found' errors."""
    try:
        resp = client.delete(Service.CORE, f"Users/{user_id}")
        # 204 No Content = success, 404 = already gone — both are fine
        if resp.status_code not in (200, 204, 404):
            print(f"Warning: cleanup DELETE Users/{user_id} returned {resp.status_code}")
    except Exception as e:
        print(f"Warning: cleanup DELETE Users/{user_id} failed: {e}")


async def delete_user_async(client, user_id):
    """Best-effort async user cleanup."""
    try:
        resp = await client.delete(Service.CORE, f"Users/{user_id}")
        if resp.status not in (200, 204, 404):
            print(f"Warning: async cleanup DELETE Users/{user_id} returned {resp.status}")
    except Exception as e:
        print(f"Warning: async cleanup DELETE Users/{user_id} failed: {e}")
