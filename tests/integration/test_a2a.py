"""Integration tests for A2A (Application-to-Application) credential operations.

These tests create a full A2A environment on the appliance:
- A local test admin user with AssetAdmin/PolicyAdmin roles
- A self-signed client certificate uploaded to TrustedCertificates
- A certificate user linked to that cert
- An "Other Managed" asset with an account and known password
- An A2A registration with a retrievable account and API key

After testing, all resources are cleaned up.

Requires SPP_HOST, SPP_USERNAME, SPP_PASSWORD environment variables.
"""

from __future__ import annotations

import base64
import hashlib
import os
import ssl
import subprocess
import tempfile
import time

import pytest

from pysafeguard import (
    EventListenerState,
    PasswordAuth,
    PersistentSafeguardEventListener,
    SafeguardClient,
    SafeguardEventListener,
    Service,
)
from pysafeguard.a2a import A2AContext
from pysafeguard.async_a2a import AsyncA2AContext

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Fixture: full A2A environment (session-scoped for efficiency)
# ---------------------------------------------------------------------------


class _A2AEnv:
    """Holds all IDs and paths needed by A2A tests."""

    host: str
    verify: bool | str
    cert_file: str
    key_file: str
    thumbprint: str
    api_key: str
    account_id: int
    asset_id: int
    reg_id: int
    cert_user_id: int
    test_admin_id: int
    tmpdir: str
    admin_client: SafeguardClient
    test_admin_client: SafeguardClient
    original_password: str = "A2AOriginal1!"


@pytest.fixture(scope="module")
def a2a_env(spp_host, spp_username, spp_password, spp_verify):
    """Create the full A2A environment; tear it down after the module."""
    env = _A2AEnv()
    env.host = spp_host
    env.verify = spp_verify

    # --- bootstrap admin (for trusted certs + test admin creation) ---
    env.admin_client = SafeguardClient(spp_host, auth=PasswordAuth("local", spp_username, spp_password), verify=spp_verify)
    env.admin_client.login()

    # --- create test admin with asset/policy roles ---
    r = env.admin_client.post(
        Service.CORE,
        "Users",
        json={
            "Name": "PySg_A2ATestAdmin",
            "IdentityProvider": {"Id": -1},
            "PrimaryAuthenticationProvider": {"Id": -1},
            "AdminRoles": [
                "GlobalAdmin",
                "AssetAdmin",
                "PolicyAdmin",
                "UserAdmin",
                "Auditor",
                "ApplicationAuditor",
            ],
        },
    )
    assert r.status_code == 201, f"Create test admin failed: {r.text[:300]}"
    env.test_admin_id = r.json()["Id"]
    env.admin_client.put(Service.CORE, f"Users/{env.test_admin_id}/Password", json="A2ATestAdmin1!")

    env.test_admin_client = SafeguardClient(spp_host, auth=PasswordAuth("local", "PySg_A2ATestAdmin", "A2ATestAdmin1!"), verify=spp_verify)
    env.test_admin_client.login()

    # --- generate self-signed client certificate ---
    env.tmpdir = tempfile.mkdtemp(prefix="pysafeguard_a2a_")
    env.key_file = os.path.join(env.tmpdir, "key.pem")
    env.cert_file = os.path.join(env.tmpdir, "cert.pem")
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            env.key_file,
            "-out",
            env.cert_file,
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=PySg_A2ATestCert",
        ],
        capture_output=True,
        check=True,
    )
    der = ssl.PEM_cert_to_DER_cert(open(env.cert_file).read())
    env.thumbprint = hashlib.sha1(der).hexdigest().upper()

    # --- upload cert to trusted store (requires ApplianceAdmin) ---
    b64cert = base64.b64encode(der).decode()
    r = env.admin_client.post(Service.CORE, "TrustedCertificates", json={"Base64CertificateData": b64cert})
    assert r.status_code == 201, f"Upload trusted cert failed: {r.text[:300]}"

    # --- create certificate user ---
    c = env.test_admin_client
    r = c.post(
        Service.CORE,
        "Users",
        json={
            "Name": "PySg_A2ACertUser",
            "PrimaryAuthenticationProvider": {"Id": -2, "Identity": env.thumbprint},
            "AdminRoles": ["Auditor"],
        },
    )
    assert r.status_code == 201, f"Create cert user failed: {r.text[:300]}"
    env.cert_user_id = r.json()["Id"]

    # --- create asset ---
    r = c.post(
        Service.CORE,
        "Assets",
        json={
            "Name": "PySg_A2ATestAsset",
            "NetworkAddress": "127.0.0.1",
            "PlatformId": 501,
            "AssetPartitionId": -1,
        },
    )
    assert r.status_code == 201, f"Create asset failed: {r.text[:300]}"
    env.asset_id = r.json()["Id"]

    # --- create account ---
    r = c.post(
        Service.CORE,
        "AssetAccounts",
        json={"Name": "PySg_a2a_testacct", "Asset": {"Id": env.asset_id}},
    )
    assert r.status_code == 201, f"Create account failed: {r.text[:300]}"
    env.account_id = r.json()["Id"]

    # --- set account password ---
    r = c.put(Service.CORE, f"AssetAccounts/{env.account_id}/Password", json=env.original_password)
    assert r.status_code == 204, f"Set password failed: {r.status_code}"

    # --- create A2A registration ---
    r = c.post(
        Service.CORE,
        "A2ARegistrations",
        json={"AppName": "PySg_A2ATest", "CertificateUserId": env.cert_user_id},
    )
    assert r.status_code == 201, f"Create A2A reg failed: {r.text[:300]}"
    env.reg_id = r.json()["Id"]

    # --- enable bidirectional (required for set_password via A2A) ---
    reg_data = c.get(Service.CORE, f"A2ARegistrations/{env.reg_id}").json()
    reg_data["BidirectionalEnabled"] = True
    r = c.put(Service.CORE, f"A2ARegistrations/{env.reg_id}", json=reg_data)
    assert r.status_code == 200, f"Enable bidirectional failed: {r.text[:300]}"

    # --- add retrievable account ---
    r = c.post(
        Service.CORE,
        f"A2ARegistrations/{env.reg_id}/RetrievableAccounts",
        json={"AccountId": env.account_id, "Type": "Password"},
    )
    assert r.status_code in (200, 201), f"Add retrievable failed: {r.text[:300]}"
    env.api_key = r.json()["ApiKey"]

    # --- readiness check: verify credential retrieval works ---
    with A2AContext(env.host, env.cert_file, env.key_file, verify=env.verify) as a2a:
        pw = a2a.retrieve_password(env.api_key)
        assert pw.value == env.original_password, "Readiness check failed"

    yield env

    # --- teardown: best-effort cleanup of every resource ---
    _safe_delete(c, Service.CORE, f"A2ARegistrations/{env.reg_id}")
    _safe_delete(c, Service.CORE, f"AssetAccounts/{env.account_id}")
    _safe_delete(c, Service.CORE, f"Assets/{env.asset_id}")
    _safe_delete(c, Service.CORE, f"Users/{env.cert_user_id}")
    _safe_delete(env.admin_client, Service.CORE, f"TrustedCertificates/{env.thumbprint}")
    _safe_delete(env.admin_client, Service.CORE, f"Users/{env.test_admin_id}")

    import shutil

    shutil.rmtree(env.tmpdir, ignore_errors=True)


def _safe_delete(client: SafeguardClient, service: Service, endpoint: str) -> None:
    """Best-effort deletion — swallow errors so cleanup continues."""
    try:
        r = client.delete(service, endpoint)
        if r.status_code not in (200, 204, 404):
            print(f"Warning: DELETE {endpoint} returned {r.status_code}")
    except Exception as e:
        print(f"Warning: DELETE {endpoint} failed: {e}")


# ---------------------------------------------------------------------------
# Helper: reset password to known state
# ---------------------------------------------------------------------------


@pytest.fixture()
def _reset_password(a2a_env):
    """Reset the account password to the original value after each test."""
    yield
    with A2AContext(a2a_env.host, a2a_env.cert_file, a2a_env.key_file, verify=a2a_env.verify) as a2a:
        try:
            a2a.set_password(a2a_env.api_key, a2a_env.original_password)
        except Exception:
            pass


# ===========================================================================
# Sync A2A credential tests
# ===========================================================================


class TestA2ARetrievePassword:
    """Test A2AContext password retrieval."""

    def test_retrieve_password(self, a2a_env):
        """Retrieve the known password via A2AContext."""
        with A2AContext(a2a_env.host, a2a_env.cert_file, a2a_env.key_file, verify=a2a_env.verify) as a2a:
            pw = a2a.retrieve_password(a2a_env.api_key)
            assert pw.value == a2a_env.original_password

    def test_retrieve_via_value_property(self, a2a_env):
        """HiddenString.value property works for retrieved passwords."""
        with A2AContext(a2a_env.host, a2a_env.cert_file, a2a_env.key_file, verify=a2a_env.verify) as a2a:
            pw = a2a.retrieve_password(a2a_env.api_key)
            assert pw.value == pw.get_value()


class TestA2ASetPassword:
    """Test A2AContext password mutation."""

    def test_set_and_retrieve(self, a2a_env, _reset_password):
        """set_password changes the credential, retrievable immediately."""
        with A2AContext(a2a_env.host, a2a_env.cert_file, a2a_env.key_file, verify=a2a_env.verify) as a2a:
            a2a.set_password(a2a_env.api_key, "Changed42!")
            pw = a2a.retrieve_password(a2a_env.api_key)
            assert pw.value == "Changed42!"

    def test_set_password_roundtrip(self, a2a_env, _reset_password):
        """Multiple set/retrieve cycles work."""
        with A2AContext(a2a_env.host, a2a_env.cert_file, a2a_env.key_file, verify=a2a_env.verify) as a2a:
            for i, new_pw in enumerate(["Round1!", "Round2!", "Round3!"]):
                a2a.set_password(a2a_env.api_key, new_pw)
                assert a2a.retrieve_password(a2a_env.api_key).value == new_pw


class TestA2AQuickRetrieve:
    """Test one-shot class method helpers."""

    def test_quick_retrieve_password(self, a2a_env):
        """Class method one-shot password retrieval."""
        pw = A2AContext.quick_retrieve_password(
            a2a_env.host,
            a2a_env.api_key,
            a2a_env.cert_file,
            a2a_env.key_file,
            verify=a2a_env.verify,
        )
        assert pw.value == a2a_env.original_password


class TestA2ARetrievableAccounts:
    """Test Core API discovery of retrievable accounts."""

    def test_get_retrievable_accounts(self, a2a_env):
        """get_retrievable_accounts returns at least one account."""
        with A2AContext(a2a_env.host, a2a_env.cert_file, a2a_env.key_file, verify=a2a_env.verify) as a2a:
            accounts = a2a.get_retrievable_accounts()
            assert len(accounts) >= 1
            our_account = [a for a in accounts if a.get("AccountId") == a2a_env.account_id]
            assert len(our_account) == 1

    def test_retrievable_accounts_have_metadata(self, a2a_env):
        """Each account is decorated with ApplicationName and Description."""
        with A2AContext(a2a_env.host, a2a_env.cert_file, a2a_env.key_file, verify=a2a_env.verify) as a2a:
            accounts = a2a.get_retrievable_accounts()
            for acct in accounts:
                assert "ApplicationName" in acct
                assert "Disabled" in acct


# ===========================================================================
# Async A2A credential tests
# ===========================================================================


class TestAsyncA2ARetrievePassword:
    """Test AsyncA2AContext password retrieval."""

    @pytest.mark.asyncio
    async def test_async_retrieve_password(self, a2a_env):
        async with AsyncA2AContext(a2a_env.host, a2a_env.cert_file, a2a_env.key_file, verify=a2a_env.verify) as a2a:
            pw = await a2a.retrieve_password(a2a_env.api_key)
            assert pw.value == a2a_env.original_password

    @pytest.mark.asyncio
    async def test_async_set_and_retrieve(self, a2a_env, _reset_password):
        async with AsyncA2AContext(a2a_env.host, a2a_env.cert_file, a2a_env.key_file, verify=a2a_env.verify) as a2a:
            await a2a.set_password(a2a_env.api_key, "AsyncChanged1!")
            pw = await a2a.retrieve_password(a2a_env.api_key)
            assert pw.value == "AsyncChanged1!"

    @pytest.mark.asyncio
    async def test_async_quick_retrieve_password(self, a2a_env):
        pw = await AsyncA2AContext.quick_retrieve_password(
            a2a_env.host,
            a2a_env.api_key,
            a2a_env.cert_file,
            a2a_env.key_file,
            verify=a2a_env.verify,
        )
        assert pw.value == a2a_env.original_password

    @pytest.mark.asyncio
    async def test_async_get_retrievable_accounts(self, a2a_env):
        async with AsyncA2AContext(a2a_env.host, a2a_env.cert_file, a2a_env.key_file, verify=a2a_env.verify) as a2a:
            accounts = await a2a.get_retrievable_accounts()
            assert len(accounts) >= 1


# ===========================================================================
# A2A event listener lifecycle tests
# ===========================================================================


class TestA2AEventListenerLifecycle:
    """Test A2A event listener connect/disconnect lifecycle.

    Note: Actual event reception depends on signalrcore protocol compatibility
    with the appliance version. These tests verify our A2A → SignalR wiring
    is correct through the connect/disconnect lifecycle.
    """

    def test_get_event_listener_returns_listener(self, a2a_env):
        """A2AContext.get_event_listener() returns a usable listener."""
        with A2AContext(a2a_env.host, a2a_env.cert_file, a2a_env.key_file, verify=a2a_env.verify) as a2a:
            listener = a2a.get_event_listener(a2a_env.api_key)
            assert isinstance(listener, SafeguardEventListener)
            assert listener._api_key == a2a_env.api_key

    def test_event_listener_start_stop(self, a2a_env):
        """A2A event listener can start and stop cleanly."""
        with A2AContext(a2a_env.host, a2a_env.cert_file, a2a_env.key_file, verify=a2a_env.verify) as a2a:
            listener = a2a.get_event_listener(a2a_env.api_key)
            try:
                listener.start()
                assert listener.is_started
            finally:
                listener.stop()
            assert not listener.is_started

    def test_event_listener_state_callback(self, a2a_env):
        """State callbacks fire during A2A listener lifecycle."""
        states: list[EventListenerState] = []
        with A2AContext(a2a_env.host, a2a_env.cert_file, a2a_env.key_file, verify=a2a_env.verify) as a2a:
            listener = a2a.get_event_listener(a2a_env.api_key)
            listener.on_state_change(lambda s: states.append(s))
            try:
                listener.start()
                assert EventListenerState.STARTING in states
                assert EventListenerState.CONNECTED in states
            finally:
                listener.stop()
            assert EventListenerState.STOPPED in states

    def test_persistent_event_listener_start_stop(self, a2a_env):
        """A2A persistent event listener can start and stop."""
        with A2AContext(a2a_env.host, a2a_env.cert_file, a2a_env.key_file, verify=a2a_env.verify) as a2a:
            listener = a2a.get_persistent_event_listener(a2a_env.api_key)
            assert isinstance(listener, PersistentSafeguardEventListener)
            try:
                listener.start()
                time.sleep(1)
                assert listener.is_started
            finally:
                listener.stop()
            assert not listener.is_started

    def test_persistent_event_listener_handler_registration(self, a2a_env):
        """Handlers can be registered on A2A persistent listener."""
        with A2AContext(a2a_env.host, a2a_env.cert_file, a2a_env.key_file, verify=a2a_env.verify) as a2a:
            listener = a2a.get_persistent_event_listener(a2a_env.api_key)
            result = listener.on("SomeEvent", lambda n, b: None)
            assert result is listener


# ===========================================================================
# User-mode event listener: get_persistent_event_listener() from client
# ===========================================================================


class TestClientPersistentEventListener:
    """Test the refactored generic get_persistent_event_listener() on SafeguardClient.

    This verifies the isinstance-free implementation that uses a generic
    token factory with any auth strategy that supports refresh.
    """

    def test_persistent_listener_from_password_auth(self, spp_host, spp_username, spp_password, spp_verify):
        """Client with PasswordAuth can create a persistent event listener."""
        client = SafeguardClient(
            spp_host,
            auth=PasswordAuth("local", spp_username, spp_password),
            verify=spp_verify,
        )
        client.login()
        listener = client.get_persistent_event_listener()
        assert isinstance(listener, PersistentSafeguardEventListener)

        # The listener should be able to start and connect
        states: list[EventListenerState] = []
        listener.on_state_change(lambda s: states.append(s))
        try:
            listener.start()
            time.sleep(2)
            assert listener.is_started
            assert EventListenerState.CONNECTED in states
        finally:
            listener.stop()

    def test_persistent_listener_token_factory_produces_valid_token(self, spp_host, spp_username, spp_password, spp_verify):
        """The generic token factory creates a valid user token."""
        client = SafeguardClient(
            spp_host,
            auth=PasswordAuth("local", spp_username, spp_password),
            verify=spp_verify,
        )
        client.login()
        listener = client.get_persistent_event_listener()

        # Call the token factory directly
        token = listener._token_factory()
        assert isinstance(token, str)
        assert len(token) > 20

        # Verify the token works for API calls
        token_client = SafeguardClient(spp_host, verify=spp_verify)
        from pysafeguard.auth import TokenAuth

        token_client._auth = TokenAuth(token)
        token_client.login()
        me = token_client.get(Service.CORE, "Me")
        assert me.status_code == 200

    def test_persistent_listener_handler_chaining(self, spp_host, spp_username, spp_password, spp_verify):
        """Fluent handler registration on the persistent listener."""
        client = SafeguardClient(
            spp_host,
            auth=PasswordAuth("local", spp_username, spp_password),
            verify=spp_verify,
        )
        client.login()
        listener = client.get_persistent_event_listener()
        result = listener.on("Event1", lambda n, b: None).on("Event2", lambda n, b: None).on_state_change(lambda s: None)
        assert result is listener
