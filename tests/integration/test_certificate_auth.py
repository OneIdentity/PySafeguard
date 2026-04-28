"""Integration tests for CertificateAuth login.

Creates a self-signed certificate, uploads it to TrustedCertificates,
creates a certificate user linked to the cert, and verifies that
CertificateAuth login/refresh works for both sync and async clients.

All resources use the PySg_ naming prefix and are cleaned up after the module.

Requires SPP_HOST, SPP_USERNAME, SPP_PASSWORD environment variables.
"""

from __future__ import annotations

import base64
import hashlib
import os
import ssl
import subprocess
import tempfile

import pytest

from pysafeguard import (
    AsyncSafeguardClient,
    CertificateAuth,
    PasswordAuth,
    SafeguardClient,
    Service,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Fixture: certificate environment (module-scoped)
# ---------------------------------------------------------------------------


class _CertEnv:
    """Holds all IDs and paths needed by certificate auth tests."""

    host: str
    verify: bool | str
    cert_file: str
    key_file: str
    thumbprint: str
    cert_user_id: int
    tmpdir: str


@pytest.fixture(scope="module")
def cert_env(spp_host, spp_username, spp_password, spp_verify):
    """Create a certificate user environment; tear it down after the module."""
    env = _CertEnv()
    env.host = spp_host
    env.verify = spp_verify

    admin = SafeguardClient(spp_host, auth=PasswordAuth("local", spp_username, spp_password), verify=spp_verify)
    admin.login()

    # --- generate self-signed certificate ---
    env.tmpdir = tempfile.mkdtemp(prefix="pysafeguard_cert_")
    env.key_file = os.path.join(env.tmpdir, "key.pem")
    env.cert_file = os.path.join(env.tmpdir, "cert.pem")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", env.key_file, "-out", env.cert_file,
            "-days", "1", "-nodes", "-subj", "/CN=PySg_CertAuthTest",
        ],
        capture_output=True,
        check=True,
    )
    der = ssl.PEM_cert_to_DER_cert(open(env.cert_file).read())
    env.thumbprint = hashlib.sha1(der).hexdigest().upper()

    # --- upload to trusted store ---
    b64cert = base64.b64encode(der).decode()
    r = admin.post(Service.CORE, "TrustedCertificates", json={"Base64CertificateData": b64cert})
    assert r.status_code == 201, f"Upload trusted cert failed: {r.text[:300]}"

    # --- create certificate user ---
    r = admin.post(
        Service.CORE,
        "Users",
        json={
            "Name": "PySg_CertAuthUser",
            "PrimaryAuthenticationProvider": {"Id": -2, "Identity": env.thumbprint},
            "AdminRoles": ["Auditor"],
        },
    )
    assert r.status_code == 201, f"Create cert user failed: {r.text[:300]}"
    env.cert_user_id = r.json()["Id"]

    yield env

    # --- teardown ---
    def _safe(fn):
        try:
            fn()
        except Exception as e:
            print(f"Warning: cleanup failed: {e}")

    _safe(lambda: admin.delete(Service.CORE, f"Users/{env.cert_user_id}"))
    _safe(lambda: admin.delete(Service.CORE, f"TrustedCertificates/{env.thumbprint}"))

    import shutil
    shutil.rmtree(env.tmpdir, ignore_errors=True)


# ===========================================================================
# Sync CertificateAuth tests
# ===========================================================================


class TestSyncCertificateAuth:
    """Test CertificateAuth with SafeguardClient."""

    def test_login_with_certificate(self, cert_env):
        """CertificateAuth login succeeds and provides a user token."""
        client = SafeguardClient(
            cert_env.host,
            auth=CertificateAuth(cert_env.cert_file, cert_env.key_file),
            verify=cert_env.verify,
        )
        client.login()
        assert client.user_token is not None
        assert client.is_authenticated

    def test_me_endpoint_with_certificate(self, cert_env):
        """Authenticated cert user can call Me endpoint."""
        client = SafeguardClient(
            cert_env.host,
            auth=CertificateAuth(cert_env.cert_file, cert_env.key_file),
            verify=cert_env.verify,
        )
        client.login()
        resp = client.get(Service.CORE, "Me")
        assert resp.status_code == 200
        me = resp.json()
        assert me["Name"] == "PySg_CertAuthUser"

    def test_refresh_with_certificate(self, cert_env):
        """CertificateAuth can refresh and get a new token."""
        client = SafeguardClient(
            cert_env.host,
            auth=CertificateAuth(cert_env.cert_file, cert_env.key_file),
            verify=cert_env.verify,
        )
        client.login()
        original_token = client.user_token

        client.refresh_access_token()
        assert client.user_token is not None
        assert client.user_token != original_token

        resp = client.get(Service.CORE, "Me")
        assert resp.status_code == 200

    def test_context_manager_with_certificate(self, cert_env):
        """Context manager does login+logout for CertificateAuth."""
        with SafeguardClient(
            cert_env.host,
            auth=CertificateAuth(cert_env.cert_file, cert_env.key_file),
            verify=cert_env.verify,
        ) as client:
            assert client.is_authenticated
            resp = client.get(Service.CORE, "Me")
            assert resp.status_code == 200

    def test_can_refresh_is_true(self, cert_env):
        """CertificateAuth.can_refresh should be True."""
        auth = CertificateAuth(cert_env.cert_file, cert_env.key_file)
        assert auth.can_refresh is True


# ===========================================================================
# Async CertificateAuth tests
# ===========================================================================


class TestAsyncCertificateAuth:
    """Test CertificateAuth with AsyncSafeguardClient."""

    @pytest.mark.asyncio
    async def test_async_login_with_certificate(self, cert_env):
        """CertificateAuth async login succeeds."""
        client = AsyncSafeguardClient(
            cert_env.host,
            auth=CertificateAuth(cert_env.cert_file, cert_env.key_file),
            verify=cert_env.verify,
        )
        await client.login()
        assert client.user_token is not None
        assert client.is_authenticated
        await client.close()

    @pytest.mark.asyncio
    async def test_async_me_endpoint(self, cert_env):
        """Authenticated async cert client can call Me endpoint."""
        async with AsyncSafeguardClient(
            cert_env.host,
            auth=CertificateAuth(cert_env.cert_file, cert_env.key_file),
            verify=cert_env.verify,
        ) as client:
            resp = await client.get(Service.CORE, "Me")
            assert resp.status == 200
            me = await resp.json()
            assert me["Name"] == "PySg_CertAuthUser"

    @pytest.mark.asyncio
    async def test_async_refresh_with_certificate(self, cert_env):
        """CertificateAuth async refresh produces a new valid token."""
        client = AsyncSafeguardClient(
            cert_env.host,
            auth=CertificateAuth(cert_env.cert_file, cert_env.key_file),
            verify=cert_env.verify,
        )
        await client.login()
        original_token = client.user_token

        await client.refresh_access_token()
        assert client.user_token is not None
        assert client.user_token != original_token

        resp = await client.get(Service.CORE, "Me")
        assert resp.status == 200
        await client.close()

    @pytest.mark.asyncio
    async def test_async_context_manager(self, cert_env):
        """Async context manager handles login/logout for cert auth."""
        async with AsyncSafeguardClient(
            cert_env.host,
            auth=CertificateAuth(cert_env.cert_file, cert_env.key_file),
            verify=cert_env.verify,
        ) as client:
            assert client.is_authenticated
            resp = await client.get(Service.CORE, "Me")
            assert resp.status == 200
