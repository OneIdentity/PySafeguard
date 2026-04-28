"""Integration tests for streaming download/upload against a live Safeguard appliance.

Uses the Backups endpoint (``service/appliance/v4/Backups``) which supports
streaming download of backup files.  This is the same endpoint used by
SafeguardDotNet's streaming test suite.

Requires SPP_HOST, SPP_USERNAME, SPP_PASSWORD environment variables.
"""

from __future__ import annotations

import os
import tempfile

import pytest

from pysafeguard import AsyncConnection, HttpMethods, Services, connect_password

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def backup_id(spp_host, spp_username, spp_password, spp_verify):
    """Find an existing completed backup to use for download tests."""
    conn = connect_password(spp_host, spp_username, spp_password, verify=spp_verify)
    try:
        resp = conn.invoke(HttpMethods.GET, Services.APPLIANCE, "Backups")
        backups = resp.json()
        if not isinstance(backups, list) or not backups:
            pytest.skip("No backups available on appliance for streaming tests")
        # Prefer a completed backup
        completed = [b for b in backups if b.get("Status") == "Complete"]
        backup = completed[0] if completed else backups[0]
        return backup["Id"]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Sync streaming tests
# ---------------------------------------------------------------------------


class TestSyncInvokeStream:
    """Test Connection.invoke_stream() for streaming responses."""

    def test_stream_backup_download(self, sync_connection, backup_id):
        """invoke_stream returns a response that can be iterated in chunks."""
        resp = sync_connection.invoke_stream(
            HttpMethods.GET, Services.APPLIANCE, f"Backups/{backup_id}/Download"
        )
        assert resp.status_code == 200
        assert resp.headers.get("content-type") == "application/octet-stream"

        chunks = []
        for chunk in resp.iter_content(chunk_size=8192):
            chunks.append(chunk)
            if len(chunks) >= 3:
                break  # Don't download the whole backup
        resp.close()

        assert len(chunks) >= 1
        assert all(isinstance(c, bytes) for c in chunks)
        total = sum(len(c) for c in chunks)
        assert total > 0

    def test_stream_response_not_buffered(self, sync_connection, backup_id):
        """The streaming response should not pre-buffer the entire body."""
        resp = sync_connection.invoke_stream(
            HttpMethods.GET, Services.APPLIANCE, f"Backups/{backup_id}/Download"
        )
        assert resp.status_code == 200
        # content should not have been fully read yet
        assert resp._content_consumed is False
        resp.close()


class TestSyncDownload:
    """Test Connection.download() for file downloads."""

    def test_download_backup_to_file(self, sync_connection, backup_id):
        """download() writes the response body to a file."""
        with tempfile.NamedTemporaryFile(suffix=".sgb", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            written = sync_connection.download(
                Services.APPLIANCE,
                f"Backups/{backup_id}/Download",
                tmp_path,
            )
            assert written > 0
            assert os.path.getsize(tmp_path) == written
        finally:
            os.unlink(tmp_path)

    def test_download_partial_with_small_chunks(self, sync_connection, backup_id):
        """download() respects the chunk_size parameter."""
        with tempfile.NamedTemporaryFile(suffix=".sgb", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            written = sync_connection.download(
                Services.APPLIANCE,
                f"Backups/{backup_id}/Download",
                tmp_path,
                chunk_size=4096,
            )
            assert written > 0
            assert os.path.getsize(tmp_path) == written
        finally:
            os.unlink(tmp_path)


class TestSyncUpload:
    """Test Connection.upload() for file uploads."""

    def test_upload_bytes(self, sync_connection):
        """upload() can send raw bytes to an endpoint.

        We use a non-streaming endpoint (POST to a known safe path) to
        verify the upload mechanics work. Backup upload requires a valid
        .sgb file so we test the transport only.
        """
        # Upload a small payload to verify the method works without error.
        # We POST to Backups/Upload which will reject invalid content,
        # but the transport layer (headers, auth, cert) should work.
        resp = sync_connection.upload(
            Services.APPLIANCE,
            "Backups/Upload",
            b"not-a-real-backup",
            content_type="application/octet-stream",
        )
        # The appliance should reject this with a 4xx, not a transport error
        assert resp.status_code in (400, 403, 409, 415, 500)

    def test_upload_from_file(self, sync_connection):
        """upload() can stream from a file path."""
        with tempfile.NamedTemporaryFile(suffix=".sgb", delete=False) as tmp:
            tmp.write(b"not-a-real-backup-file-content")
            tmp_path = tmp.name

        try:
            resp = sync_connection.upload(
                Services.APPLIANCE,
                "Backups/Upload",
                tmp_path,
                content_type="application/octet-stream",
            )
            assert resp.status_code in (400, 403, 409, 415, 500)
        finally:
            os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Async streaming tests
# ---------------------------------------------------------------------------


class TestAsyncInvokeStream:
    """Test AsyncConnection.invoke_stream() for streaming responses."""

    @pytest.mark.asyncio
    async def test_stream_backup_download(self, spp_host, spp_username, spp_password, spp_verify, backup_id):
        """invoke_stream returns a response that can be iterated in chunks."""
        conn = AsyncConnection(spp_host, verify=spp_verify)
        await conn.connect_password(spp_username, spp_password)
        try:
            resp = await conn.invoke_stream(
                HttpMethods.GET, Services.APPLIANCE, f"Backups/{backup_id}/Download"
            )
            assert resp.status == 200

            chunks = []
            async for chunk in resp.content.iter_chunked(8192):
                chunks.append(chunk)
                if len(chunks) >= 3:
                    break
            resp.release()

            assert len(chunks) >= 1
            total = sum(len(c) for c in chunks)
            assert total > 0
        finally:
            await conn.close()


class TestAsyncDownload:
    """Test AsyncConnection.download() for file downloads."""

    @pytest.mark.asyncio
    async def test_download_backup_to_file(self, spp_host, spp_username, spp_password, spp_verify, backup_id):
        """download() writes the response body to a file."""
        conn = AsyncConnection(spp_host, verify=spp_verify)
        await conn.connect_password(spp_username, spp_password)

        with tempfile.NamedTemporaryFile(suffix=".sgb", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            written = await conn.download(
                Services.APPLIANCE,
                f"Backups/{backup_id}/Download",
                tmp_path,
            )
            assert written > 0
            assert os.path.getsize(tmp_path) == written
        finally:
            os.unlink(tmp_path)
            await conn.close()


class TestAsyncUpload:
    """Test AsyncConnection.upload() for file uploads."""

    @pytest.mark.asyncio
    async def test_upload_bytes(self, spp_host, spp_username, spp_password, spp_verify):
        """upload() can send raw bytes."""
        conn = AsyncConnection(spp_host, verify=spp_verify)
        await conn.connect_password(spp_username, spp_password)
        try:
            resp = await conn.upload(
                Services.APPLIANCE,
                "Backups/Upload",
                b"not-a-real-backup",
                content_type="application/octet-stream",
            )
            assert resp.status in (400, 403, 409, 415, 500)
        finally:
            await conn.close()
