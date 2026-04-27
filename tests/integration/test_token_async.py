"""Integration tests: async token lifetime and provider lookup."""

import pytest

pytestmark = pytest.mark.integration


class TestAsyncTokenLifetime:
    @pytest.mark.asyncio
    async def test_get_remaining_token_lifetime(self, async_connection):
        remaining = await async_connection.get_remaining_token_lifetime()
        assert remaining is not None
        assert isinstance(remaining, int)
        assert remaining > 0


class TestAsyncProviderLookup:
    @pytest.mark.asyncio
    async def test_get_provider_id_local(self, async_connection):
        provider_id = await async_connection.get_provider_id("Local")
        assert provider_id is not None
        assert len(provider_id) > 0

    @pytest.mark.asyncio
    async def test_get_provider_id_not_found(self, async_connection):
        with pytest.raises(Exception, match="Unable to find Provider"):
            await async_connection.get_provider_id("NonexistentProvider_XYZ_999")
