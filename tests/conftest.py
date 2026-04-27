"""Root conftest — shared fixtures and marker registration for PySafeguard tests."""

import os

import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "integration: tests that require a live Safeguard appliance (set SPP_HOST)")


# ---------------------------------------------------------------------------
# Session-scoped appliance configuration (immutable)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def spp_host() -> str:
    """Appliance hostname / IP from environment."""
    return os.environ.get("SPP_HOST", "")


@pytest.fixture(scope="session")
def spp_username() -> str:
    return os.environ.get("SPP_USERNAME", "Admin")


@pytest.fixture(scope="session")
def spp_password() -> str:
    return os.environ.get("SPP_PASSWORD", "")


@pytest.fixture(scope="session")
def spp_verify() -> bool | str:
    """Return CA file path if set, otherwise False (disable TLS verify)."""
    ca = os.environ.get("SPP_CA_FILE", "")
    if ca:
        return ca
    return False


# ---------------------------------------------------------------------------
# Auto-skip integration tests when appliance is not configured
# ---------------------------------------------------------------------------


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    skip_integration = pytest.mark.skip(reason="SPP_HOST not set — skipping live appliance tests")
    for item in items:
        if "integration" in item.keywords and not os.environ.get("SPP_HOST"):
            item.add_marker(skip_integration)
