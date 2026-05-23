# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Regression tests pinning floor versions of security-sensitive transitive deps.

These tests guard against poetry resolving urllib3 or idna below the floor that
fixes the CVEs referenced in the Phase 1 security review fix plan.
"""

from __future__ import annotations

from packaging.version import Version


def test_urllib3_minimum_version() -> None:
    """urllib3 must be >= 2.0.8 (CVE-2026-44431 DNS rebinding, CVE-2026-44432 proxy confusion)."""
    import urllib3

    assert Version(urllib3.__version__) >= Version("2.0.8"), (
        f"urllib3 {urllib3.__version__} is below 2.0.8 (CVE-2026-44431/44432 fix)"
    )


def test_idna_minimum_version() -> None:
    """idna must be >= 3.7 (CVE-2026-45409 ReDoS)."""
    import idna

    assert Version(idna.__version__) >= Version("3.7"), (
        f"idna {idna.__version__} is below 3.7 (CVE-2026-45409 fix)"
    )
