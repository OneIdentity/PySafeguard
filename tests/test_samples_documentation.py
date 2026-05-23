# Copyright (c) One Identity LLC. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Verify sample code includes production-security guidance for insecure flags."""

from __future__ import annotations

from pathlib import Path

SAMPLES_DIR = Path(__file__).parent.parent / "samples"
README = Path(__file__).parent.parent / "README.md"


def test_anonymous_example_has_tls_warning() -> None:
    """AnonymousExample.py uses verify=False but must explain why and how to fix in production."""
    example = SAMPLES_DIR / "AnonymousExample.py"
    assert example.exists(), "samples/AnonymousExample.py not found"
    content = example.read_text(encoding="utf-8")

    assert "verify=False" in content, "Sample must demonstrate verify=False for dev/test usage"

    # The sample must include at least one of these context cues near the insecure flag
    # so a developer copying it knows it is intentional and what to do in production.
    cues = ("WARNING", "production", "self-signed", "REQUESTS_CA_BUNDLE")
    assert any(cue in content for cue in cues), f"Sample must include guidance about verify=False usage; expected one of {cues}"


def test_readme_has_tls_verification_section() -> None:
    """README.md must include a TLS verification section that documents verify=."""
    assert README.exists(), "README.md not found"
    content = README.read_text(encoding="utf-8")
    assert "TLS Verification" in content, "README.md must contain a 'TLS Verification' section"
    assert "verify=False" in content, "TLS Verification section must mention verify=False"
    assert "REQUESTS_CA_BUNDLE" in content or "CA bundle" in content, (
        "TLS Verification section must reference CA bundle / REQUESTS_CA_BUNDLE for production guidance"
    )
