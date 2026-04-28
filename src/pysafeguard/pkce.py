"""PKCE non-interactive login for Safeguard.

Programmatically drives the browser-based OAuth2/PKCE flow by directly
interacting with the Safeguard rSTS login endpoints. Supports primary
(password) and secondary (MFA/TOTP) authentication.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from urllib.parse import parse_qs, urlparse

from requests import Response, Session

from .errors import SafeguardError

DEFAULT_TIMEOUT = 300

REDIRECT_URI = "urn:InstalledApplication"

_STEP_INIT = "1"
_STEP_PRIMARY_AUTH = "3"
_STEP_SECONDARY_INIT = "7"
_STEP_SECONDARY_AUTH = "5"
_STEP_GENERATE_CLAIMS = "6"


def get_pkce_token(
    appliance: str,
    provider: str,
    username: str,
    password: str,
    secondary_password: str | None = None,
    verify: bool | str = True,
    api_version: str = "v4",
) -> str:
    """Perform the PKCE authentication flow and return a Safeguard user token.

    This is the low-level entry point that returns a raw token string.
    Most callers should use :func:`connect_pkce` instead.

    :param appliance: Network address (hostname or IP) of the Safeguard appliance.
    :param provider: Authentication provider name (e.g. ``"local"``).
    :param username: Username for authentication.
    :param password: Password for authentication.
    :param secondary_password: One-time password for MFA (e.g. TOTP code), or ``None`` if not required.
    :param verify: A path to a CA certificate file, or ``False`` to disable TLS verification.
    :param api_version: API version to use (default ``"v4"``).
    :returns: A Safeguard user token string.
    :raises SafeguardError: If authentication fails.
    """
    csrf_token = _generate_csrf_token()
    code_verifier = _generate_code_verifier()
    code_challenge = _generate_code_challenge(code_verifier)

    hostname = _parse_hostname(appliance)

    with Session() as session:
        session.verify = verify
        session.cookies.set("CsrfToken", csrf_token, domain=hostname, path="/RSTS")

        identity_provider = _resolve_identity_provider(session, appliance, api_version, provider, verify)

        form_data: dict[str, str] = {
            "directoryComboBox": identity_provider,
            "usernameTextbox": username,
            "passwordTextbox": password,
            "csrfTokenTextbox": csrf_token,
        }

        pkce_base_url = (
            f"https://{appliance}/RSTS/UserLogin/LoginController?"
            f"response_type=code&code_challenge_method=S256&"
            f"code_challenge={code_challenge}&redirect_uri={REDIRECT_URI}&loginRequestStep="
        )

        # Step 1: Provider initialization
        _rsts_request(session, pkce_base_url + _STEP_INIT, form_data)

        # Step 3: Primary authentication
        primary_resp = _rsts_request(session, pkce_base_url + _STEP_PRIMARY_AUTH, form_data)

        # Handle MFA if the primary auth response indicates a secondary provider
        _handle_secondary_auth(session, pkce_base_url, form_data, primary_resp, secondary_password)

        # Step 6: Generate claims and extract authorization code
        claims_resp = _rsts_request(session, pkce_base_url + _STEP_GENERATE_CLAIMS, form_data)
        if claims_resp.status_code != 200:
            raise SafeguardError(
                f"Failed to generate claims: {claims_resp.text}",
                status_code=claims_resp.status_code,
                response_body=claims_resp.text,
            )

        auth_code = _extract_authorization_code(claims_resp.text)

        # Exchange authorization code for rSTS access token
        rsts_access_token = _post_authorization_code(session, appliance, auth_code, code_verifier)

        # Exchange rSTS token for Safeguard user token
        return _post_login_response(session, appliance, rsts_access_token, api_version)


# ---------------------------------------------------------------------------
# PKCE crypto helpers
# ---------------------------------------------------------------------------


def _base64url(data: bytes) -> str:
    """Base64url-encode bytes without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _generate_csrf_token() -> str:
    """Generate a 32-byte random CSRF token, base64url-encoded."""
    return _base64url(os.urandom(32))


def _generate_code_verifier() -> str:
    """Generate a 60-byte random PKCE code verifier, base64url-encoded."""
    return _base64url(os.urandom(60))


def _generate_code_challenge(code_verifier: str) -> str:
    """Generate a PKCE code challenge (S256) from a code verifier."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return _base64url(digest)


def _parse_hostname(appliance: str) -> str:
    """Extract the hostname from an appliance address, stripping any port."""
    if ":" in appliance:
        host, _, _ = appliance.partition(":")
        return host
    return appliance


# ---------------------------------------------------------------------------
# rSTS request helpers
# ---------------------------------------------------------------------------


def _rsts_request(session: Session, url: str, form_data: dict[str, str]) -> Response:
    """POST form data to an rSTS login controller URL.

    Returns the response. Raises :class:`SafeguardError` for HTTP errors
    (4xx/5xx), but allows 200 and 203 through (203 is used by rSTS for
    challenges and non-fatal status).
    """
    resp = session.post(
        url,
        data=form_data,
        headers={"Accept": "application/json"},
        timeout=DEFAULT_TIMEOUT,
    )

    status = resp.status_code
    if not (200 <= status < 300):
        error_message = resp.text.strip() if resp.text.strip() else str(status)
        raise SafeguardError(
            f"rSTS authentication error: {error_message}",
            status_code=status,
            response_body=resp.text,
        )

    return resp


def _handle_secondary_auth(
    session: Session,
    pkce_base_url: str,
    form_data: dict[str, str],
    primary_resp: Response,
    secondary_password: str | None,
) -> None:
    """Handle MFA if the primary auth response indicates a secondary provider."""
    try:
        primary_data: object = json.loads(primary_resp.text)
    except (json.JSONDecodeError, TypeError):
        return  # Non-JSON response means no secondary auth info

    if not isinstance(primary_data, dict):
        return

    secondary_provider_id = primary_data.get("SecondaryProviderID")
    if not secondary_provider_id:
        return

    if secondary_password is None:
        raise SafeguardError(
            f"Multi-factor authentication is required (provider: {secondary_provider_id}) "
            "but no secondary password was provided. Pass secondary_password to supply the one-time code."
        )

    # Step 7: Initialize secondary provider
    init_resp = _rsts_request(session, pkce_base_url + _STEP_SECONDARY_INIT, form_data)

    mfa_state = ""
    if init_resp.status_code in (200, 203):
        try:
            init_data: object = json.loads(init_resp.text)
            if isinstance(init_data, dict):
                mfa_state = str(init_data.get("State", ""))
        except (json.JSONDecodeError, TypeError):
            pass

    # Step 5: Submit secondary authentication
    mfa_form_data = {
        **form_data,
        "secondaryLoginTextbox": secondary_password,
        "secondaryAuthenticationStateTextbox": mfa_state,
    }

    mfa_resp = _rsts_request(session, pkce_base_url + _STEP_SECONDARY_AUTH, mfa_form_data)

    # Step 5 returns empty on success, or 203 with error details on failure
    if mfa_resp.status_code == 203:
        error_message = "Secondary authentication failed."
        try:
            mfa_data: object = json.loads(mfa_resp.text)
            if isinstance(mfa_data, dict) and "Message" in mfa_data:
                error_message = str(mfa_data["Message"])
        except (json.JSONDecodeError, TypeError):
            if mfa_resp.text:
                error_message = mfa_resp.text
        raise SafeguardError(f"Multi-factor authentication failed: {error_message}")

    if not (200 <= mfa_resp.status_code < 300):
        raise SafeguardError(
            f"Multi-factor authentication failed: {mfa_resp.text}",
            status_code=mfa_resp.status_code,
            response_body=mfa_resp.text,
        )


# ---------------------------------------------------------------------------
# Authorization code and token exchange
# ---------------------------------------------------------------------------


def _extract_authorization_code(response_body: str) -> str:
    """Parse the authorization code from the rSTS GenerateClaims response."""
    try:
        data: object = json.loads(response_body)
    except (json.JSONDecodeError, TypeError) as ex:
        raise SafeguardError("Failed to parse authorization code from rSTS response") from ex

    if not isinstance(data, dict):
        raise SafeguardError("Failed to parse authorization code from rSTS response")

    relying_party_url = data.get("RelyingPartyUrl")
    if not relying_party_url or not isinstance(relying_party_url, str):
        raise SafeguardError("rSTS response did not contain a RelyingPartyUrl. The authentication process may be incomplete.")

    parsed = urlparse(relying_party_url)
    params = parse_qs(parsed.query)
    codes = params.get("code", [])
    if not codes:
        raise SafeguardError("rSTS response did not contain an authorization code")

    return codes[0]


def _resolve_identity_provider(session: Session, appliance: str, api_version: str, provider: str, verify: bool | str) -> str:
    """Resolve a provider name/ID to an rSTS provider ID.

    Matches by: exact RstsProviderId, then exact Name, then substring of RstsProviderId.
    """
    url = f"https://{appliance}/service/core/{api_version}/AuthenticationProviders"
    resp = session.get(url, headers={"Accept": "application/json"}, timeout=DEFAULT_TIMEOUT)

    if not resp.ok:
        raise SafeguardError(
            f"Failed to retrieve authentication providers: {resp.status_code} {resp.text}",
            status_code=resp.status_code,
            response_body=resp.text,
        )

    providers: object = resp.json()
    if not isinstance(providers, list):
        raise SafeguardError("Unexpected response from AuthenticationProviders endpoint")

    provider_lower = provider.lower()

    # Match by exact RstsProviderId (case-insensitive)
    for p in providers:
        if isinstance(p, dict):
            rsts_id = str(p.get("RstsProviderId", ""))
            if rsts_id.lower() == provider_lower:
                return rsts_id

    # Match by exact Name (case-insensitive)
    for p in providers:
        if isinstance(p, dict):
            name = str(p.get("Name", ""))
            if name.lower() == provider_lower:
                return str(p.get("RstsProviderId", ""))

    # Match by substring of RstsProviderId (case-insensitive)
    for p in providers:
        if isinstance(p, dict):
            rsts_id = str(p.get("RstsProviderId", ""))
            if provider_lower in rsts_id.lower():
                return rsts_id

    known = [f"{p.get('Name', '?')} ({p.get('RstsProviderId', '?')})" for p in providers if isinstance(p, dict)]
    raise SafeguardError(f"Unable to find provider matching '{provider}' in [{', '.join(known)}]")


def _post_authorization_code(session: Session, appliance: str, code: str, code_verifier: str) -> str:
    """Exchange an authorization code for an rSTS access token."""
    url = f"https://{appliance}/RSTS/oauth2/token"
    body = {
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
        "code": code,
        "code_verifier": code_verifier,
    }

    resp = session.post(url, json=body, headers={"Accept": "application/json"}, timeout=DEFAULT_TIMEOUT)

    if not resp.ok:
        raise SafeguardError(
            f"Failed to exchange authorization code: {resp.status_code} {resp.text}",
            status_code=resp.status_code,
            response_body=resp.text,
        )

    data: object = resp.json()
    if not isinstance(data, dict):
        raise SafeguardError("Unexpected response from RSTS token endpoint")

    access_token = data.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise SafeguardError("RSTS response did not contain an access_token")

    return access_token


def _post_login_response(session: Session, appliance: str, rsts_token: str, api_version: str) -> str:
    """Exchange an rSTS access token for a Safeguard user token."""
    url = f"https://{appliance}/service/core/{api_version}/Token/LoginResponse"
    body = {"StsAccessToken": rsts_token}

    resp = session.post(url, json=body, headers={"Accept": "application/json"}, timeout=DEFAULT_TIMEOUT)

    if not resp.ok:
        raise SafeguardError(
            f"Failed to exchange RSTS token: {resp.status_code} {resp.text}",
            status_code=resp.status_code,
            response_body=resp.text,
        )

    data: object = resp.json()
    if not isinstance(data, dict):
        raise SafeguardError("Unexpected response from Token/LoginResponse endpoint")

    status = data.get("Status")
    if status != "Success":
        raise SafeguardError(f"Error exchanging RSTS token, status: {status}")

    user_token = data.get("UserToken")
    if not isinstance(user_token, str) or not user_token:
        raise SafeguardError("LoginResponse did not contain a UserToken")

    return user_token
