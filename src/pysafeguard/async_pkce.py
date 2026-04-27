"""Async PKCE non-interactive login for Safeguard.

Async mirror of :mod:`pysafeguard.pkce`. Programmatically drives the
browser-based OAuth2/PKCE flow using ``aiohttp`` instead of ``requests``.
"""

from __future__ import annotations

import json
import ssl

from aiohttp import ClientSession, ClientTimeout, CookieJar
from truststore import SSLContext

from .async_connection import AsyncConnection, DEFAULT_TIMEOUT, _AsyncPkceCredential
from .exceptions import SafeguardException
from .hidden_string import HiddenString
from .pkce import (
    REDIRECT_URI,
    _STEP_GENERATE_CLAIMS,
    _STEP_INIT,
    _STEP_PRIMARY_AUTH,
    _STEP_SECONDARY_AUTH,
    _STEP_SECONDARY_INIT,
    _extract_authorization_code,
    _generate_code_challenge,
    _generate_code_verifier,
    _generate_csrf_token,
)


def _create_ssl_context(verify: bool | str) -> ssl.SSLContext | bool:
    """Build an SSL context for the PKCE session."""
    if verify is False:
        return False
    ctx = SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if isinstance(verify, str):
        ctx.load_verify_locations(verify)
    return ctx


async def async_get_pkce_token(
    appliance: str,
    provider: str,
    username: str,
    password: str,
    secondary_password: str | None = None,
    verify: bool | str = True,
    api_version: str = "v4",
) -> str:
    """Async PKCE authentication flow returning a Safeguard user token.

    :param appliance: Network address (hostname or IP) of the Safeguard appliance.
    :param provider: Authentication provider name (e.g. ``"local"``).
    :param username: Username for authentication.
    :param password: Password for authentication.
    :param secondary_password: One-time password for MFA, or ``None``.
    :param verify: CA certificate path or ``False`` to disable TLS verification.
    :param api_version: API version to use (default ``"v4"``).
    :returns: A Safeguard user token string.
    :raises SafeguardException: If authentication fails.
    """
    csrf_token = _generate_csrf_token()
    code_verifier = _generate_code_verifier()
    code_challenge = _generate_code_challenge(code_verifier)

    ssl_context = _create_ssl_context(verify)
    timeout = ClientTimeout(total=DEFAULT_TIMEOUT)

    jar = CookieJar(unsafe=True)
    jar.update_cookies({"CsrfToken": csrf_token})

    async with ClientSession(cookie_jar=jar) as session:
        identity_provider = await _async_resolve_identity_provider(session, appliance, api_version, provider, ssl_context, timeout)

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
        await _async_rsts_request(session, pkce_base_url + _STEP_INIT, form_data, ssl_context, timeout)

        # Step 3: Primary authentication
        primary_resp_text, primary_status = await _async_rsts_request(session, pkce_base_url + _STEP_PRIMARY_AUTH, form_data, ssl_context, timeout)

        # Handle MFA if needed
        await _async_handle_secondary_auth(session, pkce_base_url, form_data, primary_resp_text, secondary_password, ssl_context, timeout)

        # Step 6: Generate claims
        claims_text, claims_status = await _async_rsts_request(session, pkce_base_url + _STEP_GENERATE_CLAIMS, form_data, ssl_context, timeout)
        if claims_status != 200:
            raise SafeguardException(
                f"Failed to generate claims: {claims_text}",
                status_code=claims_status,
                response=claims_text,
            )

        auth_code = _extract_authorization_code(claims_text)

        rsts_access_token = await _async_post_authorization_code(session, appliance, auth_code, code_verifier, ssl_context, timeout)

        return await _async_post_login_response(session, appliance, rsts_access_token, api_version, ssl_context, timeout)


async def async_connect_pkce(
    appliance: str,
    provider: str,
    username: str,
    password: str,
    secondary_password: str | None = None,
    verify: bool | str = True,
    api_version: str = "v4",
) -> AsyncConnection:
    """Connect to Safeguard using async PKCE non-interactive login.

    :param appliance: Network address (hostname or IP) of the Safeguard appliance.
    :param provider: Authentication provider name (e.g. ``"local"``).
    :param username: Username for authentication.
    :param password: Password for authentication.
    :param secondary_password: One-time password for MFA, or ``None``.
    :param verify: CA certificate path or ``False`` to disable TLS verification.
    :param api_version: API version to use (default ``"v4"``).
    :returns: An authenticated :class:`AsyncConnection`.
    :raises SafeguardException: If authentication fails.
    """
    user_token = await async_get_pkce_token(appliance, provider, username, password, secondary_password, verify, api_version)

    conn = AsyncConnection(appliance, verify=verify, apiVersion=api_version)
    conn._set_user_token(user_token)

    secure_secondary = HiddenString(secondary_password) if secondary_password is not None else None
    conn._replace_auth_credential(  # noqa: SLF001
        _AsyncPkceCredential(provider, username, HiddenString(password), secure_secondary)
    )
    return conn


# ---------------------------------------------------------------------------
# Async rSTS request helpers
# ---------------------------------------------------------------------------


async def _async_rsts_request(
    session: ClientSession,
    url: str,
    form_data: dict[str, str],
    ssl_context: ssl.SSLContext | bool,
    timeout: ClientTimeout,
) -> tuple[str, int]:
    """POST form data to rSTS. Returns (response_text, status_code)."""
    async with session.post(
        url,
        data=form_data,
        headers={"Accept": "application/json"},
        ssl=ssl_context,
        timeout=timeout,
    ) as resp:
        text = await resp.text()
        status = resp.status

    if not (200 <= status < 300) and status != 203:
        error_message = text.strip() if text.strip() else str(status)
        raise SafeguardException(
            f"rSTS authentication error: {error_message}",
            status_code=status,
            response=text,
        )

    return text, status


async def _async_handle_secondary_auth(
    session: ClientSession,
    pkce_base_url: str,
    form_data: dict[str, str],
    primary_resp_text: str,
    secondary_password: str | None,
    ssl_context: ssl.SSLContext | bool,
    timeout: ClientTimeout,
) -> None:
    """Handle MFA if the primary auth response indicates a secondary provider."""
    try:
        primary_data: object = json.loads(primary_resp_text)
    except (json.JSONDecodeError, TypeError):
        return

    if not isinstance(primary_data, dict):
        return

    secondary_provider_id = primary_data.get("SecondaryProviderID")
    if not secondary_provider_id:
        return

    if secondary_password is None:
        raise SafeguardException(
            f"Multi-factor authentication is required (provider: {secondary_provider_id}) "
            "but no secondary password was provided. Pass secondary_password to supply the one-time code."
        )

    # Step 7: Initialize secondary provider
    init_text, init_status = await _async_rsts_request(session, pkce_base_url + _STEP_SECONDARY_INIT, form_data, ssl_context, timeout)

    mfa_state = ""
    if init_status in (200, 203):
        try:
            init_data: object = json.loads(init_text)
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

    mfa_text, mfa_status = await _async_rsts_request(session, pkce_base_url + _STEP_SECONDARY_AUTH, mfa_form_data, ssl_context, timeout)

    if mfa_status == 203:
        error_message = "Secondary authentication failed."
        try:
            mfa_data: object = json.loads(mfa_text)
            if isinstance(mfa_data, dict) and "Message" in mfa_data:
                error_message = str(mfa_data["Message"])
        except (json.JSONDecodeError, TypeError):
            if mfa_text:
                error_message = mfa_text
        raise SafeguardException(f"Multi-factor authentication failed: {error_message}")

    if not (200 <= mfa_status < 300):
        raise SafeguardException(
            f"Multi-factor authentication failed: {mfa_text}",
            status_code=mfa_status,
            response=mfa_text,
        )


# ---------------------------------------------------------------------------
# Async token exchange
# ---------------------------------------------------------------------------


async def _async_resolve_identity_provider(
    session: ClientSession,
    appliance: str,
    api_version: str,
    provider: str,
    ssl_context: ssl.SSLContext | bool,
    timeout: ClientTimeout,
) -> str:
    """Resolve a provider name/ID to an rSTS provider ID (async)."""
    url = f"https://{appliance}/service/core/{api_version}/AuthenticationProviders"
    async with session.get(url, headers={"Accept": "application/json"}, ssl=ssl_context, timeout=timeout) as resp:
        if resp.status >= 400:
            text = await resp.text()
            raise SafeguardException(
                f"Failed to retrieve authentication providers: {resp.status} {text}",
                status_code=resp.status,
                response=text,
            )
        providers: object = await resp.json()

    if not isinstance(providers, list):
        raise SafeguardException("Unexpected response from AuthenticationProviders endpoint")

    provider_lower = provider.lower()

    for p in providers:
        if isinstance(p, dict):
            rsts_id = str(p.get("RstsProviderId", ""))
            if rsts_id.lower() == provider_lower:
                return rsts_id

    for p in providers:
        if isinstance(p, dict):
            name = str(p.get("Name", ""))
            if name.lower() == provider_lower:
                return str(p.get("RstsProviderId", ""))

    for p in providers:
        if isinstance(p, dict):
            rsts_id = str(p.get("RstsProviderId", ""))
            if provider_lower in rsts_id.lower():
                return rsts_id

    known = [f"{p.get('Name', '?')} ({p.get('RstsProviderId', '?')})" for p in providers if isinstance(p, dict)]
    raise SafeguardException(f"Unable to find provider matching '{provider}' in [{', '.join(known)}]")


async def _async_post_authorization_code(
    session: ClientSession,
    appliance: str,
    code: str,
    code_verifier: str,
    ssl_context: ssl.SSLContext | bool,
    timeout: ClientTimeout,
) -> str:
    """Exchange an authorization code for an rSTS access token (async)."""
    url = f"https://{appliance}/RSTS/oauth2/token"
    body = {
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
        "code": code,
        "code_verifier": code_verifier,
    }

    async with session.post(url, json=body, headers={"Accept": "application/json"}, ssl=ssl_context, timeout=timeout) as resp:
        if resp.status >= 400:
            text = await resp.text()
            raise SafeguardException(
                f"Failed to exchange authorization code: {resp.status} {text}",
                status_code=resp.status,
                response=text,
            )
        data: object = await resp.json()

    if not isinstance(data, dict):
        raise SafeguardException("Unexpected response from RSTS token endpoint")

    access_token = data.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise SafeguardException("RSTS response did not contain an access_token")

    return access_token


async def _async_post_login_response(
    session: ClientSession,
    appliance: str,
    rsts_token: str,
    api_version: str,
    ssl_context: ssl.SSLContext | bool,
    timeout: ClientTimeout,
) -> str:
    """Exchange an rSTS access token for a Safeguard user token (async)."""
    url = f"https://{appliance}/service/core/{api_version}/Token/LoginResponse"
    body = {"StsAccessToken": rsts_token}

    async with session.post(url, json=body, headers={"Accept": "application/json"}, ssl=ssl_context, timeout=timeout) as resp:
        if resp.status >= 400:
            text = await resp.text()
            raise SafeguardException(
                f"Failed to exchange RSTS token: {resp.status} {text}",
                status_code=resp.status,
                response=text,
            )
        data: object = await resp.json()

    if not isinstance(data, dict):
        raise SafeguardException("Unexpected response from Token/LoginResponse endpoint")

    status = data.get("Status")
    if status != "Success":
        raise SafeguardException(f"Error exchanging RSTS token, status: {status}")

    user_token = data.get("UserToken")
    if not isinstance(user_token, str) or not user_token:
        raise SafeguardException("LoginResponse did not contain a UserToken")

    return user_token
