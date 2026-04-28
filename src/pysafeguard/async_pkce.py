"""Async PKCE non-interactive login for Safeguard.

Async mirror of :mod:`pysafeguard.pkce`. Programmatically drives the
browser-based OAuth2/PKCE flow using ``aiohttp`` instead of ``requests``.
"""

from __future__ import annotations

import ssl

from aiohttp import ClientSession, ClientTimeout, CookieJar
from truststore import SSLContext

from .errors import SafeguardError
from .pkce import (
    DEFAULT_TIMEOUT,
    REDIRECT_URI,
    _STEP_GENERATE_CLAIMS,
    _STEP_INIT,
    _STEP_PRIMARY_AUTH,
    _STEP_SECONDARY_AUTH,
    _STEP_SECONDARY_INIT,
    _check_mfa_result,
    _check_secondary_required,
    _extract_authorization_code,
    _extract_mfa_state,
    _generate_code_challenge,
    _generate_code_verifier,
    _generate_csrf_token,
    _match_provider,
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
    :raises SafeguardError: If authentication fails.
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
            raise SafeguardError(
                f"Failed to generate claims: {claims_text}",
                status_code=claims_status,
                response_body=claims_text,
            )

        auth_code = _extract_authorization_code(claims_text)

        rsts_access_token = await _async_post_authorization_code(session, appliance, auth_code, code_verifier, ssl_context, timeout)

        return await _async_post_login_response(session, appliance, rsts_access_token, api_version, ssl_context, timeout)


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

    if not (200 <= status < 300):
        error_message = text.strip() if text.strip() else str(status)
        raise SafeguardError(
            f"rSTS authentication error: {error_message}",
            status_code=status,
            response_body=text,
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
    if _check_secondary_required(primary_resp_text, secondary_password) is None:
        return

    assert secondary_password is not None  # validated by _check_secondary_required

    # Step 7: Initialize secondary provider
    init_text, init_status = await _async_rsts_request(session, pkce_base_url + _STEP_SECONDARY_INIT, form_data, ssl_context, timeout)
    mfa_state = _extract_mfa_state(init_text, init_status)

    # Step 5: Submit secondary authentication
    mfa_form_data = {
        **form_data,
        "secondaryLoginTextbox": secondary_password,
        "secondaryAuthenticationStateTextbox": mfa_state,
    }

    mfa_text, mfa_status = await _async_rsts_request(session, pkce_base_url + _STEP_SECONDARY_AUTH, mfa_form_data, ssl_context, timeout)
    _check_mfa_result(mfa_text, mfa_status)


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
    """Resolve a provider name/ID to an rSTS provider ID (async).

    Falls back to using the provider string as-is if the providers endpoint
    is unreachable or returns unexpected data.
    """
    try:
        url = f"https://{appliance}/service/core/{api_version}/AuthenticationProviders"
        async with session.get(url, headers={"Accept": "application/json"}, ssl=ssl_context, timeout=timeout) as resp:
            if resp.status >= 400:
                return provider
            providers: object = await resp.json()

        if not isinstance(providers, list):
            return provider

        return _match_provider(providers, provider)
    except SafeguardError:
        raise
    except Exception:
        return provider


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
            raise SafeguardError(
                f"Failed to exchange authorization code: {resp.status} {text}",
                status_code=resp.status,
                response_body=text,
            )
        data: object = await resp.json()

    if not isinstance(data, dict):
        raise SafeguardError("Unexpected response from RSTS token endpoint")

    access_token = data.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise SafeguardError("RSTS response did not contain an access_token")

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
            raise SafeguardError(
                f"Failed to exchange RSTS token: {resp.status} {text}",
                status_code=resp.status,
                response_body=text,
            )
        data: object = await resp.json()

    if not isinstance(data, dict):
        raise SafeguardError("Unexpected response from Token/LoginResponse endpoint")

    status = data.get("Status")
    if status != "Success":
        raise SafeguardError(f"Error exchanging RSTS token, status: {status}")

    user_token = data.get("UserToken")
    if not isinstance(user_token, str) or not user_token:
        raise SafeguardError("LoginResponse did not contain a UserToken")

    return user_token
