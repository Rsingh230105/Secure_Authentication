"""Google and GitHub OAuth2 provider exchange and user provisioning."""

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.user import User
from app.schemas.auth import LoginResponse
from app.services.auth_service import AuthenticationError, _issue_token_pair


# ---------------------------------------------------------------------------
# Google
# ---------------------------------------------------------------------------

_GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
_GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


def google_authorization_url() -> str:
    """Return the Google OAuth2 consent-screen URL."""

    if not settings.google_client_id:
        raise AuthenticationError("Google OAuth is not configured")

    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": settings.google_redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
    }
    query = "&".join(f"{k}={v}" for k, v in params.items())
    return f"{_GOOGLE_AUTH_URL}?{query}"


def handle_google_callback(database_session: Session, code: str) -> LoginResponse:
    """Exchange a Google authorization code for a JWT token pair.

    Finds an existing user by email or creates a new verified account,
    then issues the standard access + refresh token pair.
    """

    if not settings.google_client_id:
        raise AuthenticationError("Google OAuth is not configured")

    with httpx.Client() as client:
        token_response = client.post(
            _GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret.get_secret_value(),
                "redirect_uri": settings.google_redirect_uri,
                "grant_type": "authorization_code",
            },
        )

    if token_response.status_code != 200:
        raise AuthenticationError("Failed to exchange Google authorization code")

    access_token = token_response.json().get("access_token")
    if not access_token:
        raise AuthenticationError("Google did not return an access token")

    with httpx.Client() as client:
        userinfo_response = client.get(
            _GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )

    if userinfo_response.status_code != 200:
        raise AuthenticationError("Failed to fetch Google user profile")

    profile = userinfo_response.json()
    email = profile.get("email")
    if not email:
        raise AuthenticationError("Google profile did not include an email address")

    return _find_or_create_user_and_login(database_session, email.lower())


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------

_GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
_GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
_GITHUB_USERINFO_URL = "https://api.github.com/user"
_GITHUB_EMAILS_URL = "https://api.github.com/user/emails"


def github_authorization_url() -> str:
    """Return the GitHub OAuth2 authorization URL."""

    if not settings.github_client_id:
        raise AuthenticationError("GitHub OAuth is not configured")

    params = {
        "client_id": settings.github_client_id,
        "redirect_uri": settings.github_redirect_uri,
        "scope": "user:email",
    }
    query = "&".join(f"{k}={v}" for k, v in params.items())
    return f"{_GITHUB_AUTH_URL}?{query}"


def handle_github_callback(database_session: Session, code: str) -> LoginResponse:
    """Exchange a GitHub authorization code for a JWT token pair.

    Finds an existing user by email or creates a new verified account,
    then issues the standard access + refresh token pair.
    """

    if not settings.github_client_id:
        raise AuthenticationError("GitHub OAuth is not configured")

    with httpx.Client() as client:
        token_response = client.post(
            _GITHUB_TOKEN_URL,
            data={
                "code": code,
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret.get_secret_value(),
                "redirect_uri": settings.github_redirect_uri,
            },
            headers={"Accept": "application/json"},
        )

    if token_response.status_code != 200:
        raise AuthenticationError("Failed to exchange GitHub authorization code")

    access_token = token_response.json().get("access_token")
    if not access_token:
        raise AuthenticationError("GitHub did not return an access token")

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
    }

    with httpx.Client() as client:
        email = _fetch_github_primary_email(client, headers)

    return _find_or_create_user_and_login(database_session, email)


def _fetch_github_primary_email(client: httpx.Client, headers: dict) -> str:
    """Return the primary verified email from the GitHub emails endpoint.

    Falls back to the public profile email when the emails endpoint is
    unavailable or returns no primary address.
    """

    emails_response = client.get(_GITHUB_EMAILS_URL, headers=headers)
    if emails_response.status_code == 200:
        for entry in emails_response.json():
            if entry.get("primary") and entry.get("verified"):
                return entry["email"].lower()

    # Fallback: public profile
    profile_response = client.get(_GITHUB_USERINFO_URL, headers=headers)
    if profile_response.status_code == 200:
        email = profile_response.json().get("email")
        if email:
            return email.lower()

    raise AuthenticationError("GitHub profile did not include a verified email address")


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

def _find_or_create_user_and_login(
    database_session: Session,
    email: str,
) -> LoginResponse:
    """Return a JWT token pair for an existing user or a newly created one."""

    user = database_session.scalar(select(User).where(User.email == email))

    if user is None:
        user = User(
            email=email,
            hashed_password=None,
            is_active=True,
            is_verified=True,
        )
        database_session.add(user)
        database_session.flush()

    if not user.is_active:
        raise AuthenticationError("This account has been deactivated")

    token_pair = _issue_token_pair(database_session, user)
    database_session.commit()
    return token_pair
