"""Utility functions for Auth Service."""

import hmac
import hashlib
import os
import time
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import HTTPException
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests


def parse_allowed_domains(domains_str: str) -> set[str]:
    """Parse comma-separated domains into a lowercase set.
    
    Args:
        domains_str: Comma-separated string of domains (e.g., "example.com, Test.org")
    
    Returns:
        Set of lowercase domain strings with whitespace trimmed.
        Returns empty set for empty or whitespace-only input.
    """
    if not domains_str or not domains_str.strip():
        return set()
    
    domains = set()
    for domain in domains_str.split(","):
        trimmed = domain.strip().lower()
        if trimmed:
            domains.add(trimmed)
    
    return domains


def is_domain_allowed(email: str, allowed_domains: set[str]) -> bool:
    """Check if email domain is in the allowed set (case-insensitive).
    
    Args:
        email: Email address to check (e.g., "user@Example.COM")
        allowed_domains: Set of allowed domains (should be lowercase)
    
    Returns:
        True if the email's domain is in the allowed set, False otherwise.
    """
    if not email or "@" not in email:
        return False
    
    # Extract domain part (everything after the last @)
    domain = email.rsplit("@", 1)[-1].lower()
    
    return domain in allowed_domains



def _get_state_secret() -> str:
    """Get the STATE_SECRET from environment variables.
    
    Returns:
        The STATE_SECRET value.
    
    Raises:
        ValueError: If STATE_SECRET is not set.
    """
    secret = os.environ.get("STATE_SECRET")
    if not secret:
        raise ValueError("STATE_SECRET environment variable is not set")
    return secret


def sign_state(room: str) -> str:
    """Generate HMAC-signed state parameter containing room name.
    
    Creates a signed state string in format: {room}:{hmac_signature}
    where hmac_signature is HMAC-SHA256(STATE_SECRET, room) in hex.
    
    Args:
        room: The room name to include in the state.
    
    Returns:
        Signed state string in format "{room}:{signature}".
    
    Raises:
        ValueError: If STATE_SECRET is not set.
    """
    secret = _get_state_secret()
    signature = hmac.new(
        secret.encode("utf-8"),
        room.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return f"{room}:{signature}"


def verify_state(state: str) -> str:
    """Verify state signature and extract room name.
    
    Validates the HMAC signature in the state parameter and returns
    the room name if valid.
    
    Args:
        state: The signed state string in format "{room}:{signature}".
    
    Returns:
        The room name extracted from the state.
    
    Raises:
        HTTPException: 400 error if state format is invalid or signature doesn't match.
    """
    if not state or ":" not in state:
        raise HTTPException(status_code=400, detail="Invalid state format")
    
    # Split on the last colon to handle room names that might contain colons
    parts = state.rsplit(":", 1)
    if len(parts) != 2:
        raise HTTPException(status_code=400, detail="Invalid state format")
    
    room, provided_signature = parts
    
    if not room or not provided_signature:
        raise HTTPException(status_code=400, detail="Invalid state format")
    
    try:
        secret = _get_state_secret()
    except ValueError:
        raise HTTPException(status_code=500, detail="Server configuration error")
    
    expected_signature = hmac.new(
        secret.encode("utf-8"),
        room.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(provided_signature, expected_signature):
        raise HTTPException(status_code=400, detail="Invalid state signature")
    
    return room


def _get_jitsi_config() -> tuple[str, str, str]:
    """Get Jitsi configuration from environment variables.
    
    Returns:
        Tuple of (app_id, app_secret, domain).
    
    Raises:
        ValueError: If any required environment variable is not set.
    """
    app_id = os.environ.get("JITSI_APP_ID")
    app_secret = os.environ.get("JITSI_APP_SECRET")
    domain = os.environ.get("JITSI_DOMAIN")
    
    if not app_id:
        raise ValueError("JITSI_APP_ID environment variable is not set")
    if not app_secret:
        raise ValueError("JITSI_APP_SECRET environment variable is not set")
    if not domain:
        raise ValueError("JITSI_DOMAIN environment variable is not set")
    
    return app_id, app_secret, domain


def make_jitsi_jwt(email: str, name: str, room: str) -> str:
    """Generate a Jitsi-compatible JWT with moderator privileges.
    
    Creates a JWT token for Jitsi Meet authentication with all required claims.
    The token grants moderator privileges to the user.
    
    Args:
        email: User's email address.
        name: User's display name.
        room: The Jitsi room name.
    
    Returns:
        Encoded JWT string.
    
    Raises:
        ValueError: If required Jitsi environment variables are not set.
    """
    app_id, app_secret, domain = _get_jitsi_config()
    
    now = int(time.time())
    
    # Room name should be lowercase for Jitsi
    room_lower = room.lower()
    
    payload = {
        "aud": app_id,
        "iss": app_id,
        "sub": "*",  # Wildcard subject for all rooms
        "room": "*",  # Wildcard room - allows access to any room
        "context": {
            "user": {
                "id": email,  # Unique user identifier
                "name": name,
                "email": email,
                "moderator": True,
                "affiliation": "owner"  # Grant owner privileges
            }
        },
        "iat": now,
        "nbf": now - 10,  # Allow 10 seconds clock skew
        "exp": now + 7200  # Token valid for 2 hours
    }
    
    return jwt.encode(payload, app_secret, algorithm="HS256")


# Google OAuth Configuration
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_OAUTH_SCOPES = "openid email profile"


def _get_google_oauth_config() -> tuple[str, str, str]:
    """Get Google OAuth configuration from environment variables.
    
    Returns:
        Tuple of (client_id, client_secret, redirect_uri).
    
    Raises:
        ValueError: If any required environment variable is not set.
    """
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI")
    
    if not client_id:
        raise ValueError("GOOGLE_CLIENT_ID environment variable is not set")
    if not client_secret:
        raise ValueError("GOOGLE_CLIENT_SECRET environment variable is not set")
    if not redirect_uri:
        raise ValueError("GOOGLE_REDIRECT_URI environment variable is not set")
    
    return client_id, client_secret, redirect_uri


def build_google_auth_url(state: str) -> str:
    """Build Google OAuth2 authorization URL.
    
    Constructs the URL to redirect users to Google's OAuth2 login page.
    
    Args:
        state: The signed state parameter containing room information.
    
    Returns:
        Complete Google OAuth2 authorization URL.
    
    Raises:
        ValueError: If required Google OAuth environment variables are not set.
    """
    client_id, _, redirect_uri = _get_google_oauth_config()
    
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": GOOGLE_OAUTH_SCOPES,
        "state": state,
    }
    
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


async def exchange_code_for_tokens(code: str) -> dict:
    """Exchange authorization code for Google tokens.
    
    POSTs to Google's token endpoint to exchange the authorization code
    for access and ID tokens.
    
    Args:
        code: The authorization code received from Google OAuth callback.
    
    Returns:
        Dictionary containing token response with 'access_token', 'id_token', etc.
    
    Raises:
        HTTPException: 400 error if token exchange fails.
    """
    client_id, client_secret, redirect_uri = _get_google_oauth_config()
    
    data = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(GOOGLE_TOKEN_URL, data=data)
        
        if response.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail="Google token exchange failed"
            )
        
        return response.json()


def verify_google_id_token(id_token_str: str) -> dict:
    """Verify Google ID token signature and claims.
    
    Uses the google-auth library to verify the ID token's signature
    against Google's public keys and validates the claims.
    
    Args:
        id_token_str: The ID token string from Google's token response.
    
    Returns:
        Dictionary containing the verified token claims (email, name, etc.).
    
    Raises:
        HTTPException: 400 error if token verification fails.
    """
    client_id, _, _ = _get_google_oauth_config()
    
    try:
        # Verify the token using Google's public keys
        idinfo = id_token.verify_oauth2_token(
            id_token_str,
            google_requests.Request(),
            client_id
        )
        
        # Verify the issuer
        if idinfo.get("iss") not in ["accounts.google.com", "https://accounts.google.com"]:
            raise HTTPException(status_code=400, detail="Invalid issuer")
        
        # Ensure email is present
        if not idinfo.get("email"):
            raise HTTPException(status_code=400, detail="No email in Google token")
        
        return idinfo
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid Google ID token: {str(e)}")
