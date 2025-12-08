"""FastAPI Auth Service for Jitsi Google OAuth2 authentication."""

import os

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

from utils import (
    build_google_auth_url,
    exchange_code_for_tokens,
    is_domain_allowed,
    make_jitsi_jwt,
    parse_allowed_domains,
    sign_state,
    verify_google_id_token,
    verify_state,
)

# Load environment variables from .env file
load_dotenv()

# Initialize FastAPI application
app = FastAPI(
    title="Jitsi Auth Service",
    description="Google OAuth2 authentication service for Jitsi Meet moderators",
    version="1.0.0",
)

# Load allowed domains from environment variable
ALLOWED_MOD_DOMAINS: set[str] = parse_allowed_domains(
    os.environ.get("ALLOWED_MOD_DOMAINS", "")
)


@app.get("/auth/{room}")
async def auth_redirect(room: str) -> RedirectResponse:
    """Initiate OAuth flow for a Jitsi room.
    
    Redirects the user to Google OAuth2 login with a signed state
    parameter containing the room name.
    
    Args:
        room: The Jitsi room name to authenticate for.
    
    Returns:
        Redirect to Google OAuth2 authorization URL.
    
    Raises:
        HTTPException: 500 if Google OAuth is not configured.
    """
    try:
        state = sign_state(room)
        auth_url = build_google_auth_url(state)
        return RedirectResponse(url=auth_url)
    except ValueError as e:
        raise HTTPException(status_code=500, detail="Google OAuth not configured")


@app.get("/oauth2/callback", response_model=None)
async def oauth_callback(code: str = None, state: str = None):
    """Handle Google OAuth2 callback.
    
    Verifies the state parameter, exchanges the authorization code for tokens,
    verifies the ID token, checks the user's domain, and either redirects to
    Jitsi with a JWT or displays an access denied page.
    
    Args:
        code: Authorization code from Google.
        state: Signed state parameter containing room name.
    
    Returns:
        RedirectResponse to Jitsi room with JWT for allowed domains,
        or HTMLResponse with access denied message for disallowed domains.
    
    Raises:
        HTTPException: Various 400 errors for invalid state, token exchange
            failures, or invalid tokens.
    """
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")
    if not state:
        raise HTTPException(status_code=400, detail="Missing state parameter")
    
    # Verify state signature and extract room name
    room = verify_state(state)
    
    # Exchange authorization code for tokens
    tokens = await exchange_code_for_tokens(code)
    
    id_token_str = tokens.get("id_token")
    if not id_token_str:
        raise HTTPException(status_code=400, detail="No ID token in response")
    
    # Verify Google ID token
    idinfo = verify_google_id_token(id_token_str)
    
    email = idinfo.get("email", "")
    name = idinfo.get("name", email.split("@")[0])
    
    # Check if user's domain is allowed
    if not is_domain_allowed(email, ALLOWED_MOD_DOMAINS):
        return HTMLResponse(
            content=f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Access Denied</title>
                <style>
                    body {{
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                        background-color: #f5f5f5;
                    }}
                    .container {{
                        text-align: center;
                        padding: 40px;
                        background: white;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    }}
                    h1 {{ color: #d32f2f; }}
                    p {{ color: #666; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Access Denied</h1>
                    <p>Your email domain is not authorized for moderator access.</p>
                    <p>Email: {email}</p>
                </div>
            </body>
            </html>
            """,
            status_code=200,
        )
    
    # Generate Jitsi JWT for allowed domain
    jwt_token = make_jitsi_jwt(email, name, room)
    
    # Get Jitsi base URL from environment
    jitsi_base_url = os.environ.get("JITSI_BASE_URL", "")
    if not jitsi_base_url:
        raise HTTPException(status_code=500, detail="JITSI_BASE_URL not configured")
    
    # Redirect to Jitsi room with JWT
    redirect_url = f"{jitsi_base_url}/{room}?jwt={jwt_token}"
    return RedirectResponse(url=redirect_url)


@app.get("/health")
async def health_check() -> dict:
    """Health check endpoint.
    
    Returns:
        Simple health status response.
    """
    return {"status": "healthy"}
