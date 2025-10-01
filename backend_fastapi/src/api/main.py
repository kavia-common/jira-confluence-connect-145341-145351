import os
import secrets
import time
import urllib.parse
from typing import Dict, Optional, Tuple

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.datastructures import URL

try:
    from dotenv import load_dotenv  # type: ignore
except Exception:  # pragma: no cover
    def load_dotenv(*args, **kwargs):
        return False

# Load environment variables from .env if present
load_dotenv()

# ------------------------------------------------------------------------------
# App Initialization with CORS and OpenAPI metadata
# ------------------------------------------------------------------------------

openapi_tags = [
    {"name": "Health", "description": "Service status checks"},
    {"name": "Auth/Jira", "description": "Jira authentication using OAuth 2.0 or API token"},
    {"name": "Auth/Confluence", "description": "Confluence authentication using OAuth 2.0 or API token"},
    {"name": "Jira", "description": "Jira resources"},
    {"name": "Confluence", "description": "Confluence resources"},
    {"name": "WebSocket", "description": "Project-level notes for real-time usage (none implemented yet)"},
]

app = FastAPI(
    title="Jira/Confluence Connector API",
    description=(
        "Backend API for connecting to Atlassian Jira and Confluence using OAuth 2.0 or API Token. "
        "Sessions are stored in memory and are intended only for development/testing. "
        "Provide your own persistence/session management for production."
    ),
    version="0.1.0",
    openapi_tags=openapi_tags,
)

# CORS for frontend access (configure allow_origins via env FRONTEND_ORIGIN if needed)
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in FRONTEND_ORIGIN.split(",") if origin.strip()] or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------------------
# In-memory session store (simple dictionary)
# ------------------------------------------------------------------------------

# Session structure:
# sessions[token] = {
#   "created_at": int,
#   "expires_at": Optional[int],
#   "jira": {"auth_type": "oauth"|"api_token", "cloud_id": str, "access_token": str, "email": Optional[str], "api_token": Optional[str]},
#   "confluence": {...}
# }
SESSIONS: Dict[str, Dict] = {}

SESSION_TTL_SECONDS = 60 * 60 * 8  # 8 hours default TTL


def _now() -> int:
    return int(time.time())


def create_session() -> str:
    """Create a new session token and initialize storage."""
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = {
        "created_at": _now(),
        "expires_at": _now() + SESSION_TTL_SECONDS,
        "jira": None,
        "confluence": None,
    }
    return token


def get_session(session_token: str) -> Dict:
    """Retrieve a session from memory, validating expiration."""
    session = SESSIONS.get(session_token)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")
    if session.get("expires_at") and session["expires_at"] < _now():
        # expire and delete
        try:
            del SESSIONS[session_token]
        except Exception:
            pass
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")
    return session


def require_session(request: Request) -> Tuple[str, Dict]:
    """Dependency to require a valid session via header X-Session-Token."""
    token = request.headers.get("X-Session-Token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing X-Session-Token header")
    return token, get_session(token)


# ------------------------------------------------------------------------------
# Environment configuration (no hardcoding)
# ------------------------------------------------------------------------------

# These are intentionally read from environment variables; do not hard-code.
ATLASSIAN_CLOUD_BASE = "https://api.atlassian.com"
ATLASSIAN_AUTH_BASE = "https://auth.atlassian.com"

JIRA_OAUTH_CLIENT_ID = os.getenv("JIRA_OAUTH_CLIENT_ID", "")
JIRA_OAUTH_CLIENT_SECRET = os.getenv("JIRA_OAUTH_CLIENT_SECRET", "")
JIRA_OAUTH_REDIRECT_URI = os.getenv("JIRA_OAUTH_REDIRECT_URI", "")

CONFLUENCE_OAUTH_CLIENT_ID = os.getenv("CONFLUENCE_OAUTH_CLIENT_ID", "")
CONFLUENCE_OAUTH_CLIENT_SECRET = os.getenv("CONFLUENCE_OAUTH_CLIENT_SECRET", "")
CONFLUENCE_OAUTH_REDIRECT_URI = os.getenv("CONFLUENCE_OAUTH_REDIRECT_URI", "")

# API token auth will use HTTP Basic with email + token for site-specific endpoints under https://{site}.atlassian.net
# For unified v3 APIs, we generally need cloudId to proxy requests.

# ------------------------------------------------------------------------------
# Models
# ------------------------------------------------------------------------------

class StartAuthResponse(BaseModel):
    """Response containing URL to redirect user to begin OAuth authorization."""
    auth_url: str = Field(..., description="URL where the user should be redirected to begin authorization")


class SessionResponse(BaseModel):
    """Response containing created session token."""
    session_token: str = Field(..., description="Opaque session token to include in X-Session-Token for subsequent calls")


class ApiTokenAuthRequest(BaseModel):
    """Request model for API token authentication."""
    email: str = Field(..., description="Atlassian account email associated with the API token")
    api_token: str = Field(..., description="Atlassian API token")
    site: Optional[str] = Field(None, description="Optional Atlassian site subdomain (e.g., example.atlassian.net). If omitted, Jira/Confluence discovery via cloud ID will be attempted where applicable.")


class ProjectsResponse(BaseModel):
    """Jira projects response wrapper."""
    projects: list = Field(..., description="List of Jira projects returned by Atlassian")


class SpacesResponse(BaseModel):
    """Confluence spaces response wrapper."""
    spaces: list = Field(..., description="List of Confluence spaces returned by Atlassian")


class ErrorResponse(BaseModel):
    """Standard error response."""
    detail: str = Field(..., description="Error detail message")


# ------------------------------------------------------------------------------
# Utilities for Atlassian OAuth2 (Auth code with PKCE not required for server-side; using client secret)
# ------------------------------------------------------------------------------

SCOPES_JIRA = [
    "read:jira-work",
    "write:jira-work",
    "read:jira-user",
    "offline_access",
    "manage:jira-project",
]
SCOPES_CONFLUENCE = [
    "read:confluence-space.summary",
    "write:confluence-content",
    "read:confluence-content.all",
    "offline_access",
]


def _state_with_session(session_token: str) -> str:
    return urllib.parse.quote(session_token, safe="")


def _session_from_state(state: str) -> str:
    return urllib.parse.unquote(state)


async def _oauth_authorize_url(product: str) -> Tuple[str, str]:
    """
    Build authorization URL for OAuth 2.0 flow.

    Returns (auth_url, session_token)
    """
    if product == "jira":
        client_id = JIRA_OAUTH_CLIENT_ID
        redirect_uri = JIRA_OAUTH_REDIRECT_URI
        scopes = " ".join(SCOPES_JIRA)
    else:
        client_id = CONFLUENCE_OAUTH_CLIENT_ID
        redirect_uri = CONFLUENCE_OAUTH_REDIRECT_URI
        scopes = " ".join(SCOPES_CONFLUENCE)

    if not client_id or not redirect_uri:
        # hint to user to configure .env
        raise HTTPException(
            status_code=500,
            detail=f"OAuth not configured for {product}. Ensure environment variables are set and .env is provided.",
        )

    session_token = create_session()
    params = {
        "audience": "api.atlassian.com",
        "client_id": client_id,
        "scope": scopes,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "prompt": "consent",
        "state": _state_with_session(session_token),
    }
    url = str(URL(ATLASSIAN_AUTH_BASE).replace(path="/authorize", query=urllib.parse.urlencode(params)))
    return url, session_token


async def _exchange_code_for_token(product: str, code: str, redirect_uri: str) -> Dict:
    """Exchange authorization code for access/refresh tokens."""
    if product == "jira":
        client_id = JIRA_OAUTH_CLIENT_ID
        client_secret = JIRA_OAUTH_CLIENT_SECRET
    else:
        client_id = CONFLUENCE_OAUTH_CLIENT_ID
        client_secret = CONFLUENCE_OAUTH_CLIENT_SECRET

    if not client_id or not client_secret:
        raise HTTPException(status_code=500, detail=f"OAuth not configured for {product} (client ID/secret missing)")

    token_url = f"{ATLASSIAN_AUTH_BASE}/oauth/token"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            token_url,
            headers={"Content-Type": "application/json"},
            json={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
            },
        )
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"Token exchange failed: {resp.text}")
    return resp.json()


async def _discover_cloud_id(access_token: str, product: str) -> Optional[str]:
    """Discover cloudId for Jira/Confluence via accessible-resources endpoint."""
    url = f"{ATLASSIAN_CLOUD_BASE}/oauth/token/accessible-resources"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {access_token}"})
    if resp.status_code != 200:
        return None
    for res in resp.json():
        # productType is "jira" or "confluence"
        if res.get("scopes") and res.get("id") and res.get("url"):
            if product.lower() in (res.get("productType") or "").lower():
                return res.get("id")
    return None


# ------------------------------------------------------------------------------
# Health
# ------------------------------------------------------------------------------

# PUBLIC_INTERFACE
@app.get("/", tags=["Health"], summary="Health Check", response_model=dict)
def health_check():
    """
    Health Check endpoint.

    Returns:
        JSON indicating service is healthy.
    """
    return {"message": "Healthy"}


# ------------------------------------------------------------------------------
# Jira OAuth Flow
# ------------------------------------------------------------------------------

# PUBLIC_INTERFACE
@app.get(
    "/auth/jira/oauth/start",
    tags=["Auth/Jira"],
    summary="Start Jira OAuth 2.0 flow",
    response_model=StartAuthResponse,
    responses={500: {"model": ErrorResponse}},
)
async def jira_oauth_start():
    """
    Start Jira OAuth 2.0 flow.

    Returns:
        auth_url: URL to redirect the user to Atlassian Authorization page.
    """
    auth_url, session_token = await _oauth_authorize_url("jira")
    # Return auth URL and expose session via header for client to persist
    response = JSONResponse(content={"auth_url": auth_url})
    response.headers["X-Session-Token"] = session_token
    return response


# PUBLIC_INTERFACE
@app.get(
    "/auth/jira/oauth/callback",
    tags=["Auth/Jira"],
    summary="Handle Jira OAuth callback",
    response_model=SessionResponse,
    responses={400: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
)
async def jira_oauth_callback(code: str = Query(..., description="Authorization code"), state: str = Query(..., description="Opaque state carrying session token")):
    """
    Jira OAuth 2.0 callback.

    Parameters:
        code: Authorization code returned by Atlassian.
        state: Opaque state containing our session token.

    Returns:
        session_token: The session token to be used in subsequent requests (X-Session-Token header).
    """
    session_token = _session_from_state(state)
    session = get_session(session_token)

    token_data = await _exchange_code_for_token("jira", code, JIRA_OAUTH_REDIRECT_URI)
    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="Missing access token in response")

    cloud_id = await _discover_cloud_id(access_token, "jira")
    session["jira"] = {
        "auth_type": "oauth",
        "cloud_id": cloud_id,
        "access_token": access_token,
        "email": None,
        "api_token": None,
    }
    return SessionResponse(session_token=session_token)


# PUBLIC_INTERFACE
@app.post(
    "/auth/jira/api-token",
    tags=["Auth/Jira"],
    summary="Authenticate to Jira via API token",
    response_model=SessionResponse,
    responses={400: {"model": ErrorResponse}},
)
async def jira_api_token(auth: ApiTokenAuthRequest):
    """
    Authenticate Jira using API token and email.

    Body:
        email: Atlassian account email
        api_token: API token
        site: Optional site domain (e.g., example.atlassian.net)

    Returns:
        session_token header and body for subsequent authenticated requests.
    """
    if not auth.email or not auth.api_token:
        raise HTTPException(status_code=400, detail="email and api_token are required")
    session_token = create_session()
    session = get_session(session_token)
    session["jira"] = {
        "auth_type": "api_token",
        "cloud_id": None,
        "access_token": None,
        "email": auth.email,
        "api_token": auth.api_token,
        "site": auth.site,  # may be None, client should supply site for basic auth endpoints
    }
    response = JSONResponse(content={"session_token": session_token})
    response.headers["X-Session-Token"] = session_token
    return response


# ------------------------------------------------------------------------------
# Confluence OAuth Flow
# ------------------------------------------------------------------------------

# PUBLIC_INTERFACE
@app.get(
    "/auth/confluence/oauth/start",
    tags=["Auth/Confluence"],
    summary="Start Confluence OAuth 2.0 flow",
    response_model=StartAuthResponse,
    responses={500: {"model": ErrorResponse}},
)
async def confluence_oauth_start():
    """
    Start Confluence OAuth 2.0 flow.

    Returns:
        auth_url: URL to redirect the user to Atlassian Authorization page.
    """
    auth_url, session_token = await _oauth_authorize_url("confluence")
    response = JSONResponse(content={"auth_url": auth_url})
    response.headers["X-Session-Token"] = session_token
    return response


# PUBLIC_INTERFACE
@app.get(
    "/auth/confluence/oauth/callback",
    tags=["Auth/Confluence"],
    summary="Handle Confluence OAuth callback",
    response_model=SessionResponse,
    responses={400: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
)
async def confluence_oauth_callback(code: str = Query(..., description="Authorization code"), state: str = Query(..., description="Opaque state carrying session token")):
    """
    Confluence OAuth 2.0 callback.

    Parameters:
        code: Authorization code returned by Atlassian.
        state: Opaque state containing our session token.

    Returns:
        session_token: The session token to be used in subsequent requests (X-Session-Token header).
    """
    session_token = _session_from_state(state)
    session = get_session(session_token)

    token_data = await _exchange_code_for_token("confluence", code, CONFLUENCE_OAUTH_REDIRECT_URI)
    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="Missing access token in response")

    cloud_id = await _discover_cloud_id(access_token, "confluence")
    session["confluence"] = {
        "auth_type": "oauth",
        "cloud_id": cloud_id,
        "access_token": access_token,
        "email": None,
        "api_token": None,
    }
    return SessionResponse(session_token=session_token)


# PUBLIC_INTERFACE
@app.post(
    "/auth/confluence/api-token",
    tags=["Auth/Confluence"],
    summary="Authenticate to Confluence via API token",
    response_model=SessionResponse,
    responses={400: {"model": ErrorResponse}},
)
async def confluence_api_token(auth: ApiTokenAuthRequest):
    """
    Authenticate Confluence using API token and email.

    Body:
        email: Atlassian account email
        api_token: API token
        site: Optional site domain (e.g., example.atlassian.net)

    Returns:
        session_token header and body for subsequent authenticated requests.
    """
    if not auth.email or not auth.api_token:
        raise HTTPException(status_code=400, detail="email and api_token are required")
    session_token = create_session()
    session = get_session(session_token)
    session["confluence"] = {
        "auth_type": "api_token",
        "cloud_id": None,
        "access_token": None,
        "email": auth.email,
        "api_token": auth.api_token,
        "site": auth.site,
    }
    response = JSONResponse(content={"session_token": session_token})
    response.headers["X-Session-Token"] = session_token
    return response


# ------------------------------------------------------------------------------
# Helpers to call Atlassian APIs
# ------------------------------------------------------------------------------

async def _jira_client_headers(session: Dict) -> Tuple[Dict[str, str], str]:
    """Return headers and base URL for Jira, depending on auth type."""
    jira = session.get("jira")
    if not jira:
        raise HTTPException(status_code=401, detail="Jira not authenticated in session")

    if jira["auth_type"] == "oauth":
        access_token = jira.get("access_token")
        cloud_id = jira.get("cloud_id")
        if not access_token or not cloud_id:
            raise HTTPException(status_code=400, detail="Jira OAuth session incomplete (missing token or cloud id)")
        headers = {"Authorization": f"Bearer {access_token}"}
        base_url = f"{ATLASSIAN_CLOUD_BASE}/ex/jira/{cloud_id}/rest/api/3"
        return headers, base_url
    else:
        # API token basic auth. Requires site domain to call site-specific APIs.
        email = jira.get("email")
        api_token = jira.get("api_token")
        site = jira.get("site")
        if not (email and api_token and site):
            raise HTTPException(status_code=400, detail="Jira API token session incomplete (email, token, or site missing)")
        headers = {"Authorization": f"Basic {secrets.token_urlsafe(1)}"}  # dummy header to satisfy type; real auth via auth param
        base_url = f"https://{site}/rest/api/3"
        # httpx supports basic auth via auth=(email, token), we return placeholder headers; caller uses auth tuple
        return headers, base_url


async def _confluence_client_headers(session: Dict) -> Tuple[Dict[str, str], str]:
    """Return headers and base URL for Confluence, depending on auth type."""
    conf = session.get("confluence")
    if not conf:
        raise HTTPException(status_code=401, detail="Confluence not authenticated in session")

    if conf["auth_type"] == "oauth":
        access_token = conf.get("access_token")
        cloud_id = conf.get("cloud_id")
        if not access_token or not cloud_id:
            raise HTTPException(status_code=400, detail="Confluence OAuth session incomplete (missing token or cloud id)")
        headers = {"Authorization": f"Bearer {access_token}"}
        base_url = f"{ATLASSIAN_CLOUD_BASE}/ex/confluence/{cloud_id}/rest/api"
        return headers, base_url
    else:
        email = conf.get("email")
        api_token = conf.get("api_token")
        site = conf.get("site")
        if not (email and api_token and site):
            raise HTTPException(status_code=400, detail="Confluence API token session incomplete (email, token, or site missing)")
        headers = {"Authorization": f"Basic {secrets.token_urlsafe(1)}"}
        base_url = f"https://{site}/wiki/rest/api"
        return headers, base_url


# ------------------------------------------------------------------------------
# Jira Data Endpoints
# ------------------------------------------------------------------------------

# PUBLIC_INTERFACE
@app.get(
    "/jira/projects",
    tags=["Jira"],
    summary="List Jira projects",
    response_model=ProjectsResponse,
    responses={401: {"model": ErrorResponse}, 400: {"model": ErrorResponse}},
)
async def list_jira_projects(dep=Depends(require_session)):
    """
    List Jira projects for the authenticated user.

    Authentication:
        Provide X-Session-Token header from a previous Jira auth call.

    Returns:
        projects: List of Jira projects (raw Atlassian response items)
    """
    session_token, session = dep  # noqa: F841

    jira = session.get("jira")
    if not jira:
        raise HTTPException(status_code=401, detail="Not authenticated for Jira")

    headers, base_url = await _jira_client_headers(session)
    url = f"{base_url}/project/search"

    async with httpx.AsyncClient(timeout=30) as client:
        if jira["auth_type"] == "oauth":
            resp = await client.get(url, headers=headers)
        else:
            # API token basic auth
            resp = await client.get(url, auth=(jira["email"], jira["api_token"]))
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"Failed to fetch projects: {resp.text}")
    data = resp.json()
    # normalize to list
    projects = data.get("values") or data.get("projects") or data.get("issues") or data.get("results") or data.get("items") or data.get("data")
    if projects is None and isinstance(data, dict):
        projects = data.get("values")
    if projects is None:
        # Some Jira APIs return 'projects' key
        projects = data.get("projects", [])
    # Fallback: if 'values' not present but 'total' and 'startAt' exist, treat 'data' as a list if present
    if not isinstance(projects, list):
        projects = data.get("values", [])
    return ProjectsResponse(projects=projects)


# ------------------------------------------------------------------------------
# Confluence Data Endpoints
# ------------------------------------------------------------------------------

# PUBLIC_INTERFACE
@app.get(
    "/confluence/spaces",
    tags=["Confluence"],
    summary="List Confluence spaces",
    response_model=SpacesResponse,
    responses={401: {"model": ErrorResponse}, 400: {"model": ErrorResponse}},
)
async def list_confluence_spaces(dep=Depends(require_session)):
    """
    List Confluence spaces for the authenticated user.

    Authentication:
        Provide X-Session-Token header from a previous Confluence auth call.

    Returns:
        spaces: List of Confluence spaces (raw Atlassian response items)
    """
    session_token, session = dep  # noqa: F841

    conf = session.get("confluence")
    if not conf:
        raise HTTPException(status_code=401, detail="Not authenticated for Confluence")

    headers, base_url = await _confluence_client_headers(session)
    url = f"{base_url}/space"

    async with httpx.AsyncClient(timeout=30) as client:
        if conf["auth_type"] == "oauth":
            resp = await client.get(url, headers=headers, params={"limit": 100})
        else:
            resp = await client.get(url, auth=(conf["email"], conf["api_token"]), params={"limit": 100})
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"Failed to fetch spaces: {resp.text}")
    data = resp.json()
    spaces = data.get("results", [])
    return SpacesResponse(spaces=spaces)


# ------------------------------------------------------------------------------
# Friendly docs route for WebSocket usage notes (none yet)
# ------------------------------------------------------------------------------

# PUBLIC_INTERFACE
@app.get(
    "/websocket-usage",
    tags=["WebSocket"],
    summary="WebSocket usage notes",
    response_model=dict,
)
def websocket_usage_notes():
    """
    Provides project-level notes for establishing real-time connections.

    Note:
        This project currently does not implement WebSockets. This route exists to
        demonstrate how such endpoints would be documented and discovered.
    """
    return {
        "message": "No WebSocket endpoints implemented. For future use, document ws://... endpoints here."
    }
