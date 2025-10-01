# Backend FastAPI - Jira/Confluence Connector

This FastAPI service provides OAuth 2.0 and API token integration for Atlassian Jira and Confluence with in-memory session storage. It exposes REST endpoints for starting OAuth flows, handling callbacks, and listing Jira projects and Confluence spaces.

Important: This implementation stores sessions in memory only (for development). For production, replace with persistent/session storage.

## Endpoints

- GET `/` — Health check
- GET `/auth/jira/oauth/start` — Start Jira OAuth 2.0 flow (returns `auth_url` and `X-Session-Token` header)
- GET `/auth/jira/oauth/callback?code=...&state=...` — Handle Jira OAuth callback (returns `session_token`)
- POST `/auth/jira/api-token` — Authenticate Jira via API token `{ email, api_token, site? }` (returns `session_token`)
- GET `/jira/projects` — List Jira projects (requires `X-Session-Token`)

- GET `/auth/confluence/oauth/start` — Start Confluence OAuth 2.0 flow (returns `auth_url` and `X-Session-Token` header)
- GET `/auth/confluence/oauth/callback?code=...&state=...` — Handle Confluence OAuth callback (returns `session_token`)
- POST `/auth/confluence/api-token` — Authenticate Confluence via API token `{ email, api_token, site? }` (returns `session_token`)
- GET `/confluence/spaces` — List Confluence spaces (requires `X-Session-Token`)

All endpoints have OpenAPI docs at `/docs` and `/openapi.json`.

## CORS

Configurable via `FRONTEND_ORIGIN` env variable (comma-separated list). Defaults to `*` for development.

## Environment variables

Create `.env` (see `.env.example`):

```
FRONTEND_ORIGIN=http://localhost:3000
JIRA_OAUTH_CLIENT_ID=...
JIRA_OAUTH_CLIENT_SECRET=...
JIRA_OAUTH_REDIRECT_URI=http://localhost:3001/auth/jira/oauth/callback

CONFLUENCE_OAUTH_CLIENT_ID=...
CONFLUENCE_OAUTH_CLIENT_SECRET=...
CONFLUENCE_OAUTH_REDIRECT_URI=http://localhost:3001/auth/confluence/oauth/callback
```

Do not hard-code secrets. The service uses `python-dotenv` to load `.env` for local dev.

## Running

Install dependencies and run with uvicorn:

```
pip install -r requirements.txt
uvicorn src.api.main:app --host 0.0.0.0 --port 3001 --reload
```

## Notes on Atlassian API calls

- OAuth: Uses `https://auth.atlassian.com/authorize` and token exchange at `https://auth.atlassian.com/oauth/token`, then discovers `cloudId` via `https://api.atlassian.com/oauth/token/accessible-resources`. Requests are sent to `https://api.atlassian.com/ex/{product}/{cloudId}/rest/...` with `Bearer` token.
- API Token: Uses Basic Auth on site-specific endpoints `https://{site}.atlassian.net/rest/...` (Jira) or `https://{site}/wiki/rest/...` (Confluence). Client must provide `site` (e.g., `example.atlassian.net`) with the API token flow.

## Security

- In-memory session storage for development only.
- Ensure `FRONTEND_ORIGIN` is set to your frontend URL in production.
- Replace in-memory sessions with a secure session store for production.
