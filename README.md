# jira-confluence-connect-145341-145351

This workspace contains:
- backend_fastapi: FastAPI service for Jira/Confluence OAuth 2.0 and API token integration with in-memory session storage.

Run backend:
- Create backend_fastapi/.env from .env.example and fill values.
- pip install -r backend_fastapi/requirements.txt
- uvicorn src.api.main:app --host 0.0.0.0 --port 3001 --reload (from backend_fastapi)