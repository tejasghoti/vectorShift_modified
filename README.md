# vectorShift

Demo FastAPI + React integration project showcasing OAuth2 flows for Notion, Airtable, and HubSpot.

## Tech Stack

Backend: FastAPI, Redis (for ephemeral state + credential storage), Requests.
Frontend: React (CRA), Material UI, Axios.

## Folder Structure

backend/ # FastAPI app
integrations/ # Individual integration modules (notion, airtable, hubspot)
main.py # FastAPI application & endpoints
redis_client.py # Async redis helpers
frontend/ # React application
src/integrations/ # React UI components for each integration

## OAuth2 Flow (Example: HubSpot)

1. User clicks "Connect HubSpot" -> frontend POST /integrations/hubspot/authorize.
2. Backend builds consent URL, stores state in Redis, returns URL.
3. Frontend opens popup to HubSpot.
4. User authorizes; HubSpot redirects to backend callback with code+state.
5. Backend validates state, exchanges code for tokens, stores credentials in Redis.
6. Frontend detects popup closed, polls /integrations/hubspot/credentials to retrieve tokens.
7. Frontend can now POST /integrations/hubspot/load with credentials JSON to load data.

Pattern is consistent across Notion & Airtable for easy extensibility.

## Running Locally

In one terminal (backend):

```
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # then fill in your client IDs / secrets
uvicorn main:app --reload
```

Redis (separate terminal):

```
redis-server
```

Frontend:

```
cd frontend
npm install
npm start
```

Visit http://localhost:3000.

## Adding a New Integration

1. Create backend/integrations/<service>.py copying hubspot.py structure.
2. Add authorize/oauth2callback/credentials/load endpoints in main.py.
3. Add React component in src/integrations and surface in UI.

## Interview Talking Points

- Modular design: Each provider isolated; main.py orchestrates only routing.
- Security: Short‑lived Redis storage, state validation for CSRF mitigation.
- Extensibility: Shared patterns minimize new integration boilerplate.
- Error handling: HTTPException for user input / provider failures; simple logging via prints (could be replaced by structured logger).

## DISCLAIMER

Client IDs / secrets must go in backend/.env (never commit). Provided placeholders keep code runnable without secrets.

## Next Improvements (Optional)

## Current Features

- Completed OAuth for Airtable (with PKCE), Notion, HubSpot (Authorization Code).
- Ephemeral credential + state storage in Redis (10 min TTL) with single-use retrieval.
- Unified /integrations/<service>/(authorize|oauth2callback|credentials|load) endpoints.
- Normalized IntegrationItem objects for Airtable (Bases/Tables), HubSpot (Contacts/Companies/Deals), Notion (Databases) returned as JSON list.
- Structured logging scaffold, global exception handler, basic security headers, simple in-memory rate limiting (demo only).
- Frontend React UI with dynamic integration selection and MUI DataGrid display for normalized lists.

## Example cURL Commands

Authorize (get URL):

```bash
curl -X POST -F user_id=TestUser -F org_id=TestOrg http://localhost:8000/integrations/hubspot/authorize
```

After completing browser auth & popup close, fetch credentials:

```bash
curl -X POST -F user_id=TestUser -F org_id=TestOrg http://localhost:8000/integrations/hubspot/credentials
```

Load items using credentials JSON (example shown with placeholder <JSON>):

```bash
curl -X POST -F "credentials=<JSON>" http://localhost:8000/integrations/hubspot/load
```

## Running Tests (placeholder)

Add tests under backend/tests and run with:

```bash
pytest -q
```

Minimal tests would mock external APIs (use responses or httpx_mock) for:

- State mismatch returns 400.
- Credentials retrieval deletes key.
- Item normalization returns expected keys (id, name, type).

## Token Persistence & Refresh

SQLite persistence (`backend/storage.py`) stores access & refresh tokens (HubSpot & Notion). Credentials cached in Redis are augmented with user/org; data load endpoints transparently refresh tokens 60s before expiry (if a refresh_token exists). Airtable currently relies on its issued access token only (extend similarly if needed).

## Next Improvements (Optional / Future)

- Persist & refresh tokens (DB or KV) instead of single-use Redis delete.
- Replace polling with window.postMessage for faster OAuth completion detection.
- Add full test suite + CI.
- Enhance Notion normalization (pages, blocks) & deep links.
- Security hardening: stricter CORS, origin validation, real rate limiting backend (Redis bucket).
- Convert backend to Pydantic models for responses; add OpenAPI description details.
