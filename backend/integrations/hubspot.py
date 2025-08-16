"""hubspot.py

Lightweight HubSpot OAuth2 + data fetch helper functions.

Pattern intentionally mirrors airtable.py for consistency:
1. authorize_hubspot builds the consent URL and stores a short‑lived state in Redis.
2. oauth2callback_hubspot validates state, exchanges code for tokens, stores credentials in Redis.
3. get_hubspot_credentials retrieves & deletes stored credentials (single use for demo).
4. get_items_hubspot fetches a sample of HubSpot CRM objects (contacts, companies, deals)
   and converts them into IntegrationItem objects.

Environment variables expected (place in backend/.env – do NOT commit):
  HUBSPOT_CLIENT_ID=...
  HUBSPOT_CLIENT_SECRET=...
  HUBSPOT_SCOPES=crm.objects.contacts.read crm.objects.companies.read crm.objects.deals.read

Docs referenced:
  https://developers.hubspot.com/docs/api/intro-to-auth
  https://developers.hubspot.com/docs/api/crm/understanding-the-crm
"""

import os
import json
import secrets
import base64
from datetime import datetime
from typing import List

import requests
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
from dotenv import load_dotenv

from integrations.integration_item import IntegrationItem
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis
from storage import save_tokens, get_token_row, needs_refresh

load_dotenv()

HUBSPOT_CLIENT_ID = os.getenv("HUBSPOT_CLIENT_ID") or "YOUR_HUBSPOT_CLIENT_ID"
HUBSPOT_CLIENT_SECRET = os.getenv("HUBSPOT_CLIENT_SECRET") or "YOUR_HUBSPOT_CLIENT_SECRET"
HUBSPOT_REDIRECT_URI = os.getenv("HUBSPOT_REDIRECT_URI", "http://localhost:8000/integrations/hubspot/oauth2callback")
HUBSPOT_SCOPES = os.getenv(
    "HUBSPOT_SCOPES",
    "crm.objects.contacts.read crm.objects.companies.read crm.objects.deals.read",
)

AUTH_URL = "https://app.hubspot.com/oauth/authorize"
TOKEN_URL = "https://api.hubapi.com/oauth/v1/token"


async def authorize_hubspot(user_id: str, org_id: str):
    """Create HubSpot OAuth consent URL and store a random state token.

    The frontend will open this URL in a popup. After user authorizes, HubSpot
    redirects to our backend callback with ?code=...&state=...
    """
    state_payload = {
        "state": secrets.token_urlsafe(24),
        "user_id": user_id,
        "org_id": org_id,
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_payload).encode()).decode()
    await add_key_value_redis(f"hubspot_state:{org_id}:{user_id}", encoded_state, expire=600)

    params = {
        "client_id": HUBSPOT_CLIENT_ID,
        "redirect_uri": HUBSPOT_REDIRECT_URI,
        "scope": HUBSPOT_SCOPES,
        "response_type": "code",
        "state": encoded_state,
    }
    # Manual query build keeps dependencies light
    query = "&".join(f"{k}={requests.utils.quote(v)}" for k, v in params.items())
    return f"{AUTH_URL}?{query}"


async def oauth2callback_hubspot(request: Request):
    """Handle HubSpot redirect: validate state, exchange code for tokens.

    On success we store credentials JSON in Redis keyed by user/org for one-time fetch.
    Returns a tiny HTML page that auto-closes the popup (mirrors airtable pattern).
    """
    error = request.query_params.get("error")
    if error:
        raise HTTPException(status_code=400, detail=request.query_params.get("error_description") or error)

    code = request.query_params.get("code")
    encoded_state = request.query_params.get("state")
    if not code or not encoded_state:
        raise HTTPException(status_code=400, detail="Missing code or state")

    # Recover original state & validate
    try:
        state_json = json.loads(base64.urlsafe_b64decode(encoded_state.encode()).decode())
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid state encoding")

    user_id = state_json.get("user_id")
    org_id = state_json.get("org_id")
    saved_state = await get_value_redis(f"hubspot_state:{org_id}:{user_id}")
    if not saved_state or saved_state.decode() != encoded_state:
        raise HTTPException(status_code=400, detail="State mismatch or expired")

    # Exchange authorization code for tokens
    data = {
        "grant_type": "authorization_code",
        "client_id": HUBSPOT_CLIENT_ID,
        "client_secret": HUBSPOT_CLIENT_SECRET,
        "redirect_uri": HUBSPOT_REDIRECT_URI,
        "code": code,
    }
    try:
        resp = requests.post(TOKEN_URL, data=data, timeout=15)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token request failed: {e}")

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=f"HubSpot token error: {resp.text}")

    credentials = resp.json()
    await add_key_value_redis(
        f"hubspot_credentials:{org_id}:{user_id}", json.dumps(credentials), expire=600
    )
    await delete_key_redis(f"hubspot_state:{org_id}:{user_id}")
    # Persist for refresh
    save_tokens(
        "hubspot",
        user_id,
        org_id,
        credentials.get("access_token"),
        credentials.get("refresh_token"),
        credentials.get("expires_in"),
    )

    close_html = """
    <html><body><script>window.close();</script>HubSpot auth completed. You can close this window.</body></html>
    """
    return HTMLResponse(content=close_html)


async def get_hubspot_credentials(user_id: str, org_id: str):
    """Return (and remove) stored credentials for this user/org.

    For a production system you would persist or refresh tokens rather than delete.
    """
    raw = await get_value_redis(f"hubspot_credentials:{org_id}:{user_id}")
    if not raw:
        raise HTTPException(status_code=400, detail="No credentials found (maybe expired)")
    await delete_key_redis(f"hubspot_credentials:{org_id}:{user_id}")
    return json.loads(raw)


def _parse_time(ts: str | None):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def create_integration_item_metadata_object(obj: dict, object_type: str) -> IntegrationItem:
    """Map a HubSpot CRM object into a generic IntegrationItem.

    We extract a few helpful fields; remaining raw properties are ignored for brevity.
    """
    properties = obj.get("properties", {})
    name = (
        properties.get("firstname")
        or properties.get("name")
        or properties.get("dealname")
        or properties.get("lastname")
        or obj.get("id")
    )
    return IntegrationItem(
        id=f"{obj.get('id')}_{object_type}",
        name=name,
        type=object_type,
        creation_time=_parse_time(obj.get("createdAt")),
        last_modified_time=_parse_time(obj.get("updatedAt")),
        url=None,  # Could build deep links with hub_id if desired
        parent_id=None,
        parent_path_or_name=None,
    )


async def get_items_hubspot(credentials: str) -> List[IntegrationItem]:
    """Fetch sample HubSpot CRM objects using provided credentials JSON string.

    credentials (str): JSON serialized credentials as returned by get_hubspot_credentials.
    Returns list[IntegrationItem].
    """
    try:
        creds = json.loads(credentials)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid credentials JSON")

    access_token = creds.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="Missing access_token in credentials")

    headers = {"Authorization": f"Bearer {access_token}"}
    # Attempt refresh if stored and near expiry
    # credentials may carry refresh_token which we persisted earlier
    # Only perform refresh if token row indicates expiry
    token_row = get_token_row("hubspot", creds.get("user_id", ""), creds.get("org_id", ""))
    if token_row and needs_refresh(token_row) and token_row.get("refresh_token"):
        refresh_data = {
            "grant_type": "refresh_token",
            "refresh_token": token_row["refresh_token"],
            "client_id": HUBSPOT_CLIENT_ID,
            "client_secret": HUBSPOT_CLIENT_SECRET,
        }
        try:
            r_ref = requests.post(TOKEN_URL, data=refresh_data, timeout=15)
            if r_ref.status_code == 200:
                ref_json = r_ref.json()
                save_tokens(
                    "hubspot",
                    creds.get("user_id", ""),
                    creds.get("org_id", ""),
                    ref_json.get("access_token"),
                    ref_json.get("refresh_token") or token_row.get("refresh_token"),
                    ref_json.get("expires_in"),
                )
                headers["Authorization"] = f"Bearer {ref_json.get('access_token')}"
        except Exception:
            pass
    items: List[IntegrationItem] = []

    # Define object endpoints & minimal property sets to reduce payload size
    endpoints = [
        ("contacts", "contacts", "email,firstname,lastname"),
        ("companies", "companies", "name,domain"),
        ("deals", "deals", "dealname,amount,dealstage"),
    ]
    base = "https://api.hubapi.com/crm/v3/objects"
    for path, label, props in endpoints:
        url = f"{base}/{path}?limit=10&properties={requests.utils.quote(props)}"
        try:
            r = requests.get(url, headers=headers, timeout=15)
        except Exception as e:
            # Skip this object type if network error occurs
            print(f"HubSpot fetch {label} failed: {e}")
            continue
        if r.status_code != 200:
            print(f"HubSpot {label} error {r.status_code}: {r.text}")
            continue
        results = r.json().get("results", [])
        for obj in results:
            items.append(create_integration_item_metadata_object(obj, label[:-1].capitalize()))

    print(f"HubSpot IntegrationItems: {items}")
    return [i.to_dict() for i in items]
