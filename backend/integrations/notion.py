# As Tejas Ghoti: Handles Notion OAuth and data fetch logic.
import os
import json
import requests
from fastapi import Request, HTTPException
from integrations.integration_item import IntegrationItem
from dotenv import load_dotenv
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis
from storage import save_tokens, get_token_row, needs_refresh

load_dotenv()

NOTION_CLIENT_ID = os.getenv("NOTION_CLIENT_ID") or "YOUR_NOTION_CLIENT_ID"
NOTION_CLIENT_SECRET = os.getenv("NOTION_CLIENT_SECRET") or "YOUR_NOTION_CLIENT_SECRET"
from urllib.parse import quote

NOTION_REDIRECT_URI = os.getenv("NOTION_REDIRECT_URI", "http://localhost:8000/integrations/notion/oauth2callback")
NOTION_AUTH_URL = "https://api.notion.com/v1/oauth/authorize"
NOTION_TOKEN_URL = "https://api.notion.com/v1/oauth/token"

async def authorize_notion(user_id: str, org_id: str):
    """Return the Notion OAuth URL. Stores a simple state token in Redis (single use)."""
    state = f"notion_{user_id}_{org_id}"
    await add_key_value_redis(f"notion_state:{org_id}:{user_id}", state, expire=600)
    encoded_redirect = quote(NOTION_REDIRECT_URI, safe="")
    url = (
        f"{NOTION_AUTH_URL}"
        f"?client_id={NOTION_CLIENT_ID}"
        f"&redirect_uri={encoded_redirect}"
        f"&response_type=code"
        f"&owner=user"
        f"&state={state}"
    )
    return url

async def oauth2callback_notion(request: Request):
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    # state format: notion_user_org – we stored directly
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code/state")
    _, user_id, org_id = state.split("_", 2)
    saved_state = await get_value_redis(f"notion_state:{org_id}:{user_id}")
    if not saved_state or saved_state.decode() != state:
        raise HTTPException(status_code=400, detail="Invalid or expired state")

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": NOTION_REDIRECT_URI,
    }
    auth = (NOTION_CLIENT_ID, NOTION_CLIENT_SECRET)
    resp = requests.post(NOTION_TOKEN_URL, data=data, auth=auth)
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    token_info = resp.json()
    token_info['user_id'] = user_id
    token_info['org_id'] = org_id
    await add_key_value_redis(
        f"notion_credentials:{org_id}:{user_id}", json.dumps(token_info), expire=600
    )
    await delete_key_redis(f"notion_state:{org_id}:{user_id}")
    save_tokens(
        "notion",
        user_id,
        org_id,
        token_info.get("access_token"),
        token_info.get("refresh_token"),
        token_info.get("expires_in"),
    )
    # simple auto close page
    return """<html><script>window.close();</script>Notion auth done.</html>"""

async def get_notion_credentials(user_id: str, org_id: str):
    raw = await get_value_redis(f"notion_credentials:{org_id}:{user_id}")
    if not raw:
        raise HTTPException(status_code=400, detail="No credentials found")
    await delete_key_redis(f"notion_credentials:{org_id}:{user_id}")
    return json.loads(raw)

async def get_items_notion(credentials_json: str):
    """Return list of IntegrationItem for Notion databases."""
    creds = json.loads(credentials_json)
    access_token = creds.get("access_token")
    url = "https://api.notion.com/v1/search"
    # Auto refresh if needed
    row = get_token_row("notion", creds.get("user_id", ""), creds.get("org_id", ""))
    if row and needs_refresh(row) and row.get("refresh_token"):
        data = {
            "grant_type": "refresh_token",
            "refresh_token": row["refresh_token"],
        }
        auth = (NOTION_CLIENT_ID, NOTION_CLIENT_SECRET)
        try:
            r_ref = requests.post(NOTION_TOKEN_URL, data=data, auth=auth, timeout=15)
            if r_ref.status_code == 200:
                ref_json = r_ref.json()
                save_tokens(
                    "notion",
                    creds.get("user_id", ""),
                    creds.get("org_id", ""),
                    ref_json.get("access_token"),
                    ref_json.get("refresh_token") or row.get("refresh_token"),
                    ref_json.get("expires_in"),
                )
                access_token = ref_json.get("access_token")
        except Exception:
            pass
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Notion-Version": "2022-06-28",
        "Content-Type": "application/json",
    }
    body = {"filter": {"value": "database", "property": "object"}}
    resp = requests.post(url, headers=headers, json=body)
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    items: list[IntegrationItem] = []
    for result in resp.json().get("results", []):
        name = None
        title = result.get("title", [])
        if title and isinstance(title, list):
            first = title[0]
            if isinstance(first, dict):
                name = first.get("plain_text") or first.get("text", {}).get("content")
        name = name or result.get("id")
        items.append(
            IntegrationItem(
                id=result.get("id"),
                name=name,
                type=result.get("object"),
                parent_id=None,
                parent_path_or_name=None,
            )
        )
    return [i.to_dict() for i in items]
