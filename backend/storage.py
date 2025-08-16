"""Simple SQLite persistence for OAuth tokens.

Stores (provider, user_id, org_id, access_token, refresh_token, expires_at).
Used for automatic refresh (HubSpot & Notion demo).
"""
import os
import sqlite3
import time

DB_PATH = os.getenv("VECTORSHIFT_DB_PATH", os.path.join(os.path.dirname(__file__), "vectorshift.db"))

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS oauth_tokens (
                provider TEXT NOT NULL,
                user_id TEXT NOT NULL,
                org_id TEXT NOT NULL,
                access_token TEXT NOT NULL,
                refresh_token TEXT,
                expires_at INTEGER,
                PRIMARY KEY (provider, user_id, org_id)
            )
            """
        )

def save_tokens(provider: str, user_id: str, org_id: str, access_token: str, refresh_token: str | None, expires_in: int | None):
    expires_at = int(time.time()) + int(expires_in) if expires_in else None
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO oauth_tokens(provider, user_id, org_id, access_token, refresh_token, expires_at)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(provider, user_id, org_id) DO UPDATE SET
              access_token=excluded.access_token,
              refresh_token=COALESCE(excluded.refresh_token, oauth_tokens.refresh_token),
              expires_at=excluded.expires_at
            """,
            (provider, user_id, org_id, access_token, refresh_token, expires_at)
        )

def get_token_row(provider: str, user_id: str, org_id: str):
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "SELECT access_token, refresh_token, expires_at FROM oauth_tokens WHERE provider=? AND user_id=? AND org_id=?",
            (provider, user_id, org_id)
        )
        row = cur.fetchone()
    if not row:
        return None
    return {"access_token": row[0], "refresh_token": row[1], "expires_at": row[2]}

def needs_refresh(row: dict) -> bool:
    if not row:
        return False
    if row.get("expires_at") is None:
        return False
    return time.time() > (row["expires_at"] - 60)  # refresh 1 minute early

init_db()
