import json
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_root():
    r = client.get("/")
    assert r.status_code == 200
    assert r.json().get("Ping") == "Pong"

def test_airtable_authorize_requires_form():
    # Missing form fields should 422
    r = client.post("/integrations/airtable/authorize")
    assert r.status_code == 422

def test_openapi_has_integration_paths():
    r = client.get("/openapi.json")
    assert r.status_code == 200
    doc = r.json()
    for ep in [
        "/integrations/airtable/authorize",
        "/integrations/notion/authorize",
        "/integrations/hubspot/authorize",
    ]:
        assert ep in doc["paths"], f"Missing {ep} in OpenAPI spec"
