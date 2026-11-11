from fastapi.testclient import TestClient
from app.main import app
from app import database

client = TestClient(app)
def test_health_and_scan_lifecycle():
    database.clear_scans()
    assert client.get("/api/health").status_code == 200
    response = client.post("/api/analyze", json={"policy":{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}})
    assert response.status_code == 201
    scan_id = response.json()["scan_id"]
    assert client.get(f"/api/scans/{scan_id}").status_code == 200
    assert client.delete(f"/api/scans/{scan_id}").status_code == 204
def test_api_validation():
    assert client.post("/api/analyze", json={"policy": {}}).status_code == 422
