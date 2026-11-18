from fastapi.testclient import TestClient

from app import database
from app.main import app

client = TestClient(app)
ADMIN = {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}


def test_health_and_scan_lifecycle():
    assert client.get("/api/health").status_code == 200
    response = client.post("/api/analyze", json={"policy": ADMIN, "policy_name": "admin"})
    assert response.status_code == 201
    body = response.json()
    assert body["risk_level"] == "Critical"
    scan_id = body["scan_id"]
    assert client.get(f"/api/scans/{scan_id}").json()["policy_name"] == "admin"
    assert [s["scan_id"] for s in client.get("/api/scans").json()] == [scan_id]
    assert client.delete(f"/api/scans/{scan_id}").status_code == 204
    assert client.get(f"/api/scans/{scan_id}").status_code == 404


def test_policy_without_findings_leaves_no_trace_in_database(isolated_database):
    # Findings quote matched resources as evidence; a statement with no findings must not be stored at all.
    marker = "arn:aws:iam::123456789012:role/UniqueMarkerRole"
    policy = {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": marker}}
    assert client.post("/api/analyze", json={"policy": policy}).status_code == 201
    assert marker.encode() not in isolated_database.read_bytes()


def test_uses_isolated_database(isolated_database):
    assert database.db_path() == isolated_database
    client.post("/api/analyze", json={"policy": ADMIN})
    assert isolated_database.exists()


def test_policy_as_json_string():
    response = client.post("/api/analyze", json={"policy": '{"Statement": {"Effect": "Allow", "Action": "iam:Pass*", "Resource": "*"}}'})
    assert response.status_code == 201
    assert "IAM-003" in response.json()["rules_triggered"]


def test_api_validation():
    assert client.post("/api/analyze", json={"policy": {}}).status_code == 422
    assert client.post("/api/analyze", json={"policy": "{not json"}).status_code == 422


def test_rejects_oversized_policy():
    huge = {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "x" * 260_000}}
    assert client.post("/api/analyze", json={"policy": huge}).status_code == 413


def test_missing_scan_returns_404():
    assert client.get("/api/scans/does-not-exist").status_code == 404
    assert client.delete("/api/scans/does-not-exist").status_code == 404


def test_samples_and_rules():
    names = {s["name"] for s in client.get("/api/samples").json()}
    assert {"critical_admin", "moderate_risk", "safer_read_only"} <= names
    assert client.get("/api/samples/critical_admin").status_code == 200
    assert len(client.get("/api/rules").json()) == 10


def test_sample_path_traversal_is_blocked():
    assert client.get("/api/samples/..%2F..%2Fbackend%2Frequirements").status_code == 404
    assert client.get("/api/samples/does_not_exist").status_code == 404
