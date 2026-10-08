from fastapi.testclient import TestClient

from pii_tokenizer.main import app


def test_health_endpoint():
    # TP-API-01
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
