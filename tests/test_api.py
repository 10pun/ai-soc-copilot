import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_malicious_phishing_is_detected():
    response = client.post("/analyze", json={
        "subject": "Urgent: verify your password immediately",
        "sender": "security@micr0soft-support.com",
        "body": "Reset your credentials by opening http://185.10.20.30/login",
    })
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "malicious"
    assert data["score"] >= 70
    assert any(f["category"] == "credential-theft" for f in data["findings"])


def test_benign_message_is_not_flagged():
    response = client.post("/analyze", json={
        "subject": "Weekly team report",
        "sender": "teammate@example.com",
        "body": "Please review the attached report.",
    })
    assert response.json()["verdict"] == "benign"


def test_indicator_extraction():
    response = client.post("/indicators/extract", json={
        "subject": "Contact",
        "sender": "analyst@example.com",
        "body": "Investigate https://evil.example/payload and 192.0.2.15",
    })
    data = response.json()
    types = {item["type"] for item in data["indicators"]}
    assert {"url", "ip", "email"} <= types
