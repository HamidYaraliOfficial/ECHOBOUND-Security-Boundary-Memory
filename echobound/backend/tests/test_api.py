import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient


def test_health_endpoint(monkeypatch, tmp_path):
    monkeypatch.setenv("ECHOBOUND_DB", str(tmp_path / "test.db"))
    from echobound.api import app
    client = TestClient(app)
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json()["product"] == "ECHOBOUND"


def test_operating_hours_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("ECHOBOUND_DB", str(tmp_path / "test2.db"))
    from echobound.api import app
    client = TestClient(app)
    resp = client.post("/api/v1/context/operating-hours/quick-setup", json={
        "tenant": "default", "timezone": "UTC", "start_hhmm": "09:00", "end_hhmm": "17:00",
        "weekdays": [0, 1, 2, 3, 4],
    })
    assert resp.status_code == 200
    status_resp = client.get("/api/v1/context/operating-hours/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["configured"] is True
