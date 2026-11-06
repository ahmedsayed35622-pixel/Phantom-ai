from io import BytesIO

import pytest
from fastapi.testclient import TestClient

import app as phantom


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(phantom, "DB_PATH", tmp_path / "test-phantom.db")
    phantom.init_db()
    return TestClient(phantom.app)


def test_health_endpoint(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "online"
    assert response.json()["product"] == "PHANTOM-AI"


def test_url_triage_is_offline_and_reports_http(client):
    response = client.post("/api/analyze/url", json={"url": "http://example.test/login"})
    assert response.status_code == 200
    report = response.json()
    assert report["kind"] == "URL TRIAGE"
    assert any(item["title"] == "Unencrypted transport" for item in report["findings"])
    assert "No network request" in report["notice"] or any(
        "No network request" in item["detail"] for item in report["findings"]
    )


def test_invalid_url_rejected(client):
    response = client.post("/api/analyze/url", json={"url": "not a url%%%"})
    assert response.status_code == 400


def test_file_upload_calculates_sha256_and_detects_private_key(client):
    payload = b"-----BEGIN PRIVATE KEY-----\\nexample-placeholder-secret\\n-----END PRIVATE KEY-----"
    response = client.post(
        "/api/analyze/file",
        files={"file": ("sample.txt", BytesIO(payload), "text/plain")},
    )
    assert response.status_code == 200
    report = response.json()
    assert len(report["metadata"]["sha256"]) == 64
    assert any(item["title"] == "Possible private key" for item in report["findings"])


def test_report_download_and_history(client):
    created = client.post("/api/analyze/url", json={"url": "https://example.test"})
    assert created.status_code == 200
    scan_id = created.json()["id"]

    report = client.get(f"/api/report/{scan_id}")
    history = client.get("/api/scans")
    assert report.status_code == 200
    assert report.json()["id"] == scan_id
    assert any(item["id"] == scan_id for item in history.json())


def test_unsupported_file_extension_rejected(client):
    response = client.post(
        "/api/analyze/file",
        files={"file": ("sample.bin", BytesIO(b"data"), "application/octet-stream")},
    )
    assert response.status_code == 415
