from io import BytesIO
import hashlib
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
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
    assert "no network request" in report["notice"].lower()


@pytest.mark.parametrize("bad_url", ["not a url%%%", "https://example.test:bad/", "https://example.test:99999/"])
def test_invalid_url_rejected(client, bad_url):
    response = client.post("/api/analyze/url", json={"url": bad_url})
    assert response.status_code == 400


def test_file_upload_calculates_sha256_and_detects_private_key(client):
    payload = b"-----BEGIN PRIVATE KEY-----\\nexample-placeholder-secret\\n-----END PRIVATE KEY-----"
    response = client.post(
        "/api/analyze/file",
        files={"file": ("sample.txt", BytesIO(payload), "text/plain")},
    )
    assert response.status_code == 200
    report = response.json()
    assert report["metadata"]["sha256"] == hashlib.sha256(payload).hexdigest()
    assert any(item["title"] == "Possible private key" for item in report["findings"])


def test_report_download_and_history(client):
    created = client.post("/api/analyze/url", json={"url": "https://example.test"})
    assert created.status_code == 200
    scan_id = created.json()["id"]
    report = client.get(f"/api/report/{scan_id}")
    history = client.get("/api/scans")
    stats = client.get("/api/stats")
    assert report.status_code == 200
    assert report.json()["id"] == scan_id
    assert any(item["id"] == scan_id for item in history.json())
    assert stats.json()["total"] == 1


def test_unsupported_file_extension_rejected(client):
    response = client.post(
        "/api/analyze/file",
        files={"file": ("sample.bin", BytesIO(b"data"), "application/octet-stream")},
    )
    assert response.status_code == 415


def test_malformed_apk_is_reported_without_execution(client):
    response = client.post(
        "/api/analyze/file",
        files={"file": ("sample.apk", BytesIO(b"not a zip archive"), "application/vnd.android.package-archive")},
    )
    assert response.status_code == 200
    assert any(item["title"] == "Invalid APK/archive structure" for item in response.json()["findings"])
