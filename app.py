from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import ipaddress
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "phantom.db"
MAX_UPLOAD = 25 * 1024 * 1024
ALLOWED_EXTENSIONS = {".apk", ".zip", ".txt", ".json", ".js", ".py", ".html", ".xml", ".pdf", ".exe", ".dll", ".so", ".dex"}

app = FastAPI(title="PHANTOM-AI", version="0.1.0", description="Defensive security analysis workbench")
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")

RISKY_PERMISSIONS = {
    "READ_SMS": ("HIGH", "Can read SMS messages"),
    "RECEIVE_SMS": ("MEDIUM", "Can receive SMS messages"),
    "SEND_SMS": ("HIGH", "Can send SMS messages"),
    "READ_CALL_LOG": ("HIGH", "Can read call history"),
    "READ_CONTACTS": ("MEDIUM", "Can access contacts"),
    "RECORD_AUDIO": ("MEDIUM", "Can record audio"),
    "CAMERA": ("LOW", "Can access the camera"),
    "ACCESS_FINE_LOCATION": ("MEDIUM", "Can access precise location"),
    "REQUEST_INSTALL_PACKAGES": ("HIGH", "Can request installation of other packages"),
    "SYSTEM_ALERT_WINDOW": ("MEDIUM", "Can draw over other apps"),
    "BIND_ACCESSIBILITY_SERVICE": ("HIGH", "May use accessibility capabilities"),
    "QUERY_ALL_PACKAGES": ("MEDIUM", "Can enumerate installed applications"),
}
SECRET_PATTERNS = [
    ("Possible private key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Possible cloud access key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("Possible hard-coded token", re.compile(rb"(?i)(api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*['\"][^'\"\s]{8,}")),
    ("Possible password in source", re.compile(rb"(?i)(password|passwd)\s*[:=]\s*['\"][^'\"\s]{4,}")),
]
SUSPICIOUS_STRINGS = [
    (b"Runtime.getRuntime", "Runtime command execution reference"),
    (b"su -c", "Root shell command reference"),
    (b"/system/bin/sh", "Shell execution path"),
    (b"DexClassLoader", "Dynamic code loading reference"),
    (b"loadLibrary", "Native library loading reference"),
    (b"getDeviceId", "Device identifier access reference"),
]

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY, kind TEXT NOT NULL, target TEXT NOT NULL,
            score INTEGER NOT NULL, verdict TEXT NOT NULL, created_at TEXT NOT NULL,
            result_json TEXT NOT NULL
        )""")

init_db()

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())

def score_findings(findings):
    weights = {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 10, "LOW": 3, "INFO": 0}
    score = min(100, sum(weights.get(x["severity"], 0) for x in findings))
    verdict = "HIGH RISK" if score >= 60 else "REVIEW REQUIRED" if score >= 25 else "LOW RISK"
    return score, verdict

def save_scan(kind, target, findings, metadata=None):
    import uuid
    score, verdict = score_findings(findings)
    record = {
        "id": uuid.uuid4().hex[:12],
        "kind": kind,
        "target": target,
        "score": score,
        "verdict": verdict,
        "created_at": now(),
        "findings": findings,
        "metadata": metadata or {},
        "notice": "Automated triage only. Findings require human validation; absence of findings is not proof of safety."
    }
    with db() as conn:
        conn.execute(
            "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)",
            (record["id"], kind, target, score, verdict, record["created_at"], json.dumps(record))
        )
    return record

def analyze_url(value: str):
    raw = value.strip()
    candidate = raw if "://" in raw else "https://" + raw
    parsed = urlparse(candidate)
    findings = []
    if parsed.scheme not in ("http", "https") or not parsed.hostname or any(ch.isspace() for ch in parsed.hostname) or "%" in parsed.hostname:
        raise HTTPException(400, "Enter a valid http or https URL or domain.")
    host = parsed.hostname.lower()
    if parsed.scheme == "http":
        findings.append({"severity": "MEDIUM", "title": "Unencrypted transport", "detail": "The URL uses HTTP. Data may be exposed in transit."})
    if "@" in parsed.netloc:
        findings.append({"severity": "HIGH", "title": "User-info URL pattern", "detail": "The address contains an @ sign before the host, a pattern sometimes used to disguise destinations."})
    try:
        ipaddress.ip_address(host)
        findings.append({"severity": "MEDIUM", "title": "Direct IP destination", "detail": "The URL points directly to an IP address rather than a domain name."})
    except ValueError:
        pass
    if host.startswith("xn--") or ".xn--" in host:
        findings.append({"severity": "MEDIUM", "title": "Internationalized domain label", "detail": "The hostname contains punycode. Verify the displayed domain carefully."})
    if len(host) > 50 or host.count("-") >= 4:
        findings.append({"severity": "LOW", "title": "Unusual hostname structure", "detail": "The hostname is unusually long or contains many hyphens."})
    if len(parsed.query) > 180:
        findings.append({"severity": "LOW", "title": "Long query string", "detail": "A long query string can obscure tracking or redirect parameters."})
    if not findings:
        findings.append({"severity": "INFO", "title": "No obvious URL red flags", "detail": "Only local syntax heuristics were checked. No network request or reputation lookup was performed."})
    return save_scan("URL TRIAGE", raw, findings, {"hostname": host, "scheme": parsed.scheme, "path": parsed.path or "/"})

async def analyze_file(upload: UploadFile):
    name = Path(upload.filename or "uploaded-file").name
    ext = Path(name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(415, "Unsupported file type for this MVP.")
    data = await upload.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "Maximum upload size is 25 MB.")
    findings = []
    file_hash = hashlib.sha256(data).hexdigest()
    file_entropy = round(entropy(data), 3)
    metadata = {"filename": name, "size_bytes": len(data), "sha256": file_hash, "entropy": file_entropy, "extension": ext}
    if not data:
        findings.append({"severity": "LOW", "title": "Empty file", "detail": "The uploaded file contains no data."})
    if file_entropy > 7.2 and len(data) > 4096:
        findings.append({"severity": "LOW", "title": "High byte entropy", "detail": "The file has high entropy. This can occur in compressed, encrypted, or packed files and is not proof of malware."})
    for title, pattern in SECRET_PATTERNS:
        if pattern.search(data):
            findings.append({"severity": "HIGH", "title": title, "detail": "A pattern resembling a secret was found. Treat it as exposed until verified and rotated if genuine."})
    for marker, title in SUSPICIOUS_STRINGS:
        if marker in data:
            findings.append({"severity": "MEDIUM", "title": title, "detail": "A potentially sensitive capability reference was found. Context is required to determine whether it is harmful."})
    if ext == ".apk" or data[:2] == b"PK":
        try:
            import zipfile
            from io import BytesIO
            with zipfile.ZipFile(BytesIO(data)) as archive:
                names = archive.namelist()
                metadata["archive_entries"] = len(names)
                metadata["contains_android_manifest"] = "AndroidManifest.xml" in names
                metadata["native_libraries"] = sum(1 for x in names if x.startswith("lib/") and x.endswith(".so"))
                if any(x.endswith(".dex") for x in names):
                    metadata["dex_files"] = sum(1 for x in names if x.endswith(".dex"))
                manifest = b""
                if "AndroidManifest.xml" in names:
                    manifest = archive.read("AndroidManifest.xml")
                # Binary Android XML is not fully decoded here; search for permission identifiers as triage only.
                for permission, (severity, explanation) in RISKY_PERMISSIONS.items():
                    if permission.encode() in manifest:
                        findings.append({"severity": severity, "title": "Android permission: " + permission, "detail": explanation + ". Confirm whether this access is necessary for the app."})
                if not metadata["contains_android_manifest"] and ext == ".apk":
                    findings.append({"severity": "MEDIUM", "title": "APK manifest not found", "detail": "The file has an APK extension but no AndroidManifest.xml entry was detected."})
        except zipfile.BadZipFile:
            if ext == ".apk":
                findings.append({"severity": "HIGH", "title": "Invalid APK/archive structure", "detail": "The file extension suggests an APK, but its ZIP structure could not be read."})
    if not findings:
        findings.append({"severity": "INFO", "title": "No heuristic indicators found", "detail": "The enabled static checks did not identify a known pattern. This does not certify the file as safe."})
    return save_scan("FILE ANALYSIS", name, findings, metadata)

@app.get("/")
def home():
    return FileResponse(BASE / "static" / "index.html")

@app.get("/api/health")
def health():
    return {"status": "online", "product": "PHANTOM-AI", "version": app.version}

@app.get("/api/scans")
def scans():
    with db() as conn:
        rows = conn.execute("SELECT result_json FROM scans ORDER BY created_at DESC LIMIT 50").fetchall()
    return [json.loads(row["result_json"]) for row in rows]

@app.get("/api/stats")
def stats():
    with db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        high = conn.execute("SELECT COUNT(*) FROM scans WHERE score >= 60").fetchone()[0]
        medium = conn.execute("SELECT COUNT(*) FROM scans WHERE score >= 25 AND score < 60").fetchone()[0]
    return {"total": total, "high_risk": high, "review": medium, "protected": max(0, total - high - medium)}

@app.post("/api/analyze/url")
def url_scan(payload: dict):
    value = str(payload.get("url", ""))[:2048]
    return analyze_url(value)

@app.post("/api/analyze/file")
async def file_scan(file: UploadFile = File(...)):
    return await analyze_file(file)

@app.get("/api/report/{scan_id}")
def report(scan_id: str):
    with db() as conn:
        row = conn.execute("SELECT result_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Report not found")
    return JSONResponse(json.loads(row["result_json"]), headers={"Content-Disposition": f'attachment; filename="phantom-report-{scan_id}.json"'})
