# PHANTOM-AI

**Defensive Security Intelligence Workbench — MVP 0.1.0**

PHANTOM-AI is a local-first defensive analysis platform. This first release establishes the product foundation: a dark analyst dashboard, a FastAPI analysis service, a local SQLite case history, and downloadable JSON reports.

## MVP capabilities

- URL triage using offline structural heuristics. The server does **not** visit the submitted URL.
- File triage: SHA-256, file size, byte entropy, selected suspicious string indicators, and secret-pattern detection.
- APK/ZIP container inspection without extracting or executing uploaded content.
- Heuristic Android permission string checks (not a complete binary Android Manifest decoder).
- Risk score, findings, case history, and JSON report download.
- Responsive analyst dashboard.

## Run locally

Requires Python 3.10+.

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000

For a hosted environment such as Replit, install the requirements and run:

```bash
uvicorn app:app --host 0.0.0.0 --port 8000
```

## Safety and limitations

- Only analyze files and systems you own or are explicitly authorized to assess.
- This MVP performs static, heuristic triage. It does not execute uploaded files, exploit targets, or perform network port scans.
- URL analysis is offline and does not check DNS, TLS certificates, redirects, reputation feeds, or live website headers.
- Android binary XML parsing is not yet implemented; permission detection is best-effort string matching.
- A clean result is not a guarantee that a file, app, or URL is safe. Validate findings with trusted tools and human review.
- Uploaded files are processed in memory and are not retained as uploads. Scan metadata and findings are stored in the local SQLite database.

## Architecture

- `app.py`: API, analysis heuristics, and SQLite persistence.
- `static/index.html`: dashboard structure.
- `static/styles.css`: responsive dark analyst interface.
- `static/app.js`: dashboard navigation, API calls, and report rendering.

## Planned roadmap

1. Robust APK parsing and manifest/component analysis.
2. SBOM and dependency vulnerability analysis with trusted advisory sources.
3. Safe, allowlisted web assessment with explicit authorization controls.
4. Evidence graph and attack-path correlation.
5. AI-assisted explanation grounded in collected evidence, with citations and confidence.
6. Isolated sandbox integrations and signed PDF reports.

**Project principle:** evidence first, explainable findings, human verification.
