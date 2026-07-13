---
phase: 1
plan: 2
wave: 1
---

# Plan 1.2: FastAPI Endpoints

## Objective
Initialize the FastAPI application and create the basic health and scan endpoints to connect the user interface to the normalizer module.

## Context
- .gsd/SPEC.md
- app/core/normalizer.py

## Tasks

<task type="auto">
  <name>FastAPI App Setup</name>
  <files>app/main.py, app/api/schemas.py</files>
  <action>
    - Create `app/api/schemas.py` with a Pydantic `ScanRequest` (accepts `url`) and `ScanResponse` (returns normalized fields for now).
    - Create `app/main.py` which initializes the FastAPI application.
    - Add a simple `GET /health` endpoint returning `{"status": "ok"}`.
  </action>
  <verify>python -c "from app.main import app; print('App loaded successfully')"</verify>
  <done>FastAPI app initializes correctly with a health endpoint.</done>
</task>

<task type="auto">
  <name>Basic Scan Endpoint</name>
  <files>app/main.py, tests/test_api.py</files>
  <action>
    - Add a `POST /scan` endpoint in `app/main.py` that takes `ScanRequest`.
    - It should pass the URL to `normalize_url`.
    - Return the normalized output as part of the response.
    - Create `tests/test_api.py` using `fastapi.testclient.TestClient` to verify both `/health` and `/scan` endpoints.
  </action>
  <verify>python -m pytest tests/test_api.py</verify>
  <done>The scan endpoint accepts a URL and returns normalized parsed data.</done>
</task>

## Success Criteria
- [ ] FastAPI app is executable.
- [ ] Health check endpoint functions and is tested.
- [ ] POST /scan endpoint receives a URL, runs it through the normalizer, and returns cleaned data.
