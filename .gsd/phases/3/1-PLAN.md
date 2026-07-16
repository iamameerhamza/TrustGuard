---
phase: 3
plan: 1
wave: 1
---

# Plan 3.1: Rule Engine and Audit Log

## Objective
Implement a basic risk scoring rule engine and a lightweight SQLite audit trail to store scan results without adding any new ORM or DB dependencies (Ponytail rule).

## Context
- .gsd/ROADMAP.md
- app/core/extractor.py

## Tasks

<task type="auto">
  <name>Basic Risk Rules</name>
  <files>app/core/rules.py, tests/test_rules.py</files>
  <action>
    - Create `app/core/rules.py` with `calculate_risk(features: dict) -> dict`.
    - Implement simple heuristic rules (e.g., each suspicious keyword adds +10 risk, high entropy adds +20, etc). Ensure the score stays within 0-100.
    - Return a dict with `risk_score` (0-100) and a `prediction` ("safe", "suspicious", "phishing").
    - Write a basic test in `tests/test_rules.py`.
  </action>
  <verify>source venv/bin/activate && pytest tests/test_rules.py</verify>
  <done>Risk scoring logic functions correctly and tests pass.</done>
</task>

<task type="auto">
  <name>Database Audit Trail</name>
  <files>app/core/db.py, tests/test_db.py</files>
  <action>
    - Create `app/core/db.py` using Python's built-in `sqlite3` (Ponytail rule: avoid SQLAlchemy bloat for a simple audit log).
    - Create `init_db(db_path="trustguard.db")` to create a `scans` table (`id` INTEGER PRIMARY KEY, `url` TEXT, `risk_score` INTEGER, `prediction` TEXT, `timestamp` DATETIME DEFAULT CURRENT_TIMESTAMP).
    - Create `log_scan(db_path, url, risk_score, prediction)`.
    - Write a basic test using an in-memory `:memory:` database in `tests/test_db.py`.
  </action>
  <verify>source venv/bin/activate && pytest tests/test_db.py</verify>
  <done>SQLite database initialization and inserts work correctly without external dependencies.</done>
</task>

<task type="auto">
  <name>API Integration</name>
  <files>app/main.py, app/api/schemas.py, tests/test_api.py</files>
  <action>
    - Update `ScanResponse` in `schemas.py` to include `risk_score: int` and `prediction: str`.
    - In `main.py`, run `init_db()` on startup (using FastAPI lifespan or just at module level).
    - In the `/scan` endpoint, call `calculate_risk()`, call `log_scan()`, and return the updated `ScanResponse`.
    - Update `tests/test_api.py` to assert the new fields are returned.
  </action>
  <verify>source venv/bin/activate && pytest tests/test_api.py</verify>
  <done>Scan API returns risk scores and stores them in the DB.</done>
</task>

## Success Criteria
- [ ] Rule engine assigns risk scores based on features.
- [ ] Audit trail logs results to SQLite using stdlib `sqlite3`.
- [ ] API successfully returns risk scores and predictions.
