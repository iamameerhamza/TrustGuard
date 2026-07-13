---
phase: 1
plan: 1
wave: 1
---

# Plan 1.1: Project Skeleton & Normalizer

## Objective
Set up the core Python environment, API structure, and the URL Normalizer module which cleans raw user input before feature extraction.

## Context
- .gsd/SPEC.md
- .gsd/ARCHITECTURE.md

## Tasks

<task type="auto">
  <name>Initialize Project Skeleton</name>
  <files>requirements.txt, app/__init__.py, app/api/__init__.py, app/core/__init__.py, tests/__init__.py</files>
  <action>
    - Create the base directory structure for the application (app/api, app/core, tests).
    - Create a requirements.txt with `fastapi`, `uvicorn`, `pydantic`, `pytest`, `httpx`.
    - Create empty __init__.py files in the directories to make them Python modules.
  </action>
  <verify>cat requirements.txt && ls app/core/</verify>
  <done>Directories exist and requirements.txt contains necessary packages.</done>
</task>

<task type="auto">
  <name>Implement URL Normalizer</name>
  <files>app/core/normalizer.py, tests/test_normalizer.py</files>
  <action>
    - Implement `normalize_url(url: str)` in `app/core/normalizer.py`.
    - It must handle missing schemas (add `http://` if missing), convert to lowercase, and use `urllib.parse` to extract `domain`, `path`, and `query`.
    - Create `tests/test_normalizer.py` with pytest tests verifying valid URLs, URLs without schemas, and complex paths.
  </action>
  <verify>python -m pytest tests/test_normalizer.py</verify>
  <done>Normalizer correctly parses URLs and all tests pass.</done>
</task>

## Success Criteria
- [ ] Directory structure is in place.
- [ ] Requirements are documented.
- [ ] URL normalizer robustly handles edge cases and passes tests.
