---
phase: 2
plan: 1
wave: 1
---

# Plan 2.1: Feature Extractor

## Objective
Implement a lightweight feature extractor to generate lexical, keyword, and entropy features from the normalized URL, avoiding any unnecessary external dependencies.

## Context
- .gsd/SPEC.md
- app/core/normalizer.py

## Tasks

<task type="auto">
  <name>Implement Extractor Logic</name>
  <files>app/core/extractor.py, tests/test_extractor.py</files>
  <action>
    - Create `app/core/extractor.py` containing a function `extract_features(normalized: dict) -> dict`.
    - Extract basic features using standard library only: `url_length`, `domain_length`, `subdomain_count`, `has_special_chars`, `entropy` (using `math.log2`), and `suspicious_keywords` count.
    - Write `tests/test_extractor.py` to verify the outputs. (Keep it simple, test 1-2 edge cases).
  </action>
  <verify>source venv/bin/activate && pytest tests/test_extractor.py</verify>
  <done>Extractor calculates features using only standard libraries and passes tests.</done>
</task>

<task type="auto">
  <name>API Integration</name>
  <files>app/api/schemas.py, app/main.py, tests/test_api.py</files>
  <action>
    - Update `ScanResponse` in `schemas.py` to include a `features: dict` field.
    - In `main.py`, pass the normalized URL dict to `extract_features` and include it in the response.
    - Update `tests/test_api.py` to check that `features` is present in the response.
  </action>
  <verify>source venv/bin/activate && pytest tests/test_api.py</verify>
  <done>Scan API returns features along with normalized data.</done>
</task>

## Success Criteria
- [ ] `extractor.py` created with no new pip dependencies.
- [ ] Tests pass for extractor logic.
- [ ] API successfully returns feature set.
