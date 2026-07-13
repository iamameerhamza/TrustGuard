# SPEC.md — Project Specification

> **Status**: `FINALIZED`

## Vision
A public, layered Free URL Trust / Phishing Detection Platform where someone can paste a URL and get a risk score, prediction, reasons, historical reputation, model confidence, basic audit trail, and optional explainable reasoning. Built systematically over 12 weeks.

## Goals
1. Provide reliable, real-time risk scoring (0-100) and prediction (safe/suspicious/phishing) for URLs.
2. Ensure high explainability and reasoning for any provided URL prediction.
3. Build incrementally with layers: Fast rules, Threat intel, Feature extraction, Machine Learning, Explainable reasoning, History/Community.

## Non-Goals (Out of Scope)
- Achieving perfection on day one.
- Depending on only one single method for detection.
- Executing JavaScript on the main API server.
- Mixing model training code with API code initially.
- Doing browser sandbox, community voting, LLM explanations, and final UI polish early in the project.

## Users
- Everyday users or security professionals looking to quickly verify the safety of a URL.

## Constraints
- **Security**: Must validate input URLs, block extremely long URLs, and avoid SSRF risks.
- **Performance**: Health check < 50ms, Cached scan < 100ms, Uncached scan < 300ms, Full scan with reputation < 1.5s.
- **Technical Stack**: FastAPI (backend), PostgreSQL (database), Redis (cache), Streamlit/React (frontend). Random Forest/XGBoost for ML.

## Success Criteria
- [ ] Paste a URL, return risk score and reasons, and save the scan in the DB.
- [ ] Successfully implement rule-based, ML-based, and threat-intel layers.
- [ ] Deliver a functional 12-week MVP that is actively monitored and performant.
