# ROADMAP.md

> **Current Milestone**: 12-Week Launch
> **Goal**: Build a fully functional, layered URL Trust / Phishing Detection Platform over 12 weeks.

## Must-Haves
- [ ] Fast, rule-based heuristics engine
- [ ] Machine learning based scoring (Random Forest/XGBoost)
- [ ] Threat intelligence layer (Blacklists)
- [ ] Explanations and audit trails
- [ ] Public-facing Streamlit/React frontend

## Phases

### Phase 1: Project skeleton, clean setup, and URL handling
**Status**: ⬜ Not Started
**Objective**: Clean repo, URL validation, normalization, health endpoint.

### Phase 2: Feature extraction foundation
**Status**: ⬜ Not Started
**Objective**: Working feature extractor (lexical, keyword, entropy) with tests.

### Phase 3: Basic risk rules and audit logs
**Status**: ⬜ Not Started
**Objective**: First real scanner with an audit trail, storing scan request and result in DB.

### Phase 4: Dataset collection pipeline
**Status**: ⬜ Not Started
**Objective**: Repeatable dataset pipeline collecting from Tranco, OpenPhish, URLHaus.

### Phase 5: Baseline machine learning
**Status**: ⬜ Not Started
**Objective**: Trained baseline model (Random Forest) with proper metrics and a model card.

### Phase 6: Prediction API and caching
**Status**: ⬜ Not Started
**Objective**: Fast API with caching and ML predictions.

### Phase 7: Threat intelligence layer
**Status**: ⬜ Not Started
**Objective**: Instant known-threat detection with local blacklists and reputation.

### Phase 8: Explainability engine
**Status**: ⬜ Not Started
**Objective**: Human-readable reasoning utilizing rules and optional LLM context.

### Phase 9: Security hardening and audit layer
**Status**: ⬜ Not Started
**Objective**: Safer, rate-limited, and traceable system with model version logging.

### Phase 10: Frontend and user flow
**Status**: ⬜ Not Started
**Objective**: Usable public-facing interface connecting frontend to API.

### Phase 11: Historical intelligence and community reporting
**Status**: ⬜ Not Started
**Objective**: History tracking, community voting, and report layers.

### Phase 12: Final stabilization and release
**Status**: ⬜ Not Started
**Objective**: Final release candidate, load testing, calibration, and documentation.
