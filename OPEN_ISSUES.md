# Good First Issues for Public Contribution

Copy the text below into new GitHub issues and label them with `good first issue` to attract public contributors! These issues align with our Market-Competitive Roadmap and 2030 Vision.

---

### Issue 1: Add SHAP Explainability to Random Forest Model (Phase 3)
**Title:** `[FEAT] Add SHAP Explainability to the Random Forest Model`
**Body:**
```markdown
## The Goal
TrustGuard currently uses a Random Forest model (`phishing_rf.joblib`) to score URLs. To reach our next milestone, we need the model to explain *why* it gave a specific score.

## Tasks
1. Integrate the `shap` Python library in `app/core/predictor.py`.
2. Modify the model inference logic so it returns the top 3 contributing features (e.g., `domain_age`, `entropy`) alongside the raw score.
3. Update the API response schema to include an `explanations` array.

## Requirements
- No breaking changes to existing tests.
- Provide a new test case in `tests/test_api.py` validating the explanations.

Let us know in the comments if you want to claim this!
```

---

### Issue 2: Build FastAPI Rate-Limiting Middleware (Phase 4)
**Title:** `[FEAT] Build Rate-Limiting Middleware for the /v1/scan API`
**Body:**
```markdown
## The Goal
We want to expose our API for public use, but we need to protect it from abuse. We need a rate limiter.

## Tasks
1. Add a FastAPI middleware or dependency in `app/middleware.py` (or similar) to track request IP addresses.
2. Implement an in-memory or Redis-based rate limit (e.g., max 100 requests per IP per day for free tier).
3. Return an `HTTP 429 Too Many Requests` status when the limit is exceeded.

## Requirements
- Must not slow down standard requests.
- Add test coverage verifying the 429 response.

Comment if you want to tackle this!
```

---

### Issue 3: Export Model to ONNX for Browser Inference (Phase A - 2030 Vision)
**Title:** `[FEAT] Export Random Forest model to ONNX format`
**Body:**
```markdown
## The Goal
Our long-term 2030 vision involves running the TrustGuard ML model directly inside the user's browser for maximum privacy and zero latency. The first step is exporting our Scikit-Learn Random Forest model to ONNX.

## Tasks
1. Create a script `scripts/export_onnx.py`.
2. Use `skl2onnx` to load `models/phishing_rf.joblib` and convert it into `phishing_rf.onnx`.
3. Verify that the ONNX model produces the exact same probabilities as the original joblib model for a test URL.

## Requirements
- Output the `.onnx` file to the `models/` directory.

This is a fantastic issue for anyone interested in MLOps or Edge AI. Drop a comment to claim it!
```
