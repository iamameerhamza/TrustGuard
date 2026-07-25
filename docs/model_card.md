# Model Card: TrustGuard Baseline Random Forest

## Model Details
- **Model Type:** Random Forest Classifier (100 trees, scikit-learn)
- **Objective:** Classify URLs as benign (0) or phishing (1) based on extracted features.
- **Version:** 1.0 (Phase 5 Baseline)

## Training Data
- **Sources:**
  - Benign (0): Tranco Top 1 Million list
  - Phishing (1): OpenPhish, URLHaus
- **Dataset Size:** ~10,000 samples (balanced)

## Features
The model uses the following numerical/boolean features extracted from the URL:
1. `url_length`
2. `domain_length`
3. `subdomain_count`
4. `has_special_chars` (boolean represented as 0.0 or 1.0)
5. `entropy`
6. `suspicious_keywords`

## Performance Metrics
*(Evaluated on a 20% holdout test set)*
- **Accuracy:** 0.9995
- **Precision:** 0.9990
- **Recall:** 1.0000
- **F1 Score:** 0.9995

## Known Limitations
- The model relies solely on lexical and keyword features. It does not inspect page content, host reputation, or perform deep learning analysis.
- It may produce false positives for unusually structured benign domains (e.g., very long domains with many subdomains).

## Deployment & Calibration Notes (Phase 12 Final)
- The rule-based engine has been calibrated to heavily penalize deep subdomains (>2) and long suspicious keywords to minimize false negatives.
- When deployed, the model acts as a secondary verification check alongside the deterministic heuristic engine and a threat intelligence blacklist.
- Load testing confirms the `predict()` function introduces <5ms latency per request due to aggressive caching.
