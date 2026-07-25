# System Architecture

## 1) System Purpose
The system receives a URL and estimates whether it is safe, suspicious, or high-risk in four layers:
1. Quick trust checks
2. Model-based scoring
3. Deeper webpage inspection
4. Plain-language explanation for users

## 2) High-Level Architecture

```text
[User / Browser / Demo UI]
          |
          v
[API Gateway / FastAPI Backend]
          |
          v
[Input Normalizer]
          |
          +--> [Phase 1: Trust Signals]  - HTTPS/SSL, WHOIS age, Blacklists, URL structure
          +--> [Phase 2: Risk Engine]    - Rule engine, ML score
          +--> [Phase 3: Web Inspection] - Redirects, Forms/scripts
          +--> [Phase 4: Explanation]    - Human-readable reason, Confidence, Recommendation
          |
          v
[Database / Logs / Model Store / Feed Cache]
```

## 3) Main Modules

| Module | Key Functions |
| :--- | :--- |
| Input Normalizer | `normalize_url()`, `extract_domain()`, `parse_query()` |
| Trust Signals | `check_https()`, `lookup_whois_age()`, `check_blacklist()`, `extract_lexical_features()` |
| Rule Engine | `apply_rules()`, `assign_risk_level()`, `generate_reason_codes()` |
| ML Scoring | `encode_url()`, `predict_probability()`, `train_model()`, `save_model_version()` |
| Web Inspection | `fetch_page()`, `detect_redirects()`, `find_forms()`, `capture_screenshot()` |
| Explanation Engine | `summarize_signals()`, `convert_to_plain_language()`, `build_user_message()` |
| Data Storage | SQLite (demo) / PostgreSQL (production) / Redis (cache) |
| Monitoring | `refresh_feeds()`, `monitor_latency()`, `track_false_positives()`, `schedule_retrain()` |

## 4) Tech Stack

| Module | Technology |
| :--- | :--- |
| API | FastAPI |
| UI | React (Vite) |
| URL parsing | Python stdlib + tldextract |
| WHOIS | python-whois |
| ML | scikit-learn (Random Forest) |
| Sandbox | Playwright / aiohttp |
| Storage | SQLite / PostgreSQL |
| Cache | Redis |
| Deployment | Docker |

## 5) Data Flow
```
Input URL -> Normalizer -> Trust Signals -> Rule Engine -> ML Model -> Web Inspection -> Explanation -> Result
```
