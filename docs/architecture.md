# System Architecture

## 1) System Purpose
The system receives a URL or online artifact and estimates whether it is safe, suspicious, or high-risk. It does this in layers: 
1. Quick trust checks first
2. Model-based scoring next
3. Deeper webpage inspection later
4. A plain-language explanation for users.

*(Integrates intelligence from sources like URLhaus to inform the initial trust checks).*

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
          +--> [Phase 1: Trust Signals]
          |         - HTTPS / SSL
          |         - WHOIS age
          |         - Blacklists / feeds
          |         - URL structure
          |
          +--> [Phase 2: Risk Engine]
          |         - Rule engine
          |         - ML score
          |
          +--> [Phase 3: Web Inspection]
          |         - Redirects
          |         - Forms / scripts
          |         - Screenshot analysis
          |
          +--> [Phase 4: Explanation Engine]
          |         - Human-readable reason
          |         - Confidence
          |         - Recommendation
          |
          v
[Database / Logs / Model Store / Feed Cache]
```

FastAPI is a strong fit for this role because it supports request and response handling cleanly and provides built-in interactive docs for demos.

## 3) Main Modules

### A. User Interface Module
This is where the public or demo user submits a URL. It can be a simple web form, a Streamlit page, or a browser-based dashboard. The output is a trust verdict plus a readable explanation.
**Inputs:** URL text, Optional category (e.g., email link or webpage), Optional screenshot upload.
**Outputs:** Verdict, Confidence score, Risk reasons, Suggested next step.

### B. API Module
This receives the user input and sends it to the internal services. In FastAPI, you typically define routes and request bodies for this kind of work, which makes the system easy to document and test.
**Inputs:** POST request with URL, Optional metadata headers, Optional user session info.
**Outputs:** JSON response, Status code, Structured explanation data.

### C. Input Normalizer
This module cleans the URL before analysis. It removes formatting noise, handles case normalization, extracts the domain and path, and prepares the string for later checks.
**Inputs:** Raw user URL.
**Outputs:** Clean URL, Domain, TLD, Path, Query string.
**Functions:** `normalize_url()`, `extract_domain()`, `parse_query()`

### D. Phase 1 Trust Signal Module
This is the first analytical layer and the easiest to explain publicly. It checks domain age, HTTPS, WHOIS, threat feeds, and lexical URL patterns. OpenPhish provides phishing feed data and metadata, while URLhaus provides malicious URL feeds and feed categories.
**Inputs:** Clean URL, Domain, WHOIS data, SSL/TLS data, Feed data.
**Outputs:** Feature vector, Signal flags, Initial risk points.
**Functions:** `check_https()`, `lookup_whois_age()`, `check_blacklist()`, `extract_lexical_features()`, `compute_signal_score()`

### E. Rule Engine
This module applies human-defined rules. It is good for obvious cases and for explainability because the reason is easy to show to users.
**Inputs:** Phase 1 signal vector.
**Outputs:** Rule verdict, Triggered rule list, Risk tier.
**Functions:** `apply_rules()`, `assign_risk_level()`, `generate_reason_codes()`

### F. ML Scoring Module
This module handles uncertain cases. It can use a basic classifier first, then later a Char-CNN or other URL classifier if you want a stronger model-based layer.
**Inputs:** Encoded URL features, Training labels, Model file.
**Outputs:** Probability score, Predicted label, Confidence.
**Functions:** `encode_url()`, `predict_probability()`, `train_model()`, `evaluate_model()`, `save_model_version()`

### G. Web Inspection Module
This module checks what happens when the page is actually opened in a safe environment. It looks for redirects, suspicious forms, external scripts, and page behavior that can reveal phishing kits.
**Inputs:** URL, Browser session, Sandbox environment.
**Outputs:** Redirect chain, Page DOM summary, Form count, Script list, Screenshot.
**Functions:** `fetch_page()`, `detect_redirects()`, `find_forms()`, `check_script_behavior()`, `capture_screenshot()`

### H. Explanation Engine
This module turns the analysis into readable text. It should explain what was checked, why it looks risky, how confident the system is, and what the user should do next. This is especially important for public understanding and trust.
**Inputs:** Risk score, Rule hits, ML probability, Web inspection results.
**Outputs:** Natural-language explanation, Recommendation, Confidence summary.
**Functions:** `summarize_signals()`, `convert_to_plain_language()`, `build_user_message()`, `add_recommendation()`

### I. Data Storage Module
This module stores history, logs, model versions, and feed snapshots. It also makes later review and monitoring possible.
**Inputs:** Results, Signals, User submissions, Model metadata.
**Outputs:** Database records, Logs, Audit trail.
**Tools:** SQLite for demo, PostgreSQL for larger deployment, Redis for caching.

### J. Monitoring and Update Module
This module checks feed freshness, model drift, and system health. It is important because phishing data changes quickly, and the platform should not rely on stale indicators.
**Inputs:** Feed status, Log files, Performance metrics.
**Outputs:** Alerts, Update schedule, Retraining triggers.
**Functions:** `refresh_feeds()`, `monitor_latency()`, `track_false_positives()`, `schedule_retrain()`

## 4) Data Flow by Phase

### Phase 1 Flow
1. User submits URL.
2. Input normalizer cleans it.
3. Trust signal module checks WHOIS, HTTPS, feeds, and URL structure.
4. Rule engine assigns a first risk score.
5. Results are stored. *(Integrates intelligence from OpenPhish).*

### Phase 2 Flow
1. If the case is uncertain, the ML module encodes the URL.
2. The model predicts phishing or legitimate.
3. The probability is combined with the rule score.
4. Final label is produced. *(Informed by broad datasets like URLhaus).*

### Phase 3 Flow
1. If still uncertain, the system loads the page in a safe browser or sandbox.
2. It checks redirects, scripts, and forms.
3. Visual and behavioral signs refine the risk. *(Critical for detecting malicious payloads noted in URLhaus).*

### Phase 4 Flow
1. The explanation engine collects all signals.
2. It converts them into plain language.
3. The user sees a final verdict with reasons and advice. *(Translates structured intel like OpenPhish attribution).*

## 5) Suggested Tech Stack by Module

| Module | Technology | Why |
| :--- | :--- | :--- |
| **API** | FastAPI | Clean route handling and interactive docs. |
| **UI** | Streamlit or React | Fast demos or polished web interface. |
| **URL parsing** | Python stdlib | Simple, reliable string and URL handling. |
| **WHOIS/SSL** | Python libraries + system checks | Needed for domain trust signals. |
| **ML** | scikit-learn or PyTorch | Baseline and deeper models. |
| **Sandbox browsing** | Playwright or Selenium | Safe page inspection. |
| **Storage** | SQLite/PostgreSQL | History and audit records. |
| **Cache** | Redis | Faster feed and reputation lookup. |
| **Deployment** | Docker | Portable demo setup. |

## 6) Recommended Report Wording
You can describe the architecture like this:
> "The system is a layered internet trust platform that combines URL lexical analysis, domain reputation checks, rule-based risk scoring, machine learning classification, safe webpage inspection, and human-readable explanations to estimate online trustworthiness."

## 7) Simple Module Diagram
```text
Input URL
  -> Normalizer
  -> Trust Signals
  -> Rule Engine
  -> ML Model
  -> Web Inspection
  -> Explanation Engine
  -> Result + Recommendation
```

## 8) What to Study for This Document
*   FastAPI routing and request bodies.
*   URL parsing and domain analysis.
*   WHOIS and SSL/TLS basics.
*   OpenPhish and URLhaus feed structure.
*   Basic ML classification.
*   Explainable AI for security.
*   Safe browser automation.

## 9) Architecture Document Overview
This document successfully covers:
*   Architecture overview
*   Module descriptions
*   Input/output tables
*   Flow diagram
*   Sequence diagram
*   Dataset sources
*   Technology stack
*   Explanation logic
*   Monitoring and update strategy
