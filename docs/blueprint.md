# Project Blueprint

## 1) Project Title
**Internet Trust Platform for Suspicious URL and Webpage Analysis**

*This name is broader than “phishing detector” and better matches the layered design we have developed.*

## 2) Problem Statement
People often click links without knowing whether they are safe. Phishing pages can look legitimate, use fresh domains, and hide their intent behind short-lived infrastructure, so a layered trust-checking system is needed instead of a single blacklist check.

## 3) Project Goal
The goal is to teach and demonstrate how online trust can be assessed using multiple layers: URL structure, domain reputation, SSL/WHOIS, rule logic, machine learning, webpage inspection, and plain-language explanations. OpenPhish and URLhaus are natural source examples for the malicious side of the system.

## 4) Scope
The first version should focus on URLs and webpages. Later expansion can include email links, QR codes, downloads, and browser-extension links, but those should stay outside the first phase so the project remains clear and explainable.

## 5) System Architecture
The system should have six main layers:
1. Input layer
2. Normalization layer
3. Signal extraction layer
4. Risk scoring layer
5. Explanation layer
6. Storage and monitoring layer

FastAPI is a practical API choice because it handles request bodies cleanly and supports documentation-friendly routes.

## 6) Functional Modules
*   **URL input module:** accepts user-submitted URLs.
*   **Normalization module:** parses and cleans the URL.
*   **Trust signal module:** checks HTTPS, WHOIS age, blacklists, and lexical patterns.
*   **Rule engine:** flags obvious suspicious patterns.
*   **ML scoring module:** predicts probability for uncertain cases.
*   **Web inspection module:** checks redirects, forms, and scripts.
*   **Explanation module:** turns results into user-friendly text.
*   **Logging module:** records outcomes and errors.
*   **Update module:** refreshes feeds and model versions.

## 7) Data Plan
Use malicious URL sources such as OpenPhish and URLhaus, and benign sources such as ranked domain lists. OpenPhish’s feed page shows different feed types and update frequencies, while URLhaus provides multiple feed categories and warns not to overfetch certain feeds.

## 8) Feature Plan
Your main Phase 1 features should include:
*   Domain age
*   HTTPS presence
*   WHOIS registration details
*   Lexical URL patterns
*   Subdomain count
*   Special characters
*   Suspicious keywords
*   Reputation feed match
*   Redirect flags
*   TLD-type information

## 9) Evaluation Plan
You should evaluate accuracy, precision, recall, F1-score, and ROC-AUC, then inspect false positives carefully. For a public trust tool, false positives matter because you do not want to scare users with weak warnings. Recent phishing-detection literature also emphasizes standard performance metrics and interpretability together.

## 10) Safety Plan
If the platform opens webpages, it must do so in a sandbox or controlled browser environment. You should also add rate limits, logging, and careful handling of external content so the demo does not become unsafe to run.

## 11) Public Demo Plan
The public demo should show:
1. User submits URL
2. System checks trust signals
3. System produces risk score
4. System explains reasons
5. System displays action advice

*(OpenPhish-style intelligence and FastAPI-style request/response flow are useful references for how to present this cleanly).*

## 12) Maintenance Plan
Plan for periodic feed refresh, model version tracking, and recalibration. URLhaus specifically notes fetch-frequency limits for some feeds, so update logic should be scheduled rather than continuous.

## 13) Future Expansion
Later, the platform can be expanded to analyze emails, QR codes, downloads, and brand-impersonation pages. This should be described as future work, not part of the first release.

## Deliverables
Your blueprint can end with these deliverables:
*   Architecture document
*   Flow diagram
*   Study guide
*   Dataset plan
*   Evaluation plan
*   Demo script
*   Public presentation deck

## Formal Report Wording
You can describe the project like this:
> "This project proposes a layered internet trust platform that combines URL lexical analysis, domain reputation checks, machine learning scoring, webpage inspection, and human-readable explanations to assess the likelihood that a link or site is suspicious."
