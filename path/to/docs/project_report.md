# Project Report: Internet Trust Platform

## Abstract
This project proposes a layered internet trust platform that analyzes URLs and webpages to estimate whether they are safe, suspicious, or high-risk. It combines URL lexical analysis, domain reputation checks, threat-feed intelligence, machine learning, safe webpage inspection, and human-readable explanations to support both learning and public awareness.

## Introduction
Phishing remains effective because attackers can register new domains quickly, imitate trusted brands, and hide malicious intent behind convincing-looking links. A single blacklist or single classifier is not enough, so the platform is designed as a layered trust system that checks multiple signals before making a final decision. OpenPhish provides active phishing intelligence, and URLhaus offers malicious URL feeds with multiple feed categories that are useful for trust analysis.

## Objectives
The main objective is to demonstrate how online trust can be assessed using a structured pipeline rather than a single detector. The project also aims to explain its decisions in plain language so non-technical users can understand why a URL is flagged. FastAPI is suitable for exposing these functions through a simple API with documented request bodies and responses.

The specific objectives are:
*   Detect suspicious URLs using domain and lexical signals.
*   Combine rule-based logic with machine learning scoring.
*   Inspect webpages safely for redirects, forms, and scripts.
*   Generate explanations that users can understand.
*   Store results for later review and monitoring.

## Scope
The initial scope is limited to URLs and webpages. Email links, QR codes, downloads, and browser extensions are treated as future expansion topics so the first version stays focused and easy to present. This keeps the system realistic, testable, and suitable for a public demo.

The platform will not attempt to guarantee complete threat elimination. Instead, it will provide a risk estimate and reasoning based on available signals, which is more appropriate for a trust-oriented educational tool.

## Methodology
The methodology follows a phased analysis flow:
1.  Accept a user-submitted URL through an API.
2.  Normalize and parse the input.
3.  Extract trust signals such as HTTPS, WHOIS age, blacklist hits, and lexical patterns.
4.  Apply rule-based scoring.
5.  Use machine learning for uncertain cases.
6.  Inspect the webpage in a safe environment if needed.
7.  Produce a final verdict with an explanation.

OpenPhish and URLhaus can supply malicious feed data, while benign URLs can be collected from ranked domain sources for contrast. URLhaus explicitly provides ASN, country, and TLD feeds and advises not to fetch some feeds more often than every 10 minutes, so scheduled updates are preferable to constant polling.

## System Architecture
The system contains six main layers:
1.  Input layer.
2.  Normalization layer.
3.  Trust signal extraction layer.
4.  Decision layer.
5.  Explanation layer.
6.  Storage and monitoring layer.

The API layer can be built with FastAPI because it supports request bodies cleanly and generates interactive documentation, which is especially useful for demos and teaching.

## Main Modules
*   **URL Input Module:** receives the URL from the user.
*   **URL Normalizer:** cleans and parses the input.
*   **Signal Extractor:** checks HTTPS, WHOIS, feed matches, and lexical features.
*   **Rule Engine:** applies expert rules to obvious cases.
*   **ML Scoring Engine:** predicts risk for ambiguous cases.
*   **Web Inspector:** checks redirects, scripts, and forms in a controlled environment.
*   **Explanation Engine:** turns technical output into user-friendly language.
*   **Storage and Monitoring Module:** records results and tracks updates.

## Technology Stack
A practical stack for this platform is:
*   Python for core logic.
*   FastAPI for the backend API.
*   SQLite or PostgreSQL for result storage.
*   scikit-learn for baseline ML models.
*   PyTorch for deeper URL models if needed.
*   Playwright or Selenium for safe browser inspection.
*   Redis for caching and queued tasks.
*   Docker for packaging and demo deployment.

This stack supports both the learning goals and the public presentation goals of the project.

## Evaluation
The system should be evaluated with accuracy, precision, recall, F1-score, and ROC-AUC. Phishing-detection research commonly uses these metrics, and interpretability is increasingly treated as important alongside raw performance.

Evaluation should also include:
*   False-positive analysis.
*   Confidence calibration.
*   Case-by-case error review.
*   Comparison between rule-only and rule-plus-ML performance.

This helps show whether the layered approach is actually better than a simple detector.

## Safety and Maintenance
Because the platform may inspect real webpages, it should run page loading in a sandbox or controlled browser session. Logging, rate limiting, and cautious feed handling are also important so the demo stays safe and stable.

Maintenance should include:
*   Feed refresh scheduling.
*   Model version tracking.
*   Periodic retraining.
*   Performance monitoring.
*   Error logging and alerting.

## Conclusion
This project presents a practical and educational layered trust platform for detecting suspicious URLs and explaining the result clearly. It is more useful than a single phishing checker because it combines fast trust signals, ML-based scoring, webpage inspection, and plain-language explanation into one structured system.
