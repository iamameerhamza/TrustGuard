# Project Blueprint

## Project Title
**Internet Trust Platform for Suspicious URL and Webpage Analysis**

## Problem Statement
People often click links without knowing whether they are safe. Phishing pages can look legitimate, use fresh domains, and hide their intent behind short-lived infrastructure — a layered trust-checking system is needed instead of a single blacklist check.

## Project Goal
Demonstrate how online trust can be assessed using multiple layers: URL structure, domain reputation, SSL/WHOIS, rule logic, machine learning, webpage inspection, and plain-language explanations.

## Scope
Phase 1: URLs and webpages. Future: email links, QR codes, downloads, browser-extension links.

## Six-Layer Architecture
1. Input layer
2. Normalization layer
3. Signal extraction layer
4. Risk scoring layer
5. Explanation layer
6. Storage and monitoring layer

## Functional Modules
URL input, normalization, trust signals, rule engine, ML scoring, web inspection, explanation, logging, feed update.

## Data Plan
- Malicious: OpenPhish, URLhaus
- Benign: Tranco ranked domain lists

## Phase 1 Features
Domain age, HTTPS presence, WHOIS details, lexical URL patterns, subdomain count, special characters, suspicious keywords, reputation feed match, redirect flags, TLD-type.

## Evaluation Plan
Accuracy, precision, recall, F1-score, ROC-AUC. Inspect false positives carefully.

## Safety Plan
Sandbox for webpage inspection. Rate limits, logging, careful handling of external content.

## Public Demo Flow
User submits URL → trust signals checked → risk score produced → reasons explained → action advice displayed.

## Maintenance Plan
Periodic feed refresh, model version tracking, recalibration. Scheduled updates (URLhaus fetch-frequency limits apply).

## Future Expansion
Emails, QR codes, downloads, brand-impersonation pages.

## Deliverables
Architecture document, flow diagram, study guide, dataset plan, evaluation plan, demo script, public presentation deck.
