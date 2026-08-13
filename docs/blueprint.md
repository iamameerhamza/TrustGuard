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

## 2030 Evolution Path
TrustGuard should evolve from a URL-first trust checker into a layered, privacy-preserving security platform without losing the current student-friendly scope.

The next-stage roadmap is documented in [roadmap_2030.md](roadmap_2030.md) and focuses on four practical themes:
1. Edge-first inference for fast local scans.
2. Multi-modal analysis for URLs, webpages, QR codes, documents, audio, and video.
3. Agentic investigation and response with structured, explainable outputs.
4. Federated intelligence so local feedback improves the network without sharing raw user data.

The current project should remain grounded in URLs and webpages while the architecture keeps room for browser extensions, email scanning, and safer on-device inspection.

## Deliverables
Architecture document, flow diagram, study guide, dataset plan, evaluation plan, demo script, public presentation deck.
