# TrustGuard 2030 Roadmap

This document translates the 2030 vision into a staged, repo-friendly evolution plan for TrustGuard.

## Principle
Do not rewrite the project. Extend the current URL and webpage platform in layers so each addition remains testable, explainable, and usable by students.

## Phase A: Edge-First Foundation
Goal: move the first trust decision as close to the user as possible.

- Run a small model locally for instant URL and text analysis.
- Cache recent scans, feed snapshots, and local allow/block decisions on device.
- Keep a working offline mode for the core scan flow.
- Hash network-bound identifiers before any optional server call.

## Phase B: Multi-Modal Engine
Goal: inspect more than plain URLs.

- Add screenshot-based phishing detection for login pages and brand impersonation.
- Add QR code scanning that flows into the existing URL pipeline.
- Add document inspection for PDFs and office files before download or open.
- Add optional audio and video cues for vishing or synthetic identity checks.

## Phase C: Agentic Core
Goal: turn a score into a structured investigation.

- Produce a verdict plus evidence list, not only a number.
- Let a small local model decide which tools to call next.
- Support safe auto-actions such as blocking, quarantining, or reporting.
- Keep user-visible explanations short and grounded in extracted facts.

## Phase D: Federated Intelligence
Goal: improve models without centralizing raw user data.

- Collect local feedback as privacy-preserving updates.
- Aggregate model improvements from many devices.
- Track signed or tamper-evident threat intelligence records.
- Preserve the current open-source workflow and transparent evaluation.

## Phase E: Security Agility
Goal: keep the platform adaptable as cryptography and attack methods change.

- Design signatures and hashes so they can be swapped without a rewrite.
- Keep the transport layer ready for post-quantum experiments.
- Separate model logic, threat feeds, and policy so each can evolve independently.

## What To Build First
The most practical next steps for this repository are:

1. A browser-extension friendly scan API.
2. Local-first caching for scan history and verdicts.
3. Screenshot ingestion that reuses the current trust pipeline.
4. A structured evidence schema shared by the backend and frontend.

## What To Avoid

- Do not collapse the project into a generic AI assistant.
- Do not depend on cloud inference for the basic safety check.
- Do not hide the reasoning behind an opaque score.
- Do not broaden the scope so much that the URL detector stops being reliable.