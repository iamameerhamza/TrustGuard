# Graph Report - .  (2026-07-17)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 277 nodes · 418 edges · 27 communities (22 shown, 5 thin omitted)
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS · INFERRED: 1 edges (avg confidence: 0.5)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `655d5077`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_whois_checker.py
- main.py
- normalize_url
- compilerOptions
- scan.py
- compilerOptions
- extract_features
- package.json
- score_domain_age
- App.tsx
- devDependencies
- predictor.py
- calculate_risk
- explain
- train_model.py
- load_test.py
- train_model.py
- Any
- ScanRequest

## God Nodes (most connected - your core abstractions)
1. `compilerOptions` - 17 edges
2. `score_domain_age()` - 17 edges
3. `compilerOptions` - 15 edges
4. `_make_whois()` - 15 edges
5. `normalize_url()` - 13 edges
6. `extract_features()` - 13 edges
7. `get_domain_age_days()` - 13 edges
8. `TestScoreDomainAge` - 12 edges
9. `check_domain()` - 11 edges
10. `_days_ago()` - 11 edges

## Surprising Connections (you probably didn't know these)
- `process_and_save()` --calls--> `normalize_url()`  [EXTRACTED]
  scripts/dataset_builder.py → app/core/normalizer.py
- `test_normalize_empty()` --calls--> `normalize_url()`  [EXTRACTED]
  tests/test_normalizer.py → app/core/normalizer.py
- `test_normalize_missing_schema()` --calls--> `normalize_url()`  [EXTRACTED]
  tests/test_normalizer.py → app/core/normalizer.py
- `test_normalize_valid_url()` --calls--> `normalize_url()`  [EXTRACTED]
  tests/test_normalizer.py → app/core/normalizer.py
- `test_normalize_whitespace_and_case()` --calls--> `normalize_url()`  [EXTRACTED]
  tests/test_normalizer.py → app/core/normalizer.py

## Import Cycles
- None detected.

## Communities (27 total, 5 thin omitted)

### Community 0 - "test_whois_checker.py"
Cohesion: 0.10
Nodes (23): cached_whois(), get_domain_age_days(), invalidate_cache(), _normalise_domain(), app/modules/whois_checker.py TrustGuard — WHOIS domain age detection module.  Pr, Convert international domain names to ASCII-compatible encoding (ACE)     so WHO, Return the age of *domain* in days, or None when the age cannot be     determine, LRU-cached wrapper around get_domain_age_days().      The cache lives for the li (+15 more)

### Community 1 - "main.py"
Cohesion: 0.10
Nodes (8): Retrieve the most recent URL scans from the database., read_history(), get_history(), check_rate_limit(), lifespan(), Startup and shutdown logic for TrustGuard., FastAPI, Request

### Community 2 - "normalize_url"
Cohesion: 0.14
Nodes (19): Submit a community report about a URL (benign or phishing)., Retrieve past scans and community reports for a specific URL., read_url_history(), submit_report(), ReportRequest, UrlHistoryResponse, get_url_history(), init_db() (+11 more)

### Community 3 - "compilerOptions"
Cohesion: 0.09
Nodes (22): compilerOptions, allowArbitraryExtensions, allowImportingTsExtensions, erasableSyntaxOnly, jsx, lib, module, moduleDetection (+14 more)

### Community 4 - "scan.py"
Cohesion: 0.15
Nodes (15): scan_url(), ReportItem, ScanHistoryItem, ScanRequest, ScanResponse, get_cached_result(), Any, set_cached_result() (+7 more)

### Community 5 - "compilerOptions"
Cohesion: 0.10
Nodes (19): compilerOptions, allowImportingTsExtensions, erasableSyntaxOnly, lib, module, moduleDetection, noEmit, noFallthroughCasesInSwitch (+11 more)

### Community 6 - "extract_features"
Cohesion: 0.19
Nodes (13): Any, calculate_entropy(), extract_features(), Client, DataFrame, fetch_openphish(), fetch_tranco(), fetch_urlhaus() (+5 more)

### Community 7 - "package.json"
Cohesion: 0.12
Nodes (16): dependencies, lucide-react, react, react-dom, name, private, scripts, build (+8 more)

### Community 8 - "score_domain_age"
Cohesion: 0.23
Nodes (4): Convert a raw domain age into a structured risk assessment.      Returns a dict, score_domain_age(), Older domains must never score higher risk than younger ones., TestScoreDomainAge

### Community 9 - "App.tsx"
Cohesion: 0.14
Nodes (11): plugins, rules, react/only-export-components, react/rules-of-hooks, $schema, HistoryItem, ScanResult, oxc (+3 more)

### Community 10 - "devDependencies"
Cohesion: 0.13
Nodes (15): devDependencies, oxlint, @types/node, @types/react, @types/react-dom, typescript, vite, @vitejs/plugin-react (+7 more)

### Community 11 - "predictor.py"
Cohesion: 0.33
Nodes (3): load_model(), ModelReloadHandler, FileSystemEventHandler

### Community 12 - "calculate_risk"
Cohesion: 0.52
Nodes (5): calculate_risk(), test_calculate_risk_cap(), test_calculate_risk_phishing(), test_calculate_risk_safe(), test_calculate_risk_suspicious()

### Community 13 - "explain"
Cohesion: 0.60
Nodes (4): explain(), test_explain_blacklisted(), test_explain_safe(), test_explain_suspicious()

## Knowledge Gaps
- **59 isolated node(s):** `$schema`, `typescript`, `oxc`, `react/rules-of-hooks`, `warn` (+54 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **5 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `check_domain()` connect `scan.py` to `test_whois_checker.py`, `score_domain_age`?**
  _High betweenness centrality (0.052) - this node is a cross-community bridge._
- **Why does `score_domain_age()` connect `score_domain_age` to `test_whois_checker.py`, `scan.py`, `extract_features`?**
  _High betweenness centrality (0.052) - this node is a cross-community bridge._
- **Why does `extract_features()` connect `extract_features` to `test_whois_checker.py`, `score_domain_age`, `scan.py`?**
  _High betweenness centrality (0.049) - this node is a cross-community bridge._
- **What connects `$schema`, `typescript`, `oxc` to the rest of the system?**
  _59 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `test_whois_checker.py` be split into smaller, more focused modules?**
  _Cohesion score 0.10256410256410256 - nodes in this community are weakly interconnected._
- **Should `main.py` be split into smaller, more focused modules?**
  _Cohesion score 0.09846153846153846 - nodes in this community are weakly interconnected._
- **Should `normalize_url` be split into smaller, more focused modules?**
  _Cohesion score 0.14333333333333334 - nodes in this community are weakly interconnected._