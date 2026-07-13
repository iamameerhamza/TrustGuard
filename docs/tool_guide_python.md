# What to Learn in Each Tool Area: Python

While Machine Learning gets the spotlight, the reality of building the **Internet Trust Platform** is that 90% of the daily work is data engineering. Python is the backbone of this platform. 

To successfully execute this 12-week roadmap, you must master these specific Python capabilities, as they are the day-to-day tools behind the entire pipeline.

---

## 1. String Handling
A URL is just a string of characters. Before we can use math, we must manipulate text.
*   **Why it matters:** You will rely heavily on string methods (like `.lower()`, `.strip()`, `.count()`, and `.split()`) to normalize incoming URLs and extract basic lexical features (e.g., counting the number of hyphens or checking if a suspicious keyword exists).
*   **Where it's used:** `preprocessing/normalize.py`, `features/lexical.py`.

## 2. Regular Expressions (Regex)
When basic string methods aren't enough, we use the `re` module.
*   **Why it matters:** Attackers use obfuscation. Regex allows us to detect complex patterns, such as verifying if a URL's host is a raw IP address (e.g., matching `192.168.1.1` instead of `google.com`), or finding variations of brand names hidden in long subdomains.
*   **Where it's used:** `features/extractor.py`, `sandbox/js_analysis.py`.

## 3. URL Parsing (`urllib.parse`)
Never try to manually slice a URL string to find the domain.
*   **Why it matters:** The internet is messy. URLs have schemes, netlocs, paths, query parameters, and fragments. Python's built-in `urllib.parse` safely and accurately dissects a URL into its core components. This is absolutely critical; if you parse the domain incorrectly, your threat feed lookups will fail.
*   **Where it's used:** `app/main.py`, `features/lexical.py` (Specifically Phase 1).

## 4. File Handling
Security platforms consume and generate massive amounts of data.
*   **Why it matters:** You must be comfortable reading large CSV files (Tranco lists), writing clean logs, and saving/loading trained Machine Learning models (Pickle or Joblib files). Knowing how to efficiently read files line-by-line is crucial so you don't run out of memory when processing a 1-million-row blacklist.
*   **Where it's used:** `collector/`, `training/evaluate.py`.

## 5. JSON
JSON (JavaScript Object Notation) is the universal language of modern web architecture.
*   **Why it matters:** When our FastAPI backend finishes scoring a URL, it must package the prediction, risk score, and reasons into a structured JSON response. Furthermore, when we pull automated intelligence from OpenPhish, it arrives as JSON. You must know how to parse, manipulate, and generate it fluently.
*   **Where it's used:** `api/routes.py`, `api/schemas.py`.

## 6. Requests (`requests` and `httpx`)
The platform must talk to the outside world.
*   **Why it matters:** You need HTTP libraries to download the daily threat feeds from URLhaus and OpenPhish. Later, you will use asynchronous requests (`httpx` or `aiohttp`) to safely probe URLs to follow redirect chains without executing malicious payloads on the main server.
*   **Where it's used:** `collector/run_collection.py`, `sandbox/redirects.py`.

---

> [!TIP]
> **Learning Strategy:** You do not need to be a Python expert to start this project. As long as you understand how to slice a string and parse a JSON dictionary, you can complete Phase 1 and Phase 2. You will naturally learn the rest as the pipeline grows!
