# Essential Study Materials Reference

To successfully build the TrustGuard platform, you don't need to read textbooks cover-to-cover. You need targeted, high-quality documentation. Below is the curated list of essential study materials corresponding to the tools and concepts we've discussed.

---

### 1. API Architecture (FastAPI)
**Resource:** [FastAPI Official Tutorial - First Steps](https://fastapi.tiangolo.com/tutorial/)
*   **Why read this?** FastAPI's documentation (written by Sebastián Ramírez) is widely considered some of the best technical writing in the industry. It will teach you how to set up your `/scan` route, use Pydantic for request validation, and automatically generate your interactive Swagger UI docs. 

### 2. Phishing Threat Intelligence (OpenPhish)
**Resource:** [OpenPhish Feeds Documentation](https://openphish.com/phishing_feeds.html)
*   **Why read this?** This page explains the exact JSON structure of a live phishing feed. By studying their metadata (Targets, ASNs, Drop Accounts), you will understand exactly what fields we need to extract and store in our own database during Phase 4 (Data Collection) and Phase 7 (Threat Intel Layer).

### 3. Malware Distribution Intelligence (URLhaus)
**Resource:** [URLhaus API and Dataset Documentation](https://urlhaus.abuse.ch/api/)
*   **Why read this?** URLhaus categorizes threats differently than OpenPhish. Studying their API docs will teach you about their specialized feeds (Country, ASN, TLD) and their strict update behavior rules (e.g., fetching no more than every 10 minutes to avoid rate-limiting).

### 4. URL Parsing (Python Standard Library)
**Resource:** [Python `urllib.parse` Documentation](https://docs.python.org/3/library/urllib.parse.html)
*   **Why read this?** Before you write a single Regex for Phase 2 (Lexical Extraction), you must read this. It explains how Python safely handles the complex, messy reality of internet URLs, separating the scheme, netloc, and paths without breaking on obfuscated links.

### 5. Machine Learning Evaluation (Scikit-Learn)
**Resource:** [Scikit-Learn Classification Metrics Guide](https://scikit-learn.org/stable/modules/model_evaluation.html#classification-metrics)
*   **Why read this?** This is the definitive guide to understanding why "Accuracy" is a terrible metric for imbalanced cybersecurity datasets. It provides the math and Python code for generating Confusion Matrices, Precision, Recall, F1-Scores, and ROC-AUC curves for our Phase 5 ML models.

### 6. Explainable AI (XAI) in Cybersecurity
**Resource:** [Explainable AI (XAI) for Intrusion Detection (Research/Overview)](https://www.proofpoint.com/us/blog/threat-insight/explainable-ai-cybersecurity) *(General industry concept search)*
*   **Why read this?** Explainability (Phase 8) is what makes or breaks a security product. Studying XAI principles (like SHAP or LIME) will teach you how the industry solves the "black box" problem. You will learn how to extract feature importance (e.g., "The Domain Age contributed 40% to this malicious score") and present it as a readable security alert to reduce alert fatigue for analysts.
