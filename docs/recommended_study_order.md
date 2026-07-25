# Recommended Study Order

To master the architecture and theory of the **Internet Trust Platform for Suspicious URL and Webpage Analysis**, we recommend following this structured curriculum. This guide groups the 13 chapters we have developed into logical learning phases.

---

### Phase 1: The Foundation (Understanding the Threat)
Before building the system, you must understand the adversary and the fundamental signals of internet trust.
1.  **Phishing basics and trust signals.**
    *   [Chapter 1: Problem Understanding](chapters/chapter_1_problem_understanding.md) (Phishing vs. Typosquatting, why blacklists fail)
    *   [Chapter 2: Internet Trust Basics](chapters/chapter_2_internet_trust_basics.md) (Domain names, HTTPS myths, WHOIS)

### Phase 2: Dissecting the Data (Raw Inputs)
Learn how to safely analyze URLs and gather the intelligence necessary for scoring.
2.  **URL parsing and WHOIS.**
    *   [Chapter 3: URL Structure](chapters/chapter_3_url_structure.md) (Lexical features, obfuscation, parsing Netlocs)
3.  **Threat feeds and dataset creation.**
    *   [Chapter 4: Data Collection](chapters/chapter_4_data_collection.md) (OpenPhish, URLhaus, Tranco, balancing datasets)

### Phase 3: The Core Engine (Detection Layers)
This is where the actual scoring happens, moving from common sense to advanced math.
4.  **Rule-based scoring.**
    *   [Chapter 6: Rule-Based Detection](chapters/chapter_6_rule_based_detection.md) (Expert heuristics, defense in depth)
5.  **Machine learning classification.**
    *   [Chapter 5: Feature Engineering](chapters/chapter_5_feature_engineering.md) (Translating URLs to numbers)
    *   [Chapter 7: Machine Learning Basics](chapters/chapter_7_machine_learning_basics.md) (Supervised learning, Precision/Recall, Generalization)
    *   [Chapter 8: Character-Level Models](chapters/chapter_8_character_level_models.md) *(Advanced)* (Char-CNNs, catching zero-day obfuscation)

### Phase 4: Beyond the URL (Advanced Analysis)
6.  **Webpage inspection.**
    *   [Chapter 10: Safe Webpage Inspection](chapters/chapter_10_safe_webpage_inspection.md) (Sandboxing, redirect chains, finding hidden forms)

### Phase 5: The Product (User Experience & Operations)
Turn the detection engine into a usable, reliable software product.
7.  **Explanation writing.**
    *   [Chapter 9: Explanation Design](chapters/chapter_9_explanation_design.md) (Translating ML output into actionable advice)
8.  **API and dashboard design.**
    *   [Chapter 11: Dashboard and API](chapters/chapter_11_dashboard_and_api.md) (FastAPI architecture, React UI)
9.  **Monitoring and reporting.**
    *   [Chapter 12: Logging and Monitoring](chapters/chapter_12_logging_and_monitoring.md) (Model drift, audit trails, historical intelligence)

### Phase 6: The Pitch
10. **Public presentation.**
    *   [Chapter 13: Public Presentation](chapters/chapter_13_public_presentation.md) (The elevator pitch, the Swiss Cheese model, demo workflows)

---

*Curriculum complete. Ready for Execution.*
