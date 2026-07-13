# Chapter 4: Data Collection

Machine learning models are only as good as the data they learn from. Before we can train our Random Forest or Char-CNN models in Phase 5, we must build a high-quality, labeled dataset (Phase 4). This chapter explores the sources of our ground truth data, how to balance it, and the critical importance of data hygiene.

---

## 1. Where Our Labels Come From (Ground Truth)

In supervised machine learning for cybersecurity, we need a dataset divided into two distinct classes: **Benign** (Safe) and **Malicious** (Phishing/Malware).

### Malicious Sources (The "Bad" URLs)
We cannot just guess what phishing URLs look like; we need real-world examples.
*   **OpenPhish:** Provides a continuous stream of live, zero-day phishing URLs. These are excellent for training models to catch brand impersonation and deceptive lexical structures.
*   **URLhaus (by abuse.ch):** Provides an extensive database of URLs actively distributing malware. This gives our dataset diversity, teaching the model about malicious infrastructure and fast-flux domains that might look slightly different than traditional phishing.

### Benign Sources (The "Good" URLs)
To teach the model what a safe URL looks like, we use domain ranking lists.
*   **Tranco:** The Tranco list is a research-oriented ranking of the top 1 million domains on the internet. It was created to solve the inconsistencies found in older lists like Alexa or Cisco Umbrella. By sampling domains from the top, middle, and bottom of the Tranco list, we provide our model with a diverse representation of normal, safe web traffic.

---

## 2. Building a Balanced Dataset

A common mistake in cybersecurity data science is creating an imbalanced dataset (e.g., 99,000 benign URLs and 1,000 phishing URLs). 

*   **The Problem:** If 99% of your data is safe, a lazy ML model will achieve 99% accuracy simply by guessing "Safe" every single time. It will learn nothing about detecting threats.
*   **The Solution:** We must strictly balance our training data. If we extract 50,000 malicious URLs from OpenPhish and URLhaus, we should sample exactly 50,000 benign URLs from Tranco. This forces the model to actually learn the distinguishing features between the two classes to minimize its error rate.

---

## 3. Data Hygiene: Duplicates and Stale Entries

Raw intelligence feeds are noisy. Before any data touches an algorithm, it must pass through a rigorous preprocessing pipeline (`preprocessing/`).

### Deduplication
Both OpenPhish and URLhaus might track the exact same campaign, or a single domain might host hundreds of slightly different phishing URLs. 
*   **Why it matters:** If we have 5,000 identical or nearly identical URLs in our training set, the model will overfit to that specific campaign. It will memorize that one pattern instead of learning general rules. We must aggressively deduplicate our data based on the root domain and URL structure.

### Stale Entries
The internet changes rapidly. A domain that was malicious a year ago might have been seized, sinkholed, or purchased by a legitimate company today. Conversely, a previously top-ranked Tranco domain might have expired and been bought by a phisher.
*   **Why it matters:** Feeding stale data into the model confuses it. If it sees the exact same lexical features labeled as "Malicious" in one row and "Benign" in another, it cannot converge on a reliable pattern. We must rely on fresh data and regularly rebuild our datasets to prevent model drift.

---

## 4. Why Clean Labels Matter (Garbage In, Garbage Out)

In our architecture, the **Feature Extraction** engine (extracting length, dots, entropy, keywords) translates the URL into numbers. The **Machine Learning Model** looks at those numbers and tries to draw a mathematical boundary between "Good" and "Bad".

If our labels are wrong—if a phishing URL accidentally slipped into our benign Tranco sample—the model will mathematically adjust its boundary to accommodate that error. A noisy dataset fundamentally caps the maximum accuracy of the resulting model. 

---

> [!TIP]
> **Implementation Note for TrustGuard:** In Phase 4, we will write specific Python downloaders (`collector/openphish.py`, `urlhaus.py`, `tranco.py`) to fetch these raw lists automatically. We will then build `preprocessing/deduplicate.py` to scrub the data clean before splitting it into `train`, `validation`, and `test` sets for our algorithms.
