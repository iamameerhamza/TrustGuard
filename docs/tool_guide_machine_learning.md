# What to Learn in Each Tool Area: Machine Learning

Our Rule Engine provides immediate, explainable blocks for obvious threats. However, attackers adapt quickly to static rules. To catch subtle, zero-day, and highly obfuscated attacks, we rely on the Machine Learning layer (Phase 5). 

This guide outlines the critical Machine Learning concepts you must master to build, evaluate, and trust your predictive models.

---

## 1. Classification
Machine learning solves many problems (predicting numbers, generating text), but for TrustGuard, we are solving a specific problem: **Binary Classification**.
*   **The Concept:** We are asking the algorithm to sort URLs into exactly two buckets: `0` (Benign/Safe) or `1` (Malicious/Phishing).
*   **What you must learn:** You need to understand how algorithms like Logistic Regression, Random Forests, and XGBoost approach drawing a mathematical boundary between these two classes.

## 2. Feature Vectors
Algorithms cannot read English words or URL strings; they only understand mathematics.
*   **The Concept:** Before we can train a model, we must translate the URL into a **Feature Vector**—an array of numbers representing its characteristics. 
*   **What you must learn:** You must learn how to take the output of your `extractor.py` (e.g., URL length, number of dots, Shannon entropy, presence of keywords) and format it into an array (e.g., `[65, 3, 4.2, 1]`) that a library like `scikit-learn` can ingest.

## 3. Train/Test Split
If you test a student on the exact same questions they studied, they will get 100%, but they might fail completely in the real world. Models do the exact same thing (called **Overfitting**).
*   **The Concept:** We must split our historical dataset (from Chapter 4) into a Training set (to teach the model) and a Test set (to evaluate the model).
*   **What you must learn:** You must learn how to use tools like `train_test_split` in Python to randomly and fairly divide your data, ensuring the model is evaluated on URLs it has *never seen before*.

## 4. Evaluation Metrics
In cybersecurity, "Accuracy" is a dangerous and misleading metric. If 99% of the internet is safe, a broken model that just guesses "Safe" every time will be 99% accurate, but completely useless.
*   **What you must learn:** You must master the triad of classification metrics:
    *   **Precision:** Out of all the URLs the model claimed were dangerous, how many actually were? (Crucial for preventing False Alarms).
    *   **Recall:** Out of all the *actual* dangerous URLs in the wild, how many did the model catch? (Crucial for preventing Threats from slipping through).
    *   **F1-Score:** The harmonic mean of Precision and Recall, proving the model is balanced and healthy.

## 5. Probability Outputs
A good model doesn't just output `0` or `1`. It outputs a confidence level.
*   **The Concept:** Instead of just saying "Malicious," the model says "I am 87% confident this is Malicious." 
*   **What you must learn:** You must learn how to access these probability scores (e.g., `predict_proba()` in `scikit-learn`). This allows you to dynamically adjust your platform's sensitivity. If the model is only 51% confident, you might decide to warn the user but not block the site entirely.

---

## 6. Comparing Rule-Based Scoring vs. Model-Based Scoring

Why do we need to learn these evaluation metrics if we already have a Rule Engine? 
Because metrics allow us to prove the ML layer is actually adding value.

By running your Test dataset through your Rule Engine, you might achieve an F1-Score of 0.75. By running the exact same Test dataset through your trained Random Forest, you might achieve an F1-Score of 0.92. You now have mathematical proof that your ML layer is catching the subtle, zero-day threats that your hard-coded rules missed.

## 7. The Threat Intel Context (URLhaus)

To train a robust model, your Ground Truth data must reflect the real world. 
When we download malware distribution URLs from **URLhaus**, we are feeding the model extremely complex, often machine-generated (DGA) strings. By forcing the algorithm to study these complex feature vectors alongside benign Tranco domains, the model learns the underlying, latent "grammar" of malicious infrastructure—patterns that are impossible to articulate as a simple `IF/THEN` rule.
