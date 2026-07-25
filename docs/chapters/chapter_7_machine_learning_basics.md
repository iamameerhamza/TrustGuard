# Chapter 7: Machine Learning Basics

Machine Learning in TrustGuard utilizes Supervised Classification, training algorithms to optimally separate benign URLs from malicious ones using ground-truth labeled datasets. To prevent memorization, we rigidly partition our data into Training, Validation, and Test sets.

Cybersecurity models cannot be evaluated on simple accuracy. We rely on Precision (minimizing false positives to prevent alert fatigue) and Recall (minimizing false negatives to prevent slipped threats), unified by the F1-Score and ROC-AUC curve. 

The ultimate goal of ML is Generalization. By learning the latent mathematical features of malicious infrastructure—rather than just memorizing strings—our models can autonomously detect zero-day phishing campaigns that have never appeared on any threat feed.
In Chapter 6, we built a Rule Engine that is rigid, explainable, and instantaneous. In this chapter, we explore Phase 5 of TrustGuard: **Machine Learning (ML)**. This layer is designed to solve the exact problem that rules cannot—detecting subtle, unseen, zero-day patterns.

---

## 1. Supervised Classification

The type of Machine Learning we are building is called **Supervised Classification**.
*   **Classification** means we are asking the model to sort URLs into specific buckets (Classes). In our MVP, this is a binary choice: Class 0 (Benign) or Class 1 (Malicious).
*   **Supervised** means we act as the teacher. We don't just throw raw URLs at the algorithm and hope it figures it out. We provide it with the extracted features (from Chapter 5) alongside the correct answers (the Ground Truth labels from Chapter 4).

The model's job is to study these examples and find the optimal mathematical boundary that separates the Safe URLs from the Phishing URLs.

---

## 2. The Data Split (The Study Guide and the Exam)

If you give an ML model 100,000 URLs, you cannot let it study all 100,000 and then test it on those same URLs. It will simply memorize them, achieving 100% accuracy, but failing completely in the real world. 

To prevent this, we split our dataset into three distinct parts:

1.  **The Training Set (e.g., 80%):** The textbook. The model looks at these features and labels to learn the patterns.
2.  **The Validation Set (e.g., 10%):** The practice quizzes. While the model is training, we test it on this set to tune its settings (like how deep our Random Forest should grow) without it "memorizing" the answers.
3.  **The Test Set (e.g., 10%):** The final exam. This data is locked away until the very end. The model has **never seen it before**. If the model performs well here, we know it will perform well in the real world.

---

## 3. Beyond "Accuracy": Evaluation Metrics

In cybersecurity, "Accuracy" (the percentage of total correct guesses) is often a highly misleading metric, especially if the data isn't perfectly balanced. Instead, we use specific metrics to measure how useful the system actually is to a user.

### Precision (Minimizing False Alarms)
*   **Definition:** Out of all the URLs the model *claimed* were malicious, how many actually were?
*   **Why it matters:** If Precision is low, the model generates too many "False Positives" (flagging safe sites as dangerous). Users quickly experience alert fatigue and will stop trusting your platform. 

### Recall (Minimizing Slipped Threats)
*   **Definition:** Out of all the *actual* malicious URLs in the wild, what percentage did the model successfully catch?
*   **Why it matters:** If Recall is low, the model generates "False Negatives". Dangerous phishing sites are marked as safe, leading to compromised user accounts. 

### F1-Score
*   **Definition:** The harmonic mean of Precision and Recall. 
*   **Why it matters:** There is always a trade-off. If you want 100% Recall (catch every threat), you can just flag every single URL on the internet as malicious, but your Precision drops to 0%. The F1-Score proves you have achieved a healthy, usable balance.

### ROC-AUC (Area Under the Receiver Operating Characteristic Curve)
*   **Definition:** Measures how well the model separates the two classes at various confidence thresholds (0.0 to 1.0). 
*   **Why it matters:** An AUC of 0.5 means the model is just flipping a coin. An AUC of 1.0 means it separates the classes perfectly. We aim for an AUC > 0.95.

---

## 4. Generalization: Catching the Unknown

The entire point of using Machine Learning over static rules is **Generalization**. How does the model catch a zero-day phishing site it has never seen?

Because it didn't memorize the URL string. It learned the *features*. 
It learned that domains registered yesterday (Domain Age), combined with high entropy (Randomness), three hyphens (Structure), and the presence of the word "secure" (Keyword) mathematically correlate to a 94% probability of malicious intent.

When a zero-day URL arrives, the `extractor.py` converts it into those same numbers. The model applies its learned math to those numbers and correctly flags it, even if that specific domain has never been reported anywhere on the internet.

---

## 5. The Threat Intel Context (URLhaus)

While we use feeds like URLhaus as explicit expert rules (Chapter 6), they are also vital for our training data. By feeding historical URLhaus data into our model during Phase 5, the model learns the underlying structural features of domains that frequently host malware. It learns to recognize the "shape" of attacker infrastructure, aiding its ability to generalize to new, unreported threats.

---

> [!TIP]
> **Next Steps in our Roadmap:** We now understand how we will evaluate our models. Phase 5 of the project will involve writing the code in `training/train_baseline.py` using `scikit-learn` to build our Random Forest, split the data, and generate these exact metrics (Precision, Recall, F1) to validate our work.
