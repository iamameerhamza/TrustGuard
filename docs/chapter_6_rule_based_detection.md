# Chapter 6: Rule-Based Detection

Before we introduce the complex mathematics of Machine Learning, our system needs a foundation of common sense. This chapter explores **Rule-Based Detection** (often called Expert Heuristics), which serves as the rapid, first-line defense in our layered architecture.

---

## 1. What is a Rule-Based System?

A rule-based system applies predefined, hard-coded logic to evaluate a URL. Instead of training an algorithm to find patterns, a human expert writes the patterns explicitly. 

Think of it as a series of `IF/THEN` statements:
*   **IF** the URL contains an IP address instead of a domain name, **THEN** add 25 points to the risk score.
*   **IF** the URL length > 100 characters, **THEN** add 10 points to the risk score.

This is exactly what we will build in Phase 3 of TrustGuard.

---

## 2. Key Expert Rules (The Obvious Danger Patterns)

While ML is great at finding subtle anomalies, rule engines are perfect for catching blatant red flags instantly.

### The Domain Age Rule
As discussed in Chapter 2, legitimate businesses do not spin up domains on the same day they launch massive email campaigns.
*   **The Rule:** `IF domain_age_days < 30 THEN risk_score += 40`

### The Infrastructure Rule
Modern web infrastructure relies on DNS (translating names to IP addresses). Users should never see a raw IP address in a legitimate URL.
*   **The Rule:** `IF has_ip_address == True THEN risk_score += 25`

### The Security Protocol Rule
While the presence of HTTPS does not mean a site is safe, the *absence* of HTTPS on a page that asks for a login is a massive red flag in the modern internet.
*   **The Rule:** `IF has_https == False AND keyword_count > 0 THEN risk_score += 15`

### The Threat Intelligence Overrides (URLhaus)
This is the ultimate expert rule. If a URL is already known to be distributing malware, we don't need to guess.
*   **The Rule:** `IF domain in URLhaus_abuse_feed THEN risk_score = 100 AND status = 'MALICIOUS'`
*   **Context:** By integrating feeds from URLhaus (specifically their abuse datasets), our rule engine can instantly neutralize known threats without wasting CPU cycles running the URL through a complex ML model.

---

## 3. Why a Layered Architecture? (Defense in Depth)

You might ask: *If ML is so powerful, why do we need rules?* Or conversely, *If rules are so clear, why do we need ML?*

Relying on a single score or a single method is the most common failure point in cybersecurity. TrustGuard uses a layered architecture because every method has a critical weakness:

### The Weakness of Rules
Rules are rigid. Attackers know the standard rules and actively design campaigns to bypass them. If our rule says "Flag URLs with > 3 hyphens," an attacker will just use 2 hyphens. Rules cannot adapt to zero-day, unseen patterns.

### The Weakness of Machine Learning
Machine Learning can adapt, but it operates as a "black box." It is computationally expensive and occasionally suffers from bizarre false positives. If the ML model flags a legitimate bank website because its character entropy is slightly off, we need a way to counteract that. Furthermore, ML is difficult to explain to an end-user.

### The Synergy of Layers
By combining them, we create a robust **Defense in Depth** strategy:
1.  **Layer 1 (Threat Intel / URLhaus):** Instantly blocks known bad actors. Highly accurate, but only catches known threats.
2.  **Layer 2 (Expert Rules):** Instantly flags blatant, obvious red flags and provides 100% human-readable explanations.
3.  **Layer 3 (Machine Learning):** Analyzes the nuanced "DNA" of the URL to catch zero-day attacks that bypassed Layers 1 and 2.

Our final risk score (implemented in Phase 5) will be a weighted combination of these layers. 

---

> [!TIP]
> **Next Steps in our Roadmap:** We are now prepared to build the `explain/rules.py` engine. This engine will execute these exact `IF/THEN` heuristics, providing a baseline risk score and a readable list of reasons that we can show to the user *before* the ML model even finishes loading.
