# Chapter 3: URL Structure

Before a web page even loads, its URL often reveals its true intent. Attackers use specific structural patterns to bypass basic filters and deceive the human eye. This chapter focuses on **lexical analysis**—the process of breaking down a URL and examining its text characteristics to extract signals for our heuristic and machine learning models (Phase 2 of TrustGuard).

---

## 1. Anatomy of a URL

To effectively analyze a URL, we must first parse it correctly into its components:

`https://www.secure-login.paypal.com.badguy.net/update/account?token=12345`

*   **Scheme:** `https://` (Protocol used)
*   **Netloc (Domain/Host):** `www.secure-login.paypal.com.badguy.net` (Where the request is sent)
*   **Path:** `/update/account` (The specific resource requested)
*   **Query:** `?token=12345` (Parameters passed to the server)

Attackers often manipulate the **Netloc** and **Path** to create the illusion of legitimacy. 

---

## 2. Key Lexical Features (The "DNA" of a URL)

When examining a URL, the following structural anomalies are strong indicators of phishing:

### URL Length
*   **The Signal:** Phishing URLs are frequently abnormally long.
*   **The Reason:** Attackers use excessively long URLs to push the actual, malicious root domain out of view, especially on mobile browsers with small address bars. If a URL is hundreds of characters long, it warrants a higher risk score.

### The Number of Dots (`.`)
*   **The Signal:** An unusually high number of dots in the domain name.
*   **The Reason:** Legitimate domains typically have 1 or 2 dots (e.g., `google.com`, `mail.google.com`). Attackers use multiple dots to create deep, deceptive subdomains (e.g., `secure.login.verification.paypal.com.update-server.net`). The root domain is `update-server.net`, but the user focuses on the familiar words preceding it.

### Hyphens (`-`)
*   **The Signal:** Multiple hyphens in the domain name.
*   **The Reason:** Attackers frequently register domains with hyphens to combine trusted keywords when the actual domain is already taken (e.g., `secure-account-verification-login.com`). While some legitimate sites use hyphens, an excessive count is a strong heuristic for brand impersonation.

### Digits (`0-9`)
*   **The Signal:** A high density of numbers in the URL.
*   **The Reason:** Digits are often present in randomly generated domains (used in fast-flux networks or spam campaigns) or when an attacker uses a bare IP address instead of a domain name (e.g., `http://192.168.1.1/login`). 

---

## 3. Suspicious Keywords

Attackers rely on human psychology. They want the user to feel urgency or believe they are interacting with a security process. Therefore, phishing URLs frequently contain specific, high-risk keywords in the domain or path:

*   **Action words:** `login`, `verify`, `update`, `secure`, `confirm`, `recover`
*   **Target words:** `account`, `bank`, `password`, `billing`, `invoice`
*   **Brand names:** Impersonating specific targets (e.g., `apple`, `microsoft`, `netflix`)

**Our Implementation:** In TrustGuard, counting the presence of these suspicious keywords is a critical feature that will directly influence the heuristic risk score.

---

## 4. Obfuscation and Special Characters

Attackers also use structural tricks to confuse parsing engines or hide the true destination:

*   **The `@` Symbol:** In standard URL formatting, everything before the `@` symbol is treated as a username/password, and the browser navigates to the domain *after* the `@`. 
    *   *Example:* `http://www.google.com@badguy.net` will take the user to `badguy.net`. The human sees "google.com", but the browser ignores it.
*   **URL Encoding:** Attackers use percent-encoding (e.g., `%20` for space, `%40` for `@`) to obscure the URL structure from basic security scanners.
*   **Punycode (Homograph Attacks):** Attackers register domains using characters from different alphabets (like Cyrillic) that look identical to English letters. For example, replacing a Latin `a` with a Cyrillic `а` (U+0430). The URL looks like `apple.com` but points to a completely different server.

---

## 5. The OpenPhish Context

Platforms like **OpenPhish** do not rely on humans looking at URLs to determine if they are bad. Their autonomous engines are built to instantly extract and weigh all of the lexical features discussed in this chapter. 

When OpenPhish analyzes a newly seen URL, it looks at the entropy (randomness of characters), the distribution of dots and hyphens, and the presence of obfuscation techniques. By recognizing these structural patterns, threat intelligence engines can flag a zero-day phishing URL as malicious based purely on its "DNA"—before any victim has even visited the page.

---

> [!TIP]
> **Next Steps in our Roadmap:** In Phase 2, we will translate this knowledge into Python code. We will build `features/lexical.py` to automatically calculate URL length, count dots and hyphens, and flag suspicious keywords. These raw numbers will then feed directly into our Machine Learning models (Phase 5).
