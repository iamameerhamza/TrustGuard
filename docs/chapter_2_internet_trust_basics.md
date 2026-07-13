# Chapter 2: Internet Trust Basics

To build the first layer of TrustGuard (Phase 1), we need to program our system to analyze URLs the way an expert human analyst does. This chapter explores the foundational signals of internet trust and why they matter for our heuristic rules and machine learning models.

---

## 1. Domain Names & Subdomains

A URL is composed of several parts. Understanding the hierarchy is crucial because attackers exploit this structure to confuse users.

*   **Top-Level Domain (TLD):** The end of the domain (e.g., `.com`, `.org`, `.ru`, `.xyz`). While attackers use all TLDs, cheap or free TLDs (like `.tk`, `.xyz`, or `.top`) historically see higher volumes of abuse.
*   **Root Domain (Second-Level Domain):** The core identity (e.g., in `google.com`, `google` is the root). Attackers register deceptive root domains (e.g., `secure-update-account.com`).
*   **Subdomain:** A prefix added to the root domain (e.g., `mail.google.com`).

**How Attackers Exploit Subdomains:**
Because anyone who owns a root domain can create infinite subdomains, attackers use this to mimic brands:
*   **Safe (Legitimate):** `secure-login.paypal.com` (The root is `paypal.com`, controlled by PayPal).
*   **Phishing:** `paypal.com.secure-login-update.net` (The root is `secure-login-update.net`, controlled by the attacker. The user only sees `paypal.com` at a quick glance).

*Why it matters for Phase 1:* We must parse URLs accurately to isolate the actual root domain being visited, not just look for the presence of a brand name anywhere in the string.

---

## 2. HTTPS and SSL/TLS Certificates

There is a massive, persistent myth among web users: *"If a site has a padlock (HTTPS), it is safe."*

**The Reality:** HTTPS only encrypts the traffic between the user and the website. It means no one can intercept the password in transit. It does **not** mean the website itself is trustworthy. It just means you are securely sending your password directly to the attacker.

*   **Free Certificates:** With services like Let's Encrypt, attackers can instantly and freely acquire SSL certificates for their phishing domains. Consequently, the vast majority of modern phishing sites use HTTPS.
*   **What actually matters:** Rather than just checking *if* SSL exists, advanced trust checks look at the certificate metadata:
    *   **Validation Type:** Domain Validated (DV) certs are easy to get. Extended Validation (EV) or Organization Validation (OV) require strict identity checks and are rarely used by phishers.
    *   **Certificate Age:** Phishing certs are usually days or even hours old.

---

## 3. WHOIS Records & Domain Age

WHOIS is a public database housing information about who registered a domain name and when.

*   **Domain Age (Creation Date):** This is one of the strongest single signals in phishing detection. Legitimate corporate domains are usually years old. Phishing domains are often registered exactly when the campaign begins. **Rule of thumb:** Any domain less than 30 days old should be treated with extreme suspicion.
*   **Registrant Data:** Historically, analysts looked at who registered the site. However, due to privacy regulations (like GDPR) and domain privacy services, this data is mostly redacted today. Still, patterns in the registrar used (e.g., registrars known to ignore abuse complaints) remain a valuable signal.

---

## 4. Reputation Feeds: The Collective Defense

Instead of relying solely on the URL's anatomy, we query the internet's collective memory. If a domain is already known to be bad, we want to know instantly.

### OpenPhish
As discussed in Chapter 1, OpenPhish acts as an autonomous sensor network, identifying new phishing URLs and extracting actionable intelligence without waiting for human verification.

### URLhaus (by abuse.ch)
While OpenPhish focuses strictly on phishing, **URLhaus** focuses heavily on URLs distributing malware. URLhaus provides a massive dataset of known malicious URLs, but it goes a step further by offering specialized feeds that provide deep contextual intelligence:

*   **ASN Feed (Autonomous System Number):** Groups malicious URLs by the network provider hosting them. This is crucial because it helps identify "bulletproof hosting" providers or networks that are currently compromised or ignoring abuse complaints.
*   **Country Feed:** Groups threats by geolocation. If an attacker is targeting regional banks in Europe, the infrastructure might be heavily clustered in specific geographic zones.
*   **TLD Feed:** Highlights which Top-Level Domains are currently experiencing the most abuse. 

**Why URLhaus Feeds Matter for TrustGuard:**
By utilizing ASN, Country, and TLD feeds, we don't just ask, *"Is this specific URL bad?"* We can ask, *"Is this URL hosted on an ASN or using a TLD that is currently a hotbed for malware distribution?"* This allows us to assign a higher risk score to a suspicious URL simply because it resides in a bad neighborhood of the internet.

---

> [!TIP]
> **Implementation Note for TrustGuard:** In our architecture, these signals will feed into our `features/` directory. For instance, `whois.py` will extract the domain age, `lexical.py` will identify deceptive subdomains, and `intelligence/blacklist.py` will handle fast lookups against OpenPhish and URLhaus data.
