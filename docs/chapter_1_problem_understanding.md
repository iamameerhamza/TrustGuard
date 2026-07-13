# Chapter 1: Problem Understanding

Welcome to the foundation of **TrustGuard**. Before we write a single line of code to detect threats, we need to thoroughly understand the adversary. This chapter outlines the landscape of modern phishing attacks, the techniques attackers use to trick users, and why building a layered defense is critical.

---

## 1. What is Phishing?

At its core, **phishing** is a form of social engineering. Attackers send fraudulent communications that appear to come from a reputable source. The goal is to manipulate the victim into performing specific actions—usually clicking a link and entering sensitive information. 

Unlike traditional hacking, which exploits vulnerabilities in software or networks, phishing exploits human psychology. Attackers create a sense of urgency, fear, or curiosity to bypass a user's critical thinking.

---

## 2. The Attack Vectors: A Glossary of Deception

To build an effective detection system, we must distinguish between different types of malicious web activity.

### Malicious URLs vs. Phishing
- **Malicious URLs** is a broad term encompassing any web address designed to cause harm. This includes sites hosting malware (drive-by downloads), Command and Control (C2) servers for botnets, and crypto-miners.
- **Phishing URLs** are a specific subset of malicious URLs focused entirely on deception and data theft through fake interfaces.

### Typosquatting
Also known as URL hijacking, typosquatting targets users who incorrectly type a website address into their browser.
- **Example:** `www.goolge.com` instead of `www.google.com`.
- **Why it works:** Attackers register these misspelled domains and host phishing pages on them. The user assumes they arrived at their intended destination because the URL looks *almost* correct at a quick glance.

### Brand Impersonation
Attackers replicate the look, feel, and branding of a trusted organization (like a bank, Microsoft, or PayPal).
- **How it's deployed:** They might use a completely unrelated, compromised domain (e.g., `www.random-blog.com/login/paypal-secure/`) or a subdomain designed to look official (`paypal-support.update-account.com`).
- **The Goal:** To establish false trust instantly when the page loads, hoping the user doesn't closely inspect the address bar.

### Credential Theft
This is the ultimate objective of most phishing campaigns. Once the user is convinced by the typosquatting or brand impersonation, they are presented with a fake login form. Any username, password, or 2FA token entered is immediately harvested by the attacker.

---

## 3. Why a Single URL Check is Not Enough

A naive approach to phishing detection is to simply check the URL against a known "blacklist" (a database of bad URLs). However, **this fails in the real world** for several reasons:

1. **Short Lifespans:** The average phishing site is live for only a few hours. By the time a security researcher finds it, reports it, and adds it to a blacklist, the attacker has already moved to a new domain.
2. **Zero-Day Phishing:** Attackers constantly register new domains or compromise legitimate, previously safe websites to host their phishing kits. These "zero-day" URLs have no negative reputation history.
3. **Dynamic Infrastructure:** Advanced attackers use Fast-Flux DNS, rapidly rotating the IP addresses behind a domain to evade IP-based blocking.
4. **Evasion Techniques:** Attackers use cloaking (showing different content to security scanners vs. real users) and URL shorteners to hide the true destination.

If your system only relies on checking a database, it will miss the most dangerous attacks: the new ones.

---

## 4. The Role of Threat Intelligence (e.g., OpenPhish)

To combat the limitations of static blacklists, the industry relies on autonomous Threat Intelligence platforms like **OpenPhish**.

Instead of waiting for human reports, platforms like OpenPhish use global sensor networks and AI algorithms to actively hunt and analyze millions of URLs in real-time. When they identify a threat, they extract critical metadata:
- **Targets:** Which brand is being impersonated.
- **Infrastructure:** IP addresses, ASN, and SSL certificate anomalies.
- **Indicators:** Paths and characteristics of specific phishing kits.

**How this informs our project:**
While we will integrate threat intelligence feeds, we cannot rely solely on them. A platform like OpenPhish proves that **autonomous, feature-based detection** (looking at the *characteristics* of the URL and page, rather than just its history) is the only way to catch zero-day phishing. 

---

## 5. The Public-Facing Story

When you explain **TrustGuard** to users, the story is this:

> *"Attackers are getting faster, spinning up fake websites in seconds that perfectly mimic the brands you trust. Traditional antivirus and blocklists are too slow to catch them. TrustGuard doesn't just check a list of known bad sites; it actively analyzes the DNA of a URL—its structure, its destination, and its underlying infrastructure—to predict and stop zero-day phishing attacks before they can steal your credentials."*

---

> [!TIP]
> **Next Steps in our Roadmap:** Now that we understand the problem, Phase 1 and 2 of our project will focus on dissecting URLs and extracting these structural characteristics (Lexical features, Entropy) so our Machine Learning models can learn to spot the deception automatically.
