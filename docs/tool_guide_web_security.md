# What to Learn in Each Tool Area: Web Security

The core premise of **TrustGuard** is that it mimics the brain of a senior security analyst. To write code that accurately scores a URL, you must deeply understand the underlying architecture of the web. 

This guide outlines the critical Web Security concepts you must master, as they form the fundamental trust signals our system uses to judge risk.

---

## 1. HTTPS and Certificates
You must understand the difference between *Encryption* and *Trust*.
*   **The Concept:** HTTPS (via TLS/SSL) encrypts data between the browser and the server. It prevents someone on a coffee shop Wi-Fi network from intercepting a password. However, it **does not** mean the server itself is run by a good person.
*   **The Reality:** With the advent of free Certificate Authorities like Let's Encrypt, attackers can instantly secure their phishing domains. Today, the vast majority of phishing sites display the "secure padlock."
*   **What you must learn:** You need to understand how to read Certificate Metadata. A Domain Validated (DV) certificate that is 2 days old is a massive red flag, whereas an Extended Validation (EV) certificate that is 2 years old is a strong trust signal.

## 2. Redirects (HTTP 3xx)
Attackers rarely send a victim directly to the malware. They use mazes.
*   **The Concept:** When a server receives a request, it can respond with a `301 Moved Permanently` or a `302 Found`, telling the browser to automatically load a different URL.
*   **The Reality:** An attacker might send a link to a compromised, legitimate WordPress site. When you click it, the WordPress site redirects you to a bit.ly link, which then redirects you to the actual phishing page.
*   **What you must learn:** You must understand how to safely follow HTTP redirect chains programmatically (without rendering the page) to uncover the final landing domain, as that is the domain you actually need to scan.

## 3. Forms and Data Exfiltration
Phishing has one primary goal: getting the user to submit data.
*   **The Concept:** In HTML, data is collected using `<form>` tags containing `<input>` fields (like passwords or credit card numbers). When the user clicks submit, the browser sends an HTTP `POST` request to a server.
*   **The Reality:** Deceptive sites often use hidden input fields or route the `POST` request to a completely different, suspicious domain to quietly exfiltrate the stolen data.
*   **What you must learn:** You need to understand basic HTML structure so your sandbox (Phase 15) can search the DOM for hidden password fields and identify where the form is attempting to send the stolen credentials.

## 4. Browser Behavior (The Sandbox)
You must understand the danger of executing untrusted code.
*   **The Concept:** When a browser opens a URL, it doesn't just read text; it actively executes JavaScript and downloads payloads.
*   **The Reality:** If your Python backend simply "fetches" a malicious webpage, it might inadvertently execute a malicious script or trigger a drive-by download, potentially compromising your server (Server-Side Request Forgery or RCE).
*   **What you must learn:** You must learn how to interact with the web *safely*. This means knowing when to use static DOM parsers (like BeautifulSoup) that only read text, and when to use strictly isolated Headless Browsers (like Puppeteer in a Docker container) when you actually need to observe the JavaScript behavior.

---

## 5. The Threat Intel Context (OpenPhish)

Why do we need to learn this if we are using external feeds?

Platforms like **OpenPhish** are incredibly powerful because they have entirely automated this web security knowledge. When OpenPhish evaluates a link, it autonomously traces the redirect chains, inspects the SSL certificate metadata, and parses the HTML forms to instantly extract the targeted brand and the drop email address.

By understanding *how* OpenPhish gathers this intelligence, you can better design your own Rule Engine to complement their data, ensuring your platform is making intelligent, layered decisions.
