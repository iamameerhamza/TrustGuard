# Chapter 10: Safe Webpage Inspection

Until now, our platform has focused entirely on analyzing the URL string itself. While extremely fast and highly predictive, attackers can occasionally generate URLs that look perfectly benign. To build a truly comprehensive Internet Trust Platform, we must eventually look at the destination. 

This chapter explores Phase 15 of our roadmap: **The Sandbox Layer**, where we safely inspect a webpage's behavior and structure without falling victim to it.

---

## 1. The Golden Rule: Never Trust the Payload

When you visit a website, your browser actively executes the code (HTML, JavaScript, CSS) provided by that site. If that code is malicious, and you execute it on your core API server, the attacker could compromise your entire platform (via Server-Side Request Forgery or Remote Code Execution).

**The Golden Rule:** Never execute JavaScript or render a webpage on the main API server. 
*   **The Architecture:** Safe inspection requires a completely isolated environment—a "Sandbox" (usually a containerized Headless Browser or a specialized crawler like Puppeteer/Playwright running on a separate worker node). If the sandbox is compromised or crashes, the main scoring API remains unaffected.

---

## 2. Tracking the Redirect Chain

Attackers rarely send a victim directly to the phishing page. They use a series of redirects to evade detection.
*   **The Lure:** The user clicks a link that looks safe (e.g., a bit.ly link or a compromised WordPress site).
*   **The Chain:** The server responds with an HTTP 301 (Permanent) or 302 (Temporary) redirect, or a JavaScript `window.location` redirect.
*   **The Destination:** The final landing page where the credential theft actually happens.

**Safe Inspection Goal:** Our crawler must record the entire chain. A long chain of redirects, especially bouncing across different TLDs and ASNs before landing on a newly registered domain, is a massive red flag that our Rule Engine can score.

---

## 3. Extracting Structural Evidence

Once we safely land on the final page (often by fetching the raw HTML without executing the JavaScript first), we look for specific structural clues that indicate deception.

### Page Titles
Phishing pages want the user to feel safe immediately. The `<title>` tag often blatantly steals brand names (e.g., `<title>Sign in to your PayPal Account</title>`). If the title says "PayPal" but the domain is `secure-update.xyz`, we have a definitive mismatch.

### Visible Forms and Inputs
The ultimate goal of phishing is credential theft. Therefore, the page *must* have a way to collect data. Our inspector looks for:
*   The presence of `<form>` tags.
*   Inputs specifically requesting sensitive data: `<input type="password">`.
*   Hidden fields that might exfiltrate data to strange third-party domains.

### Suspicious Scripts
While we avoid *executing* the JavaScript, we can still *read* it. We look for:
*   Highly obfuscated scripts (e.g., variables named with random characters, excessive use of `eval()`).
*   Scripts attempting to disable right-clicking or prevent the user from leaving the page.

---

## 4. The Threat Intel Context (URLhaus)

While phishing relies on forms, malware distribution (the primary focus of URLhaus) relies on payloads. 

When inspecting a webpage, a safe crawler will monitor the network requests the page attempts to make. If the page automatically tries to download an `.exe`, `.apk`, or `.vbs` file upon loading (a drive-by download), our system flags it. 

Furthermore, if the page's HTML structure perfectly matches known malware-dropper templates (often tracked by researchers feeding data into URLhaus), we can instantly categorize the threat before the payload is ever downloaded.

---

## 5. Integrating Inspection into the Final Score

Webpage inspection is slow. A static URL check (Chapters 2-8) takes milliseconds, while spinning up a headless browser takes seconds. 

Because of this performance cost, the Sandbox is an **optional, asynchronous layer**. 
1.  The user submits a URL.
2.  The fast API returns the ML & Rule-based score instantly.
3.  *If* requested, a background job is fired to inspect the webpage's HTML and forms.
4.  Once the sandbox finishes, the final report is updated with the dynamic findings (e.g., "We found a hidden password field attempting to send data to a Russian IP address.").

---

> [!TIP]
> **Next Steps in our Roadmap:** This completes the deep dive into advanced, post-URL analysis. While the Sandbox is scheduled for the end of our 12-week roadmap, designing the system with this future capability in mind ensures our architecture remains secure from day one.
