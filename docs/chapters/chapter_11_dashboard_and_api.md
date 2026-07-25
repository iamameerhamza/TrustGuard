# Chapter 11: Dashboard and API

To expose the TrustGuard engine to the world, we wrap our Python scripts in a robust, high-performance FastAPI backend. FastAPI provides automatic interactive OpenAPI documentation, strict Pydantic data validation to reject malformed payloads, and asynchronous routing to handle concurrent threat feed lookups.

The backend exposes a `POST /scan` endpoint that ingests a URL and returns a structured JSON payload containing the fused risk score, the ML prediction, and the list of explainability reasons. 

To make this JSON actionable for non-technical users, a Streamlit (or React) frontend Dashboard consumes the API. The dashboard translates the technical payload into a visual risk gauge, a plain-text verdict, and clear evidence cards explaining exactly why a URL was flagged.
The most sophisticated Machine Learning model and Rule Engine are practically useless if people cannot interact with them. This chapter explores how we expose our TrustGuard engine to the world, bridging the gap between raw Python scripts and a usable product (Phases 6 and 10 of our roadmap).

---

## 1. The Core API: Why FastAPI?

To serve our predictions, we are building a backend API. We have chosen **FastAPI** (created by Sebastián Ramírez / Tiangolo) for several critical reasons:

### Automatic Interactive Documentation
When building a platform intended for public use or demonstrations, API documentation is usually a massive chore. FastAPI automatically generates a beautiful, interactive Swagger UI (OpenAPI standard) directly from our code. This allows users to test our `/scan` endpoint directly from their browser without writing any code.

### Data Validation (Pydantic)
Security APIs must be secure themselves. If a user sends a broken URL or a malicious payload, our backend must reject it before it hits our Machine Learning pipeline. FastAPI uses Pydantic to strictly enforce data types. If our `RequestSchema` expects a string, and the user sends an integer, FastAPI automatically rejects the request with a clean 422 Error.

### Asynchronous Performance
URL analysis often involves waiting (e.g., querying external Threat Feeds, making database calls). FastAPI's native asynchronous design (`async def`) allows the server to handle thousands of concurrent requests while waiting for these network calls to resolve, making it blazingly fast.

---

## 2. API Design: Routes and Schemas

A well-designed API is predictable and structured.

### The Request Body
When a client asks for a scan, they will send a simple JSON payload to our `POST /scan` route:
```json
{
  "url": "http://secure-login.update-account.com"
}
```

### The Response Format
The API responds with the structured intelligence required by our frontend. Based on our project roadmap, the response schema looks like this:
```json
{
  "url": "http://secure-login.update-account.com",
  "prediction": "phishing",
  "risk_score": 87,
  "confidence": 96.2,
  "reasons": [
    "Domain age is very recent.",
    "Suspicious brand impersonation keyword detected.",
    "High lexical entropy."
  ],
  "model_version": "rf-v1.2"
}
```
This single JSON object contains the combined output of our Lexical Extractor, Rule Engine, and ML Model.

---

## 3. The Dashboard: Turning JSON into Usable Advice

While developers love JSON, standard users do not. We need a frontend Dashboard (Phase 10) to display the results intuitively.

For our MVP, we will use **Streamlit** (or optionally React later). Streamlit allows us to rapidly build a Python-based web interface that connects directly to our FastAPI backend.

### Result Display Strategy
The UI must translate the API's technical response into a human-friendly format (incorporating Chapter 9's Explanation Design):

1.  **The Gauge:** The `risk_score` (87) is translated into a massive, visual gauge. (e.g., 0-30 = Green/Safe, 31-60 = Yellow/Suspicious, 61-100 = Red/Dangerous).
2.  **The Verdict:** The `prediction` ("phishing") is displayed as the core takeaway in plain text.
3.  **The Evidence Cards:** The `reasons` list is broken down into easily readable bullet points or cards. This is where the user learns *why* the URL is dangerous.
4.  **Community & History:** A secondary panel displaying how many times this URL has been scanned before, or if URLhaus explicitly reported it.

---

## 4. The Complete Data Flow

To summarize the complete system architecture for a public user:

1.  **Input:** The user pastes a URL into the Streamlit Dashboard.
2.  **Request:** Streamlit sends a `POST` request with the URL payload to the FastAPI server.
3.  **Validation:** FastAPI (Pydantic) validates the URL format.
4.  **Processing:** 
    *   The URL goes through `normalize.py`.
    *   `extractor.py` converts it to features (Lexical, Trust, Reputation).
    *   The `rules.py` engine and ML model generate the score and reasons.
5.  **Response:** FastAPI returns the JSON response.
6.  **Display:** Streamlit updates the UI, displaying the red gauge and the explanation cards to the user.

---

> [!TIP]
> **Next Steps in our Roadmap:** We have now covered the entire system from data collection to frontend UI. Our next logical step is to actually begin writing the code for Phase 1!
