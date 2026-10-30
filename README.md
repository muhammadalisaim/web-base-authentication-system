# Automated Website Security Audit & Vulnerability Scanner — Complete Edition

A comprehensive web application security audit scanner and vulnerability management platform built with FastAPI, SQLAlchemy, and Pydantic.

## Key Capabilities

### 1. Findings and Risk Engine
- **Deterministic Fingerprinting:** Generates SHA-256 fingerprints to identify recurring defects across scan cycles.
- **Smart Deduplication:** Automatically tags repeated findings (`is_duplicate`, `duplicate_of_id`) and tracks `first_seen_at` and `last_seen_at`.
- **Severity & Confidence Scoring:** Assigns standard severity levels (`critical`, `high`, `medium`, `low`, `info`) and calculates individual finding risk scores:
  $$\text{Risk Score} = \text{Severity Weight} \times \text{Confidence}$$
- **Security Score & Letter Grade:** Computes a normalized security score (0.0 to 100.0) and letter grades (A, B, C, D, F) with discount logic to avoid penalizing users twice for duplicate findings.

### 2. Dashboard and Reports
- **Real-Time Scan Progress:** Track scan execution phase and completion percentage via `GET /api/scans/{id}/progress`.
- **Multi-Format Report Generation:** Generate executive reports via `GET /api/scans/{id}/report?format=html|json|markdown`.
  - Self-contained, print-friendly **HTML Report** with security score badge, risk cards, and actionable remediation steps.
  - Formatted **Markdown Report** for documentation or GitHub issues.
  - Machine-readable **JSON Audit Report**.
- **Interactive Web Dashboard:** Accessible at `/dashboard` to view overall posture, recent scans, and live progress.
- **Scan History & Metrics:** Aggregate metrics on total targets, projects, average security score, and open issues by severity.

### 3. Number Trace & SMS Origin Analyzer
- **Reverse Number Trace (`POST /api/trace-number`):** Resolves any phone number to country, allocated operator, MCC/MNC, line type, time zone and validity, using the offline libphonenumber carrier dataset plus a built-in Pakistani operator prefix table.
- **WhatsApp Profile Fingerprint:** Resolves the public `wa.me` landing page to the account's display name, Business Account status, profile photo and verified badge — then flags machine-generated (keyboard-mash) display names and photo-less bulk accounts.
- **Pakistan Operator Intelligence:** Full `0300`–`0399` allocation map (Jazz, Zong, Ufone, Telenor Pakistan, SCO, Instaphone) with legacy brand resolution (Mobilink/Warid → Jazz), the 2026 PTML amalgamation, and Mobile Number Portability caveats.
- **Honest Location Reporting:** The engine never fabricates a coordinate. It states plainly that a mobile prefix identifies the *operator nationwide*, not a place, and lists the only legal routes to a real identity or location — PTA complaint, NCCIA / FIA Cyber Crime, FIR, operator HLR request, and device-level access.
- **SMS Origin Model:** Explains the actual SMS delivery chain (originating operator SMSC → your operator's SMSC → handset) and classifies the sender channel as individual SIM, operator short code, brand/service ID, or international number.
- **Message Risk Scoring (`POST /api/analyze-sms`):** Heuristic engine that detects credential/OTP theft, pressure tactics, prize and job scams, investment lures, impersonation, homograph and punycode domains, shortened links, raw-IP URLs, risky TLDs, zero-width characters and mixed-script spoofing.
- **Deep Link Analysis (`POST /api/analyze-link`):** Resolves a link from a scam message all the way down — expands shortener/redirect chains, resolves DNS, geolocates the hosting server, identifies the hosting provider and ASN, reads domain registration via RDAP, and checks four threat-intelligence sources (AlienVault OTX, URLhaus, OpenPhish, Google Safe Browsing). Emits a paste-ready technical annexure for a PTA / NCCIA complaint. Refuses internal-network targets (SSRF guard).
- **Operator-Wide Reuse Detection:** Free, no-key operation by default. Optional live HLR/spam lookup via `PHONE_LOOKUP_PROVIDER` + `PHONE_LOOKUP_API_KEY` (numverify / abstractapi / ipqualityscore) for current post-porting carrier and spam score.
- **Actionable Escalation:** Risk-tiered remediation steps including PTA's 0800-55055 line and complaint portal, NCCIA / FIA Cyber Crime, SBP and bank fraud hotlines.

### 4. Testing, Safety & Controls
- **Strict Scope Boundaries:** Enforces `SCANNER_ALLOWED_HOSTS` allowlist checks before initiating any connection.
- **Configurable Timeouts:** Bounded network connections (`SCANNER_TIMEOUT_SECONDS=4.0`).
- **Per-Host Rate Limiter:** Built-in leaky-bucket rate limiter (`SCANNER_RATE_LIMIT_RPS=10.0`) to avoid overwhelming target services.
- **Fast Scan Cancellation:** Gracefully abort in-flight scans via `POST /api/scans/{id}/stop`.
- **Robust Error Handling:** Network and protocol errors are trapped and logged safely without disclosing internal server stack traces.

### 5. Advanced Security Scanners
- **API Security Scanner:**
  - Security headers audit (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`).
  - Permissive CORS testing (wildcard with credentials, arbitrary origin reflection).
  - Dangerous HTTP methods detection (OPTIONS check for `TRACE`, `TRACK`).
  - Publicly accessible API specifications (`/openapi.json`, `/swagger.json`, `/api-docs`).
- **Controlled Authentication & Authorization Checks:**
  - Sensitive file & repository exposure (`/.env`, `/.git/HEAD`, `/config.json`).
  - Cookie security attributes audit (`Secure`, `HttpOnly`, `SameSite`).
  - Publicly reachable administrative interfaces (`/admin`, `/administrator`).
- **JavaScript Analysis:**
  - Leaked credentials and API keys in client-side code (AWS access keys, JWTs, secret assignments).
  - Risky DOM sinks susceptible to client-side XSS (`eval()`, `document.write()`).
  - Outdated/vulnerable client libraries (e.g. jQuery < 3.5.0, Lodash, AngularJS 1.x).
- **Dependency & Technology Stack Scanning:**
  - Server and runtime banner information disclosure (`Server`, `X-Powered-By`).
  - Outdated or End-of-Life software detection (PHP 7.x, Apache 2.2).
  - Software Bill of Materials (SBOM) manifest scanning for Python `requirements.txt`.
- **Automated Scan Scheduling:**
  - Recurring scheduled scans (`hourly`, `daily`, `weekly`, `monthly`) via `POST /api/schedules`.
- **Webhook Alert Notifications:**
  - Configurable webhook notifications triggered on scan completion or high-severity vulnerabilities.

---

## Quickstart & Launch Options

### 1. Secure HTTPS Server (Port 8443) — Recommended
Eliminates browser "Not Secure" warning with automated TLS 1.3 encryption and SAN certificate:
```bash
python3 run_https.py
```
- Local HTTPS: <https://localhost:8443/>
- Mobile/LAN HTTPS: `https://10.10.69.195:8443/`
*(In your browser, click "Advanced" -> "Proceed to localhost (unsafe)" to establish the encrypted SSL session).*

### 2. Standard HTTP Server (Port 8080)
```bash
python3 server.py
```
- Access at: <http://localhost:8080/> or `http://10.10.69.195:8080/`

### 3. FastAPI Production Uvicorn Server (Port 8000)
```bash
python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```
- Interactive API Swagger Docs: <http://127.0.0.1:8000/docs>
- Tech Stack Live Probe: <http://127.0.0.1:8000/api/detect-stack?url=https://www.iub.edu.pk/>
- 18 Security Hardening Rules: <http://127.0.0.1:8000/api/security-checklist>

### 4. Docker Deployment
```bash
docker compose up -d --build
```

### 5. Number Trace & SMS Analyzer — Direct API Use
```bash
# Trace a number
curl -X POST http://localhost:8080/api/trace-number \
  -H "Content-Type: application/json" \
  -d '{"number":"+923412107586"}'

# Analyse a suspicious SMS
curl -X POST http://localhost:8080/api/analyze-sms \
  -H "Content-Type: application/json" \
  -d '{"sender":"+923412107586","text":"Verify your account at http://example.xyz/login and confirm your OTP 123456"}'

# Deep-analyse a link received in a scam message
curl -X POST http://localhost:8080/api/analyze-link \
  -H "Content-Type: application/json" \
  -d '{"url":"http://123.ywxww.net/login"}'
```

All three endpoints are also exposed in the web dashboard under **"Number Trace & SMS Origin Analyzer"**, and work fully offline (no API key required). The link analyzer uses only public, keyless reputation feeds and can be turned off entirely with `PHONE_DEEP_LINK_ANALYSIS=0`.

### Command-line use
```bash
python3 phone_trace.py number +923412107586     # trace a number
python3 phone_trace.py link http://example.com  # deep link analysis
python3 phone_trace.py message "text" +92341... # message risk scoring
```

