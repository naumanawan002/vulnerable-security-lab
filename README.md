# Vulnerable-by-Design Security Lab & Remediation Suite

[![CI](https://github.com/nauman/vulnerable-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/nauman/vulnerable-security-lab/actions)
[![Python Version](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python)](https://python.org/)
[![Security Standard](https://img.shields.io/badge/OWASP-Top%2010%20(2021)-red)](https://owasp.org/Top10/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An interactive, vulnerable-by-design application and Vulnerability Assessment & Penetration Testing (VAPT) defense suite. Demonstrates the **Top 5 Critical Web Vulnerabilities** side-by-side: each flaw is implemented with an intentionally vulnerable endpoint (`/vulnerable/...`), an exploit payload, a secure production remediation (`/safe/...`), and an automated test proving the fix.

Includes a comprehensive **[VAPT Remediation Guide](docs/vapt_remediation_guide.md)** detailing root causes, CWE mappings, and defense-in-depth patterns.

---

## Vulnerability & Remediation Matrix

| Flaw | CWE / OWASP | Vulnerable Flaw | Proof-of-Concept Exploit Payload | Remediated Defense Pattern |
| :--- | :--- | :--- | :--- | :--- |
| **SQL Injection (SQLi)** | CWE-89 / A03 | String interpolation in SQL string | `' OR 1=1 --` | Parameterized SQL query with bound placeholders |
| **Server-Side Request Forgery (SSRF)** | CWE-918 / A10 | Unrestricted outbound HTTP request | `http://169.254.169.254/latest/meta-data/` | DNS resolution check + RFC 1918/3927 private IP blocking |
| **Insecure Direct Object Reference (IDOR)** | CWE-639 / A01 | Direct database lookup by client ID | Direct fetch of invoice `101` from session `2` | Session ownership check (`invoice.user_id == current_user.id`) |
| **Cross-Site Scripting (XSS)** | CWE-79 / A03 | Raw reflection of user input in HTML | `<script>alert('XSS')</script>` | Context-aware HTML entity encoding + CSP headers |
| **Path Traversal / Arbitrary File Read** | CWE-22 / A01 | Insecure `os.path.join` with traversal tokens | `../../../../etc/passwd` | Canonical path resolution (`Path.resolve()`) + boundary check |

---

## Architecture Topology

```
                  ┌───────────────────────────────────────────────┐
                  │       Vulnerable-by-Design Security Lab       │
                  └───────┬───────────────────────────────┬───────┘
                          │                               │
        /vulnerable/*     ▼                               ▼     /safe/*
  ┌───────────────────────────────┐               ┌───────────────────────────────┐
  │ Intentionally Insecure Path   │               │ Hardened Production Defense   │
  │                               │               │                               │
  │ • String formatted SQL        │               │ • Parameterized queries       │
  │ • Unrestricted URL fetching   │               │ • Private IP / DNS filtering  │
  │ • Blind object retrieval      │               │ • Contextual ownership checks │
  │ • Raw unescaped DOM rendering │               │ • HTML entity encoding + CSP  │
  │ • Naive path concatenation    │               │ • Canonical path validation   │
  └───────────────────────────────┘               └───────────────────────────────┘
```

---

## Quickstart (Run in 2 Minutes)

### Option 1: Docker Compose
```bash
docker compose up --build
```
The lab is available at `http://localhost:8080`.

---

### Option 2: Local Python Setup
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run automated exploit and remediation test suite
pytest -v tests/

# 3. Start the application
make run
```

---

## Interactive Exploit & Fix Testing

### 1. SQL Injection (SQLi)
```bash
# Exploit: Dumps entire database
curl "http://localhost:8080/vulnerable/sqli?username=%27%20OR%201=1%20--"

# Remediated: Parameterized query blocks breakout (returns empty array)
curl "http://localhost:8080/safe/sqli?username=%27%20OR%201=1%20--"
```

### 2. Server-Side Request Forgery (SSRF)
```bash
# Exploit: Leaks simulated cloud metadata
curl "http://localhost:8080/vulnerable/ssrf?url=http://169.254.169.254/latest/meta-data/"

# Remediated: Rejects access to link-local cloud metadata (HTTP 403 Forbidden)
curl -i "http://localhost:8080/safe/ssrf?url=http://169.254.169.254/latest/meta-data/"
```

### 3. Insecure Direct Object Reference (IDOR)
```bash
# Exploit: User 2 views User 1's executive bonus invoice
curl "http://localhost:8080/vulnerable/invoices/101"

# Remediated: Ownership boundary check denies User 2 (HTTP 403 Forbidden)
curl -i -H "X-User-ID: 2" "http://localhost:8080/safe/invoices/101"
```

### 4. Cross-Site Scripting (XSS)
```bash
# Exploit: Raw script reflected in DOM
curl "http://localhost:8080/vulnerable/xss?name=%3Cscript%3Ealert(1)%3C/script%3E"

# Remediated: HTML escaped into &lt;script&gt; with Content-Security-Policy
curl "http://localhost:8080/safe/xss?name=%3Cscript%3Ealert(1)%3C/script%3E"
```

### 5. Path Traversal
```bash
# Exploit: Reads simulated /etc/passwd
curl "http://localhost:8080/vulnerable/files?filename=../../../../etc/passwd"

# Remediated: Path traversal blocked (HTTP 403 Forbidden)
curl -i "http://localhost:8080/safe/files?filename=../../../../etc/passwd"
```

---

## Documentation
- See [`docs/vapt_remediation_guide.md`](docs/vapt_remediation_guide.md) for code walkthroughs and CWE references.

---

## License
MIT License.
