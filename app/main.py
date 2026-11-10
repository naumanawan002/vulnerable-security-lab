from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import HTMLResponse, JSONResponse
import html
import ipaddress
import os
import pathlib
import socket
import urllib.parse
from app.db import get_db

app = FastAPI(
    title="Vulnerable-by-Design Security Lab",
    description="Interactive application demonstrating Top Web Vulnerabilities (SQLi, SSRF, IDOR, XSS, Path Traversal) with safe remediations",
    version="1.0.0"
)

db = get_db()

# Sample files storage path for Path Traversal demo
FILES_DIR = pathlib.Path(__file__).parent.parent / "data" / "public_files"
FILES_DIR.mkdir(parents=True, exist_ok=True)
(FILES_DIR / "welcome.txt").write_text("Public welcome document. Authorized for public release.")

# -------------------------------------------------------------
# 1. SQL Injection (SQLi)
# -------------------------------------------------------------
@app.get("/vulnerable/sqli")
def vulnerable_sqli(username: str):
    cursor = db.cursor()
    # VULNERABLE: Direct string interpolation into SQL query string
    query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"
    try:
        rows = cursor.execute(query).fetchall()
        return [dict(row) for row in rows]
    except Exception as e:
        return {"error": str(e), "executed_query": query}

@app.get("/safe/sqli")
def safe_sqli(username: str):
    cursor = db.cursor()
    # SAFE: Parameterized query binding prevents SQL syntax breakout
    query = "SELECT id, username, email, role FROM users WHERE username = ?"
    rows = cursor.execute(query, (username,)).fetchall()
    return [dict(row) for row in rows]

# -------------------------------------------------------------
# 2. Server-Side Request Forgery (SSRF)
# -------------------------------------------------------------
@app.get("/vulnerable/ssrf")
def vulnerable_ssrf(url: str):
    # VULNERABLE: Fetches arbitrary URL without checking target IP or scheme
    parsed = urllib.parse.urlparse(url)
    if parsed.hostname in ["169.254.169.254", "localhost", "127.0.0.1"]:
        # Simulated cloud metadata / internal service response
        return {
            "status": "ssrf_success",
            "target": url,
            "internal_metadata_leaked": {
                "ami_id": "ami-0123456789abcdef0",
                "iam_role_secret": "AWS_SECRET_KEY_EXPOSED_VIA_METADATA",
            }
        }
    return {"status": "fetched", "target": url}

@app.get("/safe/ssrf")
def safe_ssrf(url: str):
    # SAFE: Validates scheme, resolves DNS, and blocks private/loopback/cloud metadata CIDRs
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Only HTTP/HTTPS protocols are permitted")

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid target URL host")

    try:
        # Resolve hostname to IPv4/IPv6 address
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Could not resolve target hostname")

    # Block private, loopback, link-local, and reserved ranges per RFC 1918 / RFC 3927
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        raise HTTPException(
            status_code=403,
            detail=f"SSRF Protection: Access to private/internal network IP ({ip_str}) is prohibited"
        )

    return {"status": "permitted", "resolved_ip": ip_str, "target": url}

# -------------------------------------------------------------
# 3. Insecure Direct Object Reference (IDOR)
# -------------------------------------------------------------
@app.get("/vulnerable/invoices/{invoice_id}")
def vulnerable_idor(invoice_id: int):
    # VULNERABLE: Direct access to record without validating caller authorization
    cursor = db.cursor()
    row = cursor.execute("SELECT id, user_id, amount, description FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return dict(row)

@app.get("/safe/invoices/{invoice_id}")
def safe_idor(invoice_id: int, x_user_id: int = Header(default=2)):
    # SAFE: Enforces ownership boundary check (invoice.user_id == caller_id)
    cursor = db.cursor()
    row = cursor.execute("SELECT id, user_id, amount, description FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Invoice not found")
    
    invoice = dict(row)
    if invoice["user_id"] != x_user_id:
        raise HTTPException(status_code=403, detail="Forbidden: You are not authorized to view this invoice")

    return invoice

# -------------------------------------------------------------
# 4. Cross-Site Scripting (XSS)
# -------------------------------------------------------------
@app.get("/vulnerable/xss", response_class=HTMLResponse)
def vulnerable_xss(name: str):
    # VULNERABLE: Unescaped reflection of user input into raw HTML
    return f"<html><body><h1>Welcome, {name}!</h1></body></html>"

@app.get("/safe/xss", response_class=HTMLResponse)
def safe_xss(name: str):
    # SAFE: HTML entity encoding escapes <, >, &, ", and '
    safe_name = html.escape(name)
    response = HTMLResponse(content=f"<html><body><h1>Welcome, {safe_name}!</h1></body></html>")
    # Defense-in-depth: Set Content-Security-Policy header
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'none';"
    return response

# -------------------------------------------------------------
# 5. Path Traversal
# -------------------------------------------------------------
@app.get("/vulnerable/files")
def vulnerable_path_traversal(filename: str):
    # VULNERABLE: os.path.join with user-controlled traversal sequences (../../)
    target_path = os.path.join(FILES_DIR, filename)
    try:
        if "passwd" in filename or "etc" in filename:
            # Simulated sensitive system file read
            return {"file": filename, "content": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"}
        with open(target_path, "r") as f:
            return {"file": filename, "content": f.read()}
    except Exception as e:
        return {"error": str(e), "path_resolved": target_path}

@app.get("/safe/files")
def safe_path_traversal(filename: str):
    # SAFE: Canonical resolution with strict directory boundary check
    base_dir = FILES_DIR.resolve()
    target_path = (base_dir / filename).resolve()

    # Enforce that target_path is strictly inside base_dir
    try:
        target_path.relative_to(base_dir)
    except ValueError:
        raise HTTPException(
            status_code=403,
            detail="Path Traversal detected: Target file path escapes the authorized directory boundary"
        )

    if not target_path.exists() or not target_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    return {"file": filename, "content": target_path.read_text()}
