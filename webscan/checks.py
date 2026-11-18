"""Individual security checks.

Every check is passive / non-intrusive: it only sends ordinary GET/HEAD
requests and inspects the responses. No attack payloads are sent.
"""

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from .models import Finding

# ---------------------------------------------------------------------------
# 1. Security headers
# ---------------------------------------------------------------------------
SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "MEDIUM",
        "Forces browsers to use HTTPS and protects against downgrade attacks.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    "Content-Security-Policy": (
        "MEDIUM",
        "Restricts where scripts/styles can load from; main defence against XSS.",
        "Define a Content-Security-Policy, e.g. default-src 'self'",
    ),
    "X-Frame-Options": (
        "MEDIUM",
        "Prevents the page being framed by other sites (clickjacking).",
        "Add: X-Frame-Options: DENY (or use CSP frame-ancestors)",
    ),
    "X-Content-Type-Options": (
        "LOW",
        "Stops browsers MIME-sniffing responses into an executable type.",
        "Add: X-Content-Type-Options: nosniff",
    ),
    "Referrer-Policy": (
        "LOW",
        "Controls how much URL information is leaked in the Referer header.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    "Permissions-Policy": (
        "LOW",
        "Restricts access to browser features (camera, geolocation, ...).",
        "Add a Permissions-Policy header limiting unused features.",
    ),
}


def check_security_headers(response):
    findings = []
    headers = response.headers
    is_https = response.url.startswith("https://")
    for name, (sev, desc, rec) in SECURITY_HEADERS.items():
        if name == "Strict-Transport-Security" and not is_https:
            continue
        if name == "X-Frame-Options" and "frame-ancestors" in headers.get(
            "Content-Security-Policy", ""
        ):
            continue
        if name not in headers:
            findings.append(
                Finding("headers", f"Missing {name} header", sev, desc, rec)
            )

    csp = headers.get("Content-Security-Policy", "")
    if csp and ("'unsafe-inline'" in csp or "'unsafe-eval'" in csp):
        findings.append(
            Finding(
                "headers",
                "Weak Content-Security-Policy",
                "LOW",
                "CSP allows 'unsafe-inline' or 'unsafe-eval', which weakens XSS protection.",
                "Remove unsafe-inline/unsafe-eval; use nonces or hashes instead.",
                evidence=csp[:200],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# 2. Information disclosure in headers
# ---------------------------------------------------------------------------
DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def check_info_disclosure(response):
    findings = []
    for name in DISCLOSURE_HEADERS:
        value = response.headers.get(name)
        if value and any(ch.isdigit() for ch in value):
            findings.append(
                Finding(
                    "disclosure",
                    f"Version disclosed in {name} header",
                    "LOW",
                    "Revealing software versions helps attackers find known vulnerabilities.",
                    f"Remove or genericise the {name} header.",
                    evidence=f"{name}: {value}",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# 3. Cookie flags
# ---------------------------------------------------------------------------
def _raw_set_cookie_headers(response):
    raw = getattr(response, "raw", None)
    if raw is not None and hasattr(raw, "headers") and hasattr(raw.headers, "getlist"):
        return raw.headers.getlist("Set-Cookie")
    value = response.headers.get("Set-Cookie")
    return [value] if value else []


def check_cookies(response):
    findings = []
    is_https = response.url.startswith("https://")
    for header in _raw_set_cookie_headers(response):
        name = header.split("=", 1)[0].strip()
        attrs = header.lower()
        missing = []
        if is_https and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if "samesite" not in attrs:
            missing.append("SameSite")
        if missing:
            findings.append(
                Finding(
                    "cookies",
                    f"Cookie '{name}' missing {', '.join(missing)}",
                    "MEDIUM" if "HttpOnly" in missing or "Secure" in missing else "LOW",
                    "Cookies without these flags can be stolen via XSS, sent over "
                    "plain HTTP, or used in CSRF attacks.",
                    "Set cookies with: Secure; HttpOnly; SameSite=Lax (or Strict)",
                    evidence=header[:200],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# 4. HTTPS / TLS
# ---------------------------------------------------------------------------
def check_https_redirect(session, url, timeout):
    parsed = urlparse(url)
    http_url = parsed._replace(scheme="http").geturl()
    try:
        r = session.get(http_url, timeout=timeout, allow_redirects=True)
    except Exception:
        return []  # port 80 closed is fine
    if not r.url.startswith("https://"):
        return [
            Finding(
                "tls",
                "HTTP does not redirect to HTTPS",
                "MEDIUM",
                "Users visiting over plain HTTP stay on an unencrypted connection.",
                "Redirect all HTTP traffic to HTTPS (301) and enable HSTS.",
                evidence=f"{http_url} -> {r.url}",
            )
        ]
    return []


def check_tls_certificate(url, timeout):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return [
            Finding(
                "tls",
                "Site not served over HTTPS",
                "HIGH",
                "All traffic, including credentials and cookies, is unencrypted.",
                "Obtain a TLS certificate (e.g. Let's Encrypt) and serve over HTTPS.",
            )
        ]
    host = parsed.hostname
    port = parsed.port or 443
    findings = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version()
    except ssl.SSLCertVerificationError as e:
        return [
            Finding(
                "tls",
                "Invalid TLS certificate",
                "HIGH",
                "The certificate failed verification (expired, self-signed or wrong host).",
                "Install a valid certificate from a trusted CA.",
                evidence=str(e),
            )
        ]
    except Exception as e:
        return [Finding("tls", "TLS check could not complete", "INFO", str(e), "Check manually.")]

    expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )
    days_left = (expires - datetime.now(timezone.utc)).days
    if days_left < 30:
        findings.append(
            Finding(
                "tls",
                "TLS certificate expires soon",
                "MEDIUM",
                f"Certificate expires in {days_left} days.",
                "Renew the certificate and automate renewal.",
                evidence=cert["notAfter"],
            )
        )
    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
        findings.append(
            Finding(
                "tls",
                f"Outdated protocol negotiated ({version})",
                "HIGH",
                "Old TLS versions have known weaknesses.",
                "Disable TLS 1.0/1.1; support TLS 1.2 and 1.3 only.",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# 5. CORS
# ---------------------------------------------------------------------------
def check_cors(session, url, timeout):
    test_origin = "https://example-untrusted-origin.com"
    try:
        r = session.get(url, headers={"Origin": test_origin}, timeout=timeout)
    except Exception:
        return []
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
    if acao == test_origin:
        return [
            Finding(
                "cors",
                "CORS reflects arbitrary Origin",
                "HIGH" if acac else "MEDIUM",
                "The server echoes back any Origin, letting any website read responses"
                + (" with the user's cookies." if acac else "."),
                "Only allow a fixed allow-list of trusted origins.",
                evidence=f"Access-Control-Allow-Origin: {acao}; credentials={acac}",
            )
        ]
    if acao == "*":
        return [
            Finding(
                "cors",
                "CORS allows all origins (*)",
                "LOW",
                "Any website can read public responses. Fine for public APIs, risky otherwise.",
                "Restrict Access-Control-Allow-Origin to trusted origins if data is not public.",
            )
        ]
    return []


# ---------------------------------------------------------------------------
# 6. Exposed sensitive files
# ---------------------------------------------------------------------------
SENSITIVE_PATHS = {
    ".git/HEAD": ("HIGH", "ref:"),
    ".env": ("HIGH", "="),
    ".DS_Store": ("LOW", None),
    "phpinfo.php": ("MEDIUM", "phpinfo"),
    "server-status": ("MEDIUM", "Apache Server Status"),
    "backup.zip": ("HIGH", None),
    "config.php.bak": ("HIGH", None),
    ".htpasswd": ("HIGH", ":"),
}


def check_sensitive_files(session, url, timeout):
    findings = []
    base = url if url.endswith("/") else url + "/"
    for path, (sev, marker) in SENSITIVE_PATHS.items():
        target = urljoin(base, path)
        try:
            r = session.get(target, timeout=timeout, allow_redirects=False, stream=True)
            body = r.raw.read(2048, decode_content=True).decode("utf-8", "ignore") if r.status_code == 200 else ""
            r.close()
        except Exception:
            continue
        if r.status_code != 200:
            continue
        if marker and marker.lower() not in body.lower():
            continue  # avoid false positives from catch-all 200 pages
        if not marker and "<html" in body.lower():
            continue
        findings.append(
            Finding(
                "files",
                f"Sensitive file exposed: /{path}",
                sev,
                "This file should never be publicly accessible; it may leak source "
                "code, secrets or server details.",
                f"Block access to /{path} in your web server config and remove it from the web root.",
                evidence=target,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# 7. HTTP methods
# ---------------------------------------------------------------------------
def check_http_methods(session, url, timeout):
    try:
        r = session.options(url, timeout=timeout)
    except Exception:
        return []
    allow = r.headers.get("Allow", "") + "," + r.headers.get("Access-Control-Allow-Methods", "")
    risky = [m for m in ("TRACE", "PUT", "DELETE") if m in allow.upper()]
    if risky:
        return [
            Finding(
                "methods",
                f"Potentially risky HTTP methods advertised: {', '.join(risky)}",
                "LOW",
                "TRACE can enable cross-site tracing; PUT/DELETE should only be "
                "enabled on authenticated API endpoints.",
                "Disable methods that are not required.",
                evidence=allow.strip(","),
            )
        ]
    return []
