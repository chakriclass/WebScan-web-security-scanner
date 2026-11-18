# WebScan 🔍 – Web Security Misconfiguration Scanner

A lightweight Python tool that audits a website for common security weaknesses and
gives clear, actionable fixes. It is **passive and non-intrusive**: it sends only
normal HTTP requests and inspects the responses. It never sends attack payloads.

> ⚠️ **Legal notice:** Only scan websites you own or have written permission to test.

## Features

| Check | What it finds |
|-------|---------------|
| Security headers | Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy; weak CSP |
| Information disclosure | Software versions leaked via `Server`, `X-Powered-By`, etc. |
| Cookie security | Cookies missing `Secure`, `HttpOnly`, `SameSite` |
| HTTPS / TLS | No HTTPS, missing HTTP→HTTPS redirect, invalid or expiring certificate, outdated TLS version |
| CORS | Origin reflection, wildcard origins, credentials exposure |
| Sensitive files | Exposed `.git/`, `.env`, `.htpasswd`, backups, `phpinfo.php`, `server-status` |
| HTTP methods | Risky methods like `TRACE`, `PUT`, `DELETE` enabled |

Each finding gets a severity (**HIGH / MEDIUM / LOW / INFO**), and the site gets an overall score out of 100.

## Installation

```bash
git clone https://github.com/<your-username>/web-vuln-scanner.git
cd web-vuln-scanner
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python -m webscan https://example.com

# Save an HTML report
python -m webscan https://example.com -o report.html

# Save a JSON report (useful for CI pipelines)
python -m webscan https://example.com -o report.json
```

The command exits with code `1` if any HIGH-severity issue is found, so you can
use it in CI/CD to fail a build.

### Example output

```
Target : https://example.com/  (HTTP 200)
Score  : 62/100
Summary: HIGH=0, MEDIUM=3, LOW=3, INFO=0
----------------------------------------------------------------------
[MEDIUM] Missing Content-Security-Policy header
    Restricts where scripts/styles can load from; main defence against XSS.
    Fix: Define a Content-Security-Policy, e.g. default-src 'self'
...
```

## Project structure

```
web-vuln-scanner/
├── webscan/
│   ├── __init__.py
│   ├── __main__.py     # enables `python -m webscan`
│   ├── cli.py          # command-line interface
│   ├── scanner.py      # runs all checks
│   ├── checks.py       # individual security checks
│   ├── models.py       # Finding data model
│   └── report.py       # console / JSON / HTML reports
├── tests/
│   └── test_checks.py
├── requirements.txt
├── LICENSE
└── README.md
```

## Running tests

```bash
pip install pytest
pytest
```

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN Web Security](https://developer.mozilla.org/en-US/docs/Web/Security)

## License

MIT
