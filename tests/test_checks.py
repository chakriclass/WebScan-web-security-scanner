from types import SimpleNamespace

from requests.structures import CaseInsensitiveDict

from webscan import checks


def fake_response(url="https://example.com/", headers=None):
    return SimpleNamespace(url=url, headers=CaseInsensitiveDict(headers or {}), raw=None)


def test_missing_headers_detected():
    findings = checks.check_security_headers(fake_response())
    titles = {f.title for f in findings}
    assert "Missing Content-Security-Policy header" in titles
    assert "Missing Strict-Transport-Security header" in titles


def test_all_headers_present():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()",
    }
    assert checks.check_security_headers(fake_response(headers=headers)) == []


def test_hsts_not_required_on_http():
    findings = checks.check_security_headers(fake_response(url="http://example.com/"))
    assert all("Strict-Transport-Security" not in f.title for f in findings)


def test_version_disclosure():
    findings = checks.check_info_disclosure(fake_response(headers={"Server": "Apache/2.4.1"}))
    assert len(findings) == 1


def test_insecure_cookie():
    resp = fake_response(headers={"Set-Cookie": "session=abc; Path=/"})
    findings = checks.check_cookies(resp)
    assert len(findings) == 1
    assert "HttpOnly" in findings[0].title


def test_secure_cookie():
    resp = fake_response(headers={"Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Lax"})
    assert checks.check_cookies(resp) == []


def test_plain_http_flagged():
    findings = checks.check_tls_certificate("http://example.com", timeout=5)
    assert findings[0].severity == "HIGH"
