import requests

from . import __version__, checks
from .models import SEVERITY_ORDER


class Scanner:
    def __init__(self, url, timeout=10):
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        self.url = url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = f"WebScan/{__version__} (security-audit)"

    def run(self):
        response = self.session.get(self.url, timeout=self.timeout)
        findings = []
        findings += checks.check_security_headers(response)
        findings += checks.check_info_disclosure(response)
        findings += checks.check_cookies(response)
        findings += checks.check_tls_certificate(response.url, self.timeout)
        if response.url.startswith("https://"):
            findings += checks.check_https_redirect(self.session, response.url, self.timeout)
        findings += checks.check_cors(self.session, response.url, self.timeout)
        findings += checks.check_sensitive_files(self.session, response.url, self.timeout)
        findings += checks.check_http_methods(self.session, response.url, self.timeout)
        findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
        return {"target": response.url, "status": response.status_code, "findings": findings}
