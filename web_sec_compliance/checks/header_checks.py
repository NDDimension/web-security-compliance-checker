"""
HTTP Security Header Checks
"""

import requests
from utils import safe_request


class HeaderChecks:
    """
    Checks related to HTTP security headers
    """

    def __init__(self, url, hostname):
        self.url = url
        self.hostname = hostname
        self.response = None
        self._fetch_response()

    def _fetch_response(self):
        """Fetch HTTPS response for header inspection"""
        try:
            https_url = f"https://{self.hostname}"
            self.response = safe_request(https_url, timeout=10)
        except:
            self.response = None

    def check_server_version_hidden(self):
        """
        Check 4: Ensure webserver version is not exposed
        Returns: (compliant: bool, remarks: str)
        """
        if not self.response:
            return (False, "Cannot fetch headers")

        server_header = self.response.headers.get("Server", "")

        if not server_header:
            return (True, "Server header not present (version hidden)")

        # Check for version numbers in server header
        suspicious_patterns = ["/", "apache", "nginx", "iis", "microsoft"]
        server_lower = server_header.lower()

        # If contains version pattern like "Apache/2.4.41"
        if "/" in server_header:
            return (False, f"Server version exposed: {server_header}")

        # Generic server name without version is acceptable
        return (True, f"Server header present but no version: {server_header}")

    def check_software_version_hidden(self):
        """
        Check 5: Ensure PHP/CMS version is not exposed
        Returns: (compliant: bool, remarks: str)
        """
        if not self.response:
            return (False, "Cannot fetch headers")

        # Check common headers that expose software versions
        exposing_headers = [
            "X-Powered-By",
            "X-AspNet-Version",
            "X-AspNetMvc-Version",
            "X-Generator",
            "X-Drupal-Cache",
            "X-Joomla-Version",
        ]

        found_versions = []
        for header in exposing_headers:
            value = self.response.headers.get(header)
            if value:
                found_versions.append(f"{header}: {value}")

        if found_versions:
            return (False, f"Software versions exposed - {', '.join(found_versions)}")

        return (True, "No software version headers detected")

    def check_etag_safe(self):
        """
        Check 6: Ensure ETag doesn't leak sensitive information (inode)
        Returns: (compliant: bool, remarks: str)
        """
        if not self.response:
            return (False, "Cannot fetch headers")

        etag = self.response.headers.get("ETag", "")

        if not etag:
            return (True, "ETag header not present")

        # Apache's default ETag includes inode: "inode-size-timestamp"
        # Weak ETags start with W/
        # Strong ETags with 3+ hyphen-separated hex values likely contain inode

        etag_clean = etag.strip('"').strip("W/").strip('"')
        parts = etag_clean.split("-")

        if len(parts) >= 3:
            return (False, f"ETag may contain inode information: {etag}")

        return (True, f"ETag appears safe: {etag}")

    def check_xss_protection(self):
        """
        Check 7: X-XSS-Protection header enabled
        Returns: (compliant: bool, remarks: str)
        """
        if not self.response:
            return (False, "Cannot fetch headers")

        xss_header = self.response.headers.get("X-XSS-Protection", "")

        if not xss_header:
            return (False, "X-XSS-Protection header not set")

        if "1" in xss_header:
            if "mode=block" in xss_header:
                return (True, f"X-XSS-Protection enabled with blocking: {xss_header}")
            return (True, f"X-XSS-Protection enabled: {xss_header}")

        return (False, f"X-XSS-Protection disabled: {xss_header}")

    def check_frame_options(self):
        """
        Check 8: X-Frame-Options header enabled
        Returns: (compliant: bool, remarks: str)
        """
        if not self.response:
            return (False, "Cannot fetch headers")

        frame_options = self.response.headers.get("X-Frame-Options", "")

        if not frame_options:
            return (False, "X-Frame-Options header not set")

        frame_options_upper = frame_options.upper()

        if "DENY" in frame_options_upper or "SAMEORIGIN" in frame_options_upper:
            return (True, f"X-Frame-Options properly configured: {frame_options}")

        return (False, f"X-Frame-Options set but weak: {frame_options}")

    def check_hsts(self):
        """
        Check 9: Strict-Transport-Security enabled
        Returns: (compliant: bool, remarks: str)
        """
        if not self.response:
            return (False, "Cannot fetch headers")

        hsts = self.response.headers.get("Strict-Transport-Security", "")

        if not hsts:
            return (False, "HSTS header not set")

        # Check for max-age
        if "max-age=" in hsts.lower():
            return (True, f"HSTS enabled: {hsts}")

        return (False, f"HSTS header present but misconfigured: {hsts}")

    def check_csp(self):
        """
        Check 10: Content-Security-Policy enabled
        Returns: (compliant: bool, remarks: str)
        """
        if not self.response:
            return (False, "Cannot fetch headers")

        csp = self.response.headers.get("Content-Security-Policy", "")
        csp_report = self.response.headers.get(
            "Content-Security-Policy-Report-Only", ""
        )

        if csp:
            return (True, f"CSP header present: {csp[:100]}...")
        elif csp_report:
            return (True, f"CSP (report-only) present: {csp_report[:100]}...")

        return (False, "Content-Security-Policy header not set")

    def check_cookie_flags(self):
        """
        Check 11: Cookies have HttpOnly and Secure flags
        Returns: (compliant: bool, remarks: str)
        """
        if not self.response:
            return (False, "Cannot fetch headers")

        cookies = self.response.headers.get("Set-Cookie", "")

        if not cookies:
            return (True, "No cookies set by server")

        # Split multiple Set-Cookie headers
        cookie_list = cookies.split(",") if "," in cookies else [cookies]

        issues = []
        for cookie in cookie_list:
            cookie_lower = cookie.lower()
            if "httponly" not in cookie_lower:
                issues.append("HttpOnly missing")
            if "secure" not in cookie_lower:
                issues.append("Secure missing")

        if issues:
            return (False, f"Cookie security issues: {', '.join(set(issues))}")

        return (True, "All cookies have HttpOnly and Secure flags")

    def check_cookie_samesite(self):
        """
        Check 12: Cookie SameSite attribute set
        Returns: (compliant: bool, remarks: str)
        """
        if not self.response:
            return (False, "Cannot fetch headers")

        cookies = self.response.headers.get("Set-Cookie", "")

        if not cookies:
            return (True, "No cookies set by server")

        cookie_lower = cookies.lower()

        if "samesite=strict" in cookie_lower:
            return (True, "SameSite=Strict configured")
        elif "samesite=lax" in cookie_lower:
            return (True, "SameSite=Lax configured")
        elif "samesite" in cookie_lower:
            return (False, "SameSite set but not to Strict/Lax")

        return (False, "SameSite attribute not set on cookies")

    def check_cache_control(self):
        """
        Check 13: Cache-Control header set
        Returns: (compliant: bool, remarks: str)
        """
        if not self.response:
            return (False, "Cannot fetch headers")

        cache_control = self.response.headers.get("Cache-Control", "")

        if cache_control:
            return (True, f"Cache-Control set: {cache_control}")

        return (False, "Cache-Control header not set")
