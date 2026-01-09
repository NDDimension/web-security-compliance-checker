"""
Security Controller - Orchestrates all security checks
"""

from checks.https_checks import HTTPSChecks
from checks.header_checks import HeaderChecks
from checks.method_checks import MethodChecks
from checks.port_checks import PortChecks
from checks.tls_checks import TLSChecks
from checks.dns_checks import DNSChecks
from results import SecurityResults
from utils import extract_hostname
import traceback


class SecurityController:
    """
    Main controller that orchestrates all security compliance checks
    """

    def __init__(self, url):
        self.url = url
        self.hostname = extract_hostname(url)
        self.results = SecurityResults()

        # Initialize check modules
        self.https_checks = HTTPSChecks(url, self.hostname)
        self.header_checks = HeaderChecks(url, self.hostname)
        self.method_checks = MethodChecks(url, self.hostname)
        self.port_checks = PortChecks(self.hostname)
        self.tls_checks = TLSChecks(self.hostname)
        self.dns_checks = DNSChecks(self.hostname)

    def run_all_checks(self, progress_callback=None):
        """
        Execute all 28 security compliance checks
        Returns list of dictionaries with check results
        """
        total_checks = 28
        current_check = 0

        def update_progress():
            nonlocal current_check
            current_check += 1
            if progress_callback:
                progress_callback.progress(
                    int((current_check / total_checks) * 90) + 10
                )

        try:
            # Check 1: Port scan
            result = self.port_checks.check_only_standard_ports()
            self.results.add(1, "Only port 80 and 443 are open", result[0], result[1])
            update_progress()

            # Check 2: HTTP only operational
            result = self.https_checks.check_not_http_only()
            self.results.add(
                2,
                "Website should not be operational over HTTP only",
                result[0],
                result[1],
            )
            update_progress()

            # Check 3: HTTPS operational
            result = self.https_checks.check_https_operational()
            self.results.add(
                3, "Website is operational over HTTPS only", result[0], result[1]
            )
            update_progress()

            # Check 4: Webserver version
            result = self.header_checks.check_server_version_hidden()
            self.results.add(
                4, "Webserver version display is disabled", result[0], result[1]
            )
            update_progress()

            # Check 5: Software version
            result = self.header_checks.check_software_version_hidden()
            self.results.add(
                5,
                "PHP/CMS/Other software version display is disabled",
                result[0],
                result[1],
            )
            update_progress()

            # Check 6: ETag
            result = self.header_checks.check_etag_safe()
            self.results.add(
                6, "ETag does not leak sensitive information", result[0], result[1]
            )
            update_progress()

            # Check 7: X-XSS-Protection
            result = self.header_checks.check_xss_protection()
            self.results.add(7, "X-XSS-Protection header enabled", result[0], result[1])
            update_progress()

            # Check 8: X-Frame-Options
            result = self.header_checks.check_frame_options()
            self.results.add(8, "X-Frame-Options header enabled", result[0], result[1])
            update_progress()

            # Check 9: HSTS
            result = self.header_checks.check_hsts()
            self.results.add(
                9, "Strict-Transport-Security enabled", result[0], result[1]
            )
            update_progress()

            # Check 10: CSP
            result = self.header_checks.check_csp()
            self.results.add(
                10, "Content-Security-Policy enabled", result[0], result[1]
            )
            update_progress()

            # Check 11: Cookie flags
            result = self.header_checks.check_cookie_flags()
            self.results.add(
                11, "Cookies set with HttpOnly and Secure flags", result[0], result[1]
            )
            update_progress()

            # Check 12: SameSite
            result = self.header_checks.check_cookie_samesite()
            self.results.add(
                12,
                "Cookie SameSite attribute set to Strict or Lax",
                result[0],
                result[1],
            )
            update_progress()

            # Check 13: Cache-Control
            result = self.header_checks.check_cache_control()
            self.results.add(13, "Cache-Control header set", result[0], result[1])
            update_progress()

            # Check 14: HTTP methods
            result = self.method_checks.check_unsafe_methods_disabled()
            self.results.add(
                14,
                "HTTP methods PUT, DELETE, TRACE, OPTIONS disabled",
                result[0],
                result[1],
            )
            update_progress()

            # Check 15: Admin panels
            result = self.method_checks.check_admin_paths()
            self.results.add(
                15,
                "CMS/Tomcat/Admin management not accessible publicly",
                result[0],
                result[1],
            )
            update_progress()

            # Check 16: Old TLS/SSL versions
            result = self.tls_checks.check_old_protocols_disabled()
            self.results.add(16, "TLSv1.0, SSLv2, SSLv3 disabled", result[0], result[1])
            update_progress()

            # Check 17: Weak ciphers
            result = self.tls_checks.check_weak_ciphers_disabled()
            self.results.add(17, "Weak cipher suites disabled", result[0], result[1])
            update_progress()

            # Check 18: POODLE
            result = self.tls_checks.check_poodle_protected()
            self.results.add(18, "Protected from POODLE attack", result[0], result[1])
            update_progress()

            # Check 19: Logjam
            result = self.tls_checks.check_logjam_protected()
            self.results.add(19, "Protected from Logjam attack", result[0], result[1])
            update_progress()

            # Check 20: Heartbleed
            result = self.tls_checks.check_heartbleed_protected()
            self.results.add(20, "Protected from Heartbleed", result[0], result[1])
            update_progress()

            # Check 21: CRIME
            result = self.tls_checks.check_crime_protected()
            self.results.add(
                21, "Protected from CRIME vulnerability", result[0], result[1]
            )
            update_progress()

            # Check 22: CCS Injection
            result = self.tls_checks.check_ccs_injection_protected()
            self.results.add(22, "Protected from CCS Injection", result[0], result[1])
            update_progress()

            # Check 23: Anonymous ciphers
            result = self.tls_checks.check_anonymous_ciphers_disabled()
            self.results.add(
                23, "Anonymous cipher suites disabled", result[0], result[1]
            )
            update_progress()

            # Check 24: FREAK
            result = self.tls_checks.check_freak_protected()
            self.results.add(24, "Protected from OpenSSL FREAK", result[0], result[1])
            update_progress()

            # Check 25: DROWN
            result = self.tls_checks.check_drown_protected()
            self.results.add(25, "Protected from SSLv2 DROWN", result[0], result[1])
            update_progress()

            # Check 26: Forward Secrecy
            result = self.tls_checks.check_forward_secrecy()
            self.results.add(26, "Forward Secrecy supported", result[0], result[1])
            update_progress()

            # Check 27: HTTP/1.0
            result = self.https_checks.check_http10_blocked()
            self.results.add(27, "HTTP/1.0 requests blocked", result[0], result[1])
            update_progress()

            # Check 28: DNS CAA
            result = self.dns_checks.check_caa_record()
            self.results.add(28, "DNS CAA record present", result[0], result[1])
            update_progress()

        except Exception as e:
            print(f"Error during scan: {str(e)}")
            traceback.print_exc()

        return self.results.get_all()
