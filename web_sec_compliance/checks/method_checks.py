"""
HTTP Method and Path Security Checks
"""

import requests
from utils import safe_request


class MethodChecks:
    """
    Checks related to HTTP methods and admin paths
    """

    def __init__(self, url, hostname):
        self.url = url
        self.hostname = hostname

    def check_unsafe_methods_disabled(self):
        """
        Check 14: Ensure PUT, DELETE, TRACE, OPTIONS are disabled
        Returns: (compliant: bool, remarks: str)
        """
        try:
            base_url = f"https://{self.hostname}"
            unsafe_methods = ["PUT", "DELETE", "TRACE", "OPTIONS"]
            enabled_methods = []

            for method in unsafe_methods:
                try:
                    response = requests.request(
                        method=method,
                        url=base_url,
                        timeout=5,
                        verify=True,
                        allow_redirects=False,
                    )

                    # Methods returning 200, 201, 204 are considered enabled
                    # 405 Method Not Allowed means disabled (good)
                    # 501 Not Implemented means disabled (good)
                    if response.status_code not in [405, 501, 400, 404]:
                        enabled_methods.append(f"{method}({response.status_code})")

                except requests.exceptions.RequestException:
                    # If request fails, consider method disabled
                    pass

            if enabled_methods:
                return (False, f"Unsafe methods enabled: {', '.join(enabled_methods)}")

            return (True, "All unsafe HTTP methods disabled (405/501)")

        except Exception as e:
            return (False, f"Cannot verify method restrictions: {str(e)}")

    def check_admin_paths(self):
        """
        Check 15: Ensure admin/management interfaces are not publicly accessible
        Returns: (compliant: bool, remarks: str)
        """
        try:
            base_url = f"https://{self.hostname}"

            # Common admin paths to check
            admin_paths = [
                "/admin",
                "/administrator",
                "/wp-admin",
                "/wp-login.php",
                "/manager",
                "/tomcat",
                "/phpmyadmin",
                "/cpanel",
                "/webmin",
                "/console",
            ]

            accessible_paths = []

            for path in admin_paths:
                try:
                    response = safe_request(base_url + path, timeout=5)

                    if response and response.status_code == 200:
                        accessible_paths.append(path)

                except:
                    pass

            if accessible_paths:
                return (False, f"Admin paths accessible: {', '.join(accessible_paths)}")

            return (True, "No common admin paths publicly accessible")

        except Exception as e:
            return (False, f"Cannot verify admin path restriction: {str(e)}")
