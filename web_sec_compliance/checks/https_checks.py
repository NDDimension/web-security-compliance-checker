"""
HTTPS and Protocol Checks
"""

import requests
import socket
from utils import safe_request


class HTTPSChecks:
    """
    Checks related to HTTPS availability and configuration
    """

    def __init__(self, url, hostname):
        self.url = url
        self.hostname = hostname

    def check_not_http_only(self):
        """
        Check 2: Ensure website is not operational ONLY over HTTP
        Returns: (compliant: bool, remarks: str)
        """
        try:
            # Try HTTP
            http_url = f"http://{self.hostname}"
            http_response = safe_request(http_url, timeout=5)

            # Try HTTPS
            https_url = f"https://{self.hostname}"
            https_response = safe_request(https_url, timeout=5)

            if http_response and not https_response:
                return (False, "Site operational only over HTTP - HTTPS not available")

            if http_response and https_response:
                # Check if HTTP redirects to HTTPS
                if http_response.url.startswith("https://"):
                    return (True, "HTTP properly redirects to HTTPS")
                else:
                    return (False, "HTTP does not redirect to HTTPS")

            if https_response and not http_response:
                return (True, "HTTPS available, HTTP not responding")

            return (False, "Neither HTTP nor HTTPS responding")

        except Exception as e:
            return (False, f"Check failed: {str(e)}")

    def check_https_operational(self):
        """
        Check 3: Ensure website is operational over HTTPS
        Returns: (compliant: bool, remarks: str)
        """
        try:
            https_url = f"https://{self.hostname}"
            response = safe_request(https_url, timeout=10)

            if response and response.status_code < 400:
                return (True, f"HTTPS operational (Status: {response.status_code})")
            elif response:
                return (False, f"HTTPS returns error (Status: {response.status_code})")
            else:
                return (False, "HTTPS not accessible")

        except Exception as e:
            return (False, f"HTTPS check failed: {str(e)}")

    def check_http10_blocked(self):
        """
        Check 27: Ensure HTTP/1.0 requests are blocked or rejected
        Returns: (compliant: bool, remarks: str)
        """
        try:
            # Create raw HTTP/1.0 request
            request = f"GET / HTTP/1.0\r\nHost: {self.hostname}\r\n\r\n"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)

            # Try HTTPS port
            try:
                sock.connect((self.hostname, 443))
                sock.send(request.encode())
                response = sock.recv(4096).decode("utf-8", errors="ignore")
                sock.close()

                if "HTTP/1.0" in response or "HTTP/1.1" in response:
                    if "400" in response or "505" in response or "426" in response:
                        return (True, "HTTP/1.0 rejected with error status")
                    else:
                        return (False, "HTTP/1.0 requests accepted")

                return (True, "HTTP/1.0 appears to be blocked")

            except:
                # If connection fails, consider it blocked
                return (True, "HTTP/1.0 connection refused")

        except Exception as e:
            return (False, f"Cannot verify HTTP/1.0 blocking: {str(e)}")
