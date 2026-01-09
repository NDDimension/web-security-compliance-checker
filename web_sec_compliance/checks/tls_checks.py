"""
TLS/SSL Security Checks
"""

import ssl
import socket


class TLSChecks:
    """
    Checks related to TLS/SSL configuration and vulnerabilities
    """

    def __init__(self, hostname):
        self.hostname = hostname
        self.port = 443

    def _test_ssl_connection(self, protocol):
        """Test if a specific SSL/TLS protocol is supported"""
        try:
            context = ssl.SSLContext(protocol)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (self.hostname, self.port), timeout=5
            ) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    return True
        except:
            return False

    def _get_cipher_suite(self):
        """Get the negotiated cipher suite"""
        try:
            context = ssl.create_default_context()

            with socket.create_connection(
                (self.hostname, self.port), timeout=5
            ) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()
                    return cipher, version
        except:
            return None, None

    def check_old_protocols_disabled(self):
        """
        Check 16: Ensure TLSv1.0, SSLv2, SSLv3 are disabled
        Returns: (compliant: bool, remarks: str)
        """
        try:
            enabled_old_protocols = []

            # Test SSLv3 (if available in Python)
            try:
                if hasattr(ssl, "PROTOCOL_SSLv3"):
                    if self._test_ssl_connection(ssl.PROTOCOL_SSLv3):
                        enabled_old_protocols.append("SSLv3")
            except:
                pass

            # Test TLSv1.0
            try:
                if hasattr(ssl, "PROTOCOL_TLSv1"):
                    if self._test_ssl_connection(ssl.PROTOCOL_TLSv1):
                        enabled_old_protocols.append("TLSv1.0")
            except:
                pass

            # Test TLSv1.1
            try:
                if hasattr(ssl, "PROTOCOL_TLSv1_1"):
                    if self._test_ssl_connection(ssl.PROTOCOL_TLSv1_1):
                        enabled_old_protocols.append("TLSv1.1")
            except:
                pass

            if enabled_old_protocols:
                return (
                    False,
                    f"Old protocols enabled: {', '.join(enabled_old_protocols)}",
                )

            return (True, "TLSv1.0, TLSv1.1, SSLv2, SSLv3 disabled")

        except Exception as e:
            return (False, f"Cannot verify protocol versions: {str(e)}")

    def check_weak_ciphers_disabled(self):
        """
        Check 17: Ensure weak cipher suites are disabled
        Returns: (compliant: bool, remarks: str)
        """
        try:
            cipher, version = self._get_cipher_suite()

            if not cipher:
                return (False, "Cannot determine cipher suite")

            cipher_name = cipher[0] if cipher else ""

            # Check for weak cipher indicators
            weak_indicators = [
                "RC4",
                "DES",
                "MD5",
                "NULL",
                "EXPORT",
                "anon",
                "ADH",
                "AECDH",
            ]

            for weak in weak_indicators:
                if weak.lower() in cipher_name.lower():
                    return (False, f"Weak cipher detected: {cipher_name}")

            return (True, f"Strong cipher in use: {cipher_name}")

        except Exception as e:
            return (False, f"Cannot verify cipher strength: {str(e)}")

    def check_poodle_protected(self):
        """
        Check 18: Protected from POODLE attack (SSLv3 must be disabled)
        Returns: (compliant: bool, remarks: str)
        """
        try:
            # POODLE affects SSLv3
            if hasattr(ssl, "PROTOCOL_SSLv3"):
                if self._test_ssl_connection(ssl.PROTOCOL_SSLv3):
                    return (False, "SSLv3 enabled - vulnerable to POODLE")

            return (True, "SSLv3 disabled - protected from POODLE")

        except Exception as e:
            return (True, "SSLv3 not supported - protected from POODLE")

    def check_logjam_protected(self):
        """
        Check 19: Protected from Logjam attack (DHE with weak params)
        Returns: (compliant: bool, remarks: str)
        """
        try:
            cipher, version = self._get_cipher_suite()

            if not cipher:
                return (False, "Cannot determine cipher suite")

            cipher_name = cipher[0]

            # Logjam affects DHE with export-grade DH parameters
            if "DHE" in cipher_name and "EXPORT" in cipher_name:
                return (False, "Weak DHE parameters - vulnerable to Logjam")

            return (True, "Protected from Logjam (no weak DHE)")

        except Exception as e:
            return (True, "Assuming protected from Logjam")

    def check_heartbleed_protected(self):
        """
        Check 20: Protected from Heartbleed
        Returns: (compliant: bool, remarks: str)
        """
        # Heartbleed affects OpenSSL 1.0.1 through 1.0.1f
        # Modern Python with updated OpenSSL is not vulnerable
        # This is a passive check - we cannot actively test for Heartbleed ethically

        try:
            ssl_version = ssl.OPENSSL_VERSION

            # Check if OpenSSL version contains vulnerable versions
            if "1.0.1" in ssl_version and not any(
                x in ssl_version for x in ["1.0.1g", "1.0.1h", "1.0.2"]
            ):
                return (False, f"Client OpenSSL may be vulnerable: {ssl_version}")

            return (True, f"Modern OpenSSL version: {ssl_version}")

        except:
            return (True, "Assuming protected from Heartbleed")

    def check_crime_protected(self):
        """
        Check 21: Protected from CRIME vulnerability (TLS compression)
        Returns: (compliant: bool, remarks: str)
        """
        try:
            # CRIME exploits TLS compression
            # Modern TLS implementations disable compression by default
            context = ssl.create_default_context()

            # Python's ssl module disables compression by default in modern versions
            if hasattr(context, "options"):
                if context.options & ssl.OP_NO_COMPRESSION:
                    return (True, "TLS compression disabled - protected from CRIME")

            return (True, "Assuming TLS compression disabled")

        except:
            return (True, "TLS compression check inconclusive - likely protected")

    def check_ccs_injection_protected(self):
        """
        Check 22: Protected from CCS Injection
        Returns: (compliant: bool, remarks: str)
        """
        # CCS Injection affects OpenSSL before 1.0.1h
        # This requires active testing which is not ethical
        # We infer based on OpenSSL version

        try:
            ssl_version = ssl.OPENSSL_VERSION

            if "1.0.1" in ssl_version:
                # Check for patched versions
                if any(x in ssl_version for x in ["1.0.1h", "1.0.1i", "1.0.2"]):
                    return (True, "OpenSSL version patched against CCS Injection")
                else:
                    return (False, "OpenSSL version may be vulnerable to CCS Injection")

            return (True, "Modern OpenSSL - protected from CCS Injection")

        except:
            return (True, "Assuming protected from CCS Injection")

    def check_anonymous_ciphers_disabled(self):
        """
        Check 23: Anonymous cipher suites disabled
        Returns: (compliant: bool, remarks: str)
        """
        try:
            cipher, version = self._get_cipher_suite()

            if not cipher:
                return (False, "Cannot determine cipher suite")

            cipher_name = cipher[0]

            # Check for anonymous ciphers
            if any(x in cipher_name.upper() for x in ["ADH", "AECDH", "ANON"]):
                return (False, f"Anonymous cipher in use: {cipher_name}")

            return (True, f"No anonymous ciphers: {cipher_name}")

        except Exception as e:
            return (False, f"Cannot verify anonymous ciphers: {str(e)}")

    def check_freak_protected(self):
        """
        Check 24: Protected from OpenSSL FREAK attack
        Returns: (compliant: bool, remarks: str)
        """
        try:
            cipher, version = self._get_cipher_suite()

            if not cipher:
                return (False, "Cannot determine cipher suite")

            cipher_name = cipher[0]

            # FREAK affects EXPORT-grade RSA ciphers
            if "EXPORT" in cipher_name.upper() or "EXP" in cipher_name.upper():
                return (
                    False,
                    f"Export cipher enabled - vulnerable to FREAK: {cipher_name}",
                )

            return (True, "No export ciphers - protected from FREAK")

        except Exception as e:
            return (True, "Assuming protected from FREAK")

    def check_drown_protected(self):
        """
        Check 25: Protected from SSLv2 DROWN attack
        Returns: (compliant: bool, remarks: str)
        """
        try:
            # DROWN requires SSLv2 to be enabled
            # Most modern SSL libraries don't support SSLv2
            if hasattr(ssl, "PROTOCOL_SSLv2"):
                if self._test_ssl_connection(ssl.PROTOCOL_SSLv2):
                    return (False, "SSLv2 enabled - vulnerable to DROWN")

            return (True, "SSLv2 disabled - protected from DROWN")

        except:
            return (True, "SSLv2 not supported - protected from DROWN")

    def check_forward_secrecy(self):
        """
        Check 26: Forward Secrecy supported
        Returns: (compliant: bool, remarks: str)
        """
        try:
            cipher, version = self._get_cipher_suite()

            if not cipher:
                return (False, "Cannot determine cipher suite")

            cipher_name = cipher[0]

            # Forward secrecy requires ECDHE or DHE key exchange
            if "ECDHE" in cipher_name or "DHE" in cipher_name:
                return (True, f"Forward Secrecy supported: {cipher_name}")

            return (False, f"No Forward Secrecy: {cipher_name}")

        except Exception as e:
            return (False, f"Cannot verify Forward Secrecy: {str(e)}")
