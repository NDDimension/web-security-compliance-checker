"""
Port Security Checks
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


class PortChecks:
    """
    Checks related to open ports
    """

    def __init__(self, hostname):
        self.hostname = hostname

    def _check_port(self, port, timeout=2):
        """Check if a specific port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.hostname, port))
            sock.close()
            return port if result == 0 else None
        except:
            return None

    def check_only_standard_ports(self):
        """
        Check 1: Ensure only ports 80 and 443 are open
        Returns: (compliant: bool, remarks: str)
        """
        try:
            # Check common ports that should be closed
            ports_to_check = [
                21,  # FTP
                22,  # SSH
                23,  # Telnet
                25,  # SMTP
                53,  # DNS
                80,  # HTTP (allowed)
                110,  # POP3
                143,  # IMAP
                443,  # HTTPS (allowed)
                445,  # SMB
                3306,  # MySQL
                3389,  # RDP
                5432,  # PostgreSQL
                8080,  # HTTP Alt
                8443,  # HTTPS Alt
                8888,  # HTTP Alt
            ]

            open_ports = []
            # Use threading for faster port scanning
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_port = {
                    executor.submit(self._check_port, port): port
                    for port in ports_to_check
                }

                for future in as_completed(future_to_port):
                    result = future.result()
                    if result:
                        open_ports.append(result)

            # Filter out allowed ports
            allowed_ports = [80, 443]
            unexpected_ports = [p for p in open_ports if p not in allowed_ports]

            if unexpected_ports:
                return (
                    False,
                    f"Additional ports open: {', '.join(map(str, unexpected_ports))}",
                )

            if 80 in open_ports or 443 in open_ports:
                return (
                    True,
                    f"Only standard web ports open: {', '.join(map(str, [p for p in open_ports if p in allowed_ports]))}",
                )

            return (False, "No standard web ports (80, 443) detected as open")

        except Exception as e:
            return (False, f"Port scan failed: {str(e)}")
