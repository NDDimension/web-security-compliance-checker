"""
DNS Security Checks
"""

import dns.resolver


class DNSChecks:
    """
    Checks related to DNS configuration
    """

    def __init__(self, hostname):
        self.hostname = hostname

    def check_caa_record(self):
        """
        Check 28: DNS CAA record present
        Returns: (compliant: bool, remarks: str)
        """
        try:
            # Query for CAA records
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            try:
                answers = resolver.resolve(self.hostname, "CAA")

                if answers:
                    caa_records = []
                    for rdata in answers:
                        caa_records.append(str(rdata))

                    return (
                        True,
                        f"CAA record(s) present: {', '.join(caa_records[:3])}",
                    )

            except dns.resolver.NoAnswer:
                return (False, "No CAA records found for domain")

            except dns.resolver.NXDOMAIN:
                return (False, "Domain does not exist")

            return (False, "No CAA records configured")

        except Exception as e:
            return (False, f"CAA check failed: {str(e)}")
