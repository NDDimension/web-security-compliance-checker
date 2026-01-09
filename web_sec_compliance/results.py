"""
Results Management
"""


class SecurityResults:
    """
    Manages and formats security check results
    """

    def __init__(self):
        self.results = []

    def add(self, sr_no, parameter, compliant, remarks):
        """
        Add a security check result

        Args:
            sr_no: Serial number (1-28)
            parameter: Security parameter description
            compliant: Boolean compliance status
            remarks: Additional information
        """
        self.results.append(
            {
                "sr_no": sr_no,
                "parameter": parameter,
                "status": "Y" if compliant else "N",
                "remarks": remarks,
            }
        )

    def get_all(self):
        """Return all results as list of dictionaries"""
        return sorted(self.results, key=lambda x: x["sr_no"])

    def get_summary(self):
        """Return compliance summary"""
        total = len(self.results)
        compliant = sum(1 for r in self.results if r["status"] == "Y")

        return {
            "total_checks": total,
            "compliant": compliant,
            "non_compliant": total - compliant,
            "compliance_rate": (compliant / total * 100) if total > 0 else 0,
        }
