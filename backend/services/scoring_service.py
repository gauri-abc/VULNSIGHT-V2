class ScoringService:
    DEDUCTIONS = {
        "CRITICAL": 20,
        "HIGH": 10,
        "MEDIUM": 5,
        "LOW": 1,
    }

    def calculate_score(self, counts: dict) -> float:
        score = 100.0
        score -= counts.get("CRITICAL", 0) * self.DEDUCTIONS["CRITICAL"]
        score -= counts.get("HIGH", 0) * self.DEDUCTIONS["HIGH"]
        score -= counts.get("MEDIUM", 0) * self.DEDUCTIONS["MEDIUM"]
        score -= counts.get("LOW", 0) * self.DEDUCTIONS["LOW"]
        return max(0.0, round(score, 2))

    def calculate_service_score(self, vulnerabilities: list[dict]) -> float:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "LOW").upper()
            if severity in counts:
                counts[severity] += 1
        return self.calculate_score(counts)
