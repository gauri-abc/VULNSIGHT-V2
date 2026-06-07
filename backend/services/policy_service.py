class PolicyService:
    def evaluate(self, counts: dict) -> str:
        critical = counts.get("CRITICAL", 0)
        high = counts.get("HIGH", 0)
        medium = counts.get("MEDIUM", 0)

        if critical > 0:
            return "FAIL"
        if high > 5:
            return "FAIL"
        if medium > 20:
            return "WARNING"
        return "PASS"

    def evaluate_service(self, counts: dict) -> str:
        return self.evaluate(counts)
