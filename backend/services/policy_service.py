REMEDIATION_AVAILABLE = "REMEDIATION_AVAILABLE"
REMEDIATION_APPLIED = "REMEDIATION_APPLIED"
REMEDIATION_EXHAUSTED = "REMEDIATION_EXHAUSTED"


class PolicyService:
    def is_fixable(self, vulnerability: dict) -> bool:
        fixed = (vulnerability.get("fixed_version") or "").strip()
        return bool(fixed) and fixed != "-"

    def classify_vulnerabilities(self, vulnerabilities: list[dict]) -> dict:
        fixable = []
        unfixable = []

        for vuln in vulnerabilities:
            entry = {
                "severity": vuln.get("severity", "LOW"),
                "fixed_version": vuln.get("fixed_version", ""),
                "package_name": vuln.get("package_name", ""),
                "cve_id": vuln.get("cve_id", ""),
            }
            if self.is_fixable(vuln):
                fixable.append(entry)
            else:
                unfixable.append(entry)

        def count_severity(items, severity):
            return sum(1 for v in items if v.get("severity") == severity)

        return {
            "fixable_count": len(fixable),
            "unfixable_count": len(unfixable),
            "fixable_critical": count_severity(fixable, "CRITICAL"),
            "fixable_high": count_severity(fixable, "HIGH"),
            "fixable_medium": count_severity(fixable, "MEDIUM"),
            "fixable_low": count_severity(fixable, "LOW"),
            "unfixable_critical": count_severity(unfixable, "CRITICAL"),
            "unfixable_high": count_severity(unfixable, "HIGH"),
            "unfixable_medium": count_severity(unfixable, "MEDIUM"),
            "unfixable_low": count_severity(unfixable, "LOW"),
            "total_critical": count_severity(fixable + unfixable, "CRITICAL"),
            "total_high": count_severity(fixable + unfixable, "HIGH"),
        }

    def evaluate_deployment(
        self,
        vulnerabilities: list[dict],
        remediation_state: str | None = None,
    ) -> str:
        if not vulnerabilities:
            return "PASS"

        classification = self.classify_vulnerabilities(vulnerabilities)

        if classification["fixable_critical"] > 0 or classification["fixable_high"] > 0:
            return "FAIL"

        if classification["total_critical"] == 0 and classification["total_high"] == 0:
            return "PASS"

        remaining = len(vulnerabilities)
        all_unfixable = classification["fixable_count"] == 0 and remaining > 0

        if all_unfixable and remediation_state == REMEDIATION_EXHAUSTED:
            return "PASS_WITH_RISK"

        return "FAIL"

    def evaluate_repository(self, services: list[dict]) -> str:
        all_vulnerabilities = []
        remediation_states = []

        for service in services:
            all_vulnerabilities.extend(service.get("vulnerabilities", []))
            state = service.get("remediation_state")
            if state:
                remediation_states.append(state)

        if not all_vulnerabilities:
            return "PASS"

        aggregate_state = None
        if remediation_states and all(s == REMEDIATION_EXHAUSTED for s in remediation_states):
            aggregate_state = REMEDIATION_EXHAUSTED

        return self.evaluate_deployment(
            all_vulnerabilities, remediation_state=aggregate_state
        )

    def get_status_reason(
        self,
        vulnerabilities: list[dict],
        decision: str,
        remediation_state: str | None = None,
    ) -> str:
        classification = self.classify_vulnerabilities(vulnerabilities)
        total = len(vulnerabilities)

        if decision == "PASS":
            return "No critical or high vulnerabilities detected."

        if decision == "PASS_WITH_RISK":
            return (
                f"{total} vulnerabilities remain. "
                f"{classification['unfixable_count']} have no vendor-provided fix. "
                f"Deployment may continue. All Dockerfile fixes have been applied. "
                f"Waiting for upstream vendor security updates."
            )

        if classification["fixable_critical"] > 0:
            return (
                f"{classification['fixable_critical']} fixable critical "
                f"vulnerabilities require remediation before deployment."
            )

        if classification["fixable_high"] > 0:
            return (
                f"{classification['fixable_high']} fixable high "
                f"vulnerabilities require remediation before deployment."
            )

        if remediation_state == REMEDIATION_AVAILABLE:
            return "Dockerfile remediation available but not yet applied."

        return "Security gate failed. Remediation required before deployment."

    def evaluate(self, counts: dict) -> str:
        critical = counts.get("CRITICAL", 0)
        high = counts.get("HIGH", 0)
        if critical > 0 or high > 0:
            return "FAIL"
        return "PASS"

    def evaluate_service(self, counts: dict) -> str:
        return self.evaluate(counts)
