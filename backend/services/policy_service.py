REMEDIATION_AVAILABLE = "REMEDIATION_AVAILABLE"
REMEDIATION_APPLIED = "REMEDIATION_APPLIED"
REMEDIATION_EXHAUSTED = "REMEDIATION_EXHAUSTED"

RISK_ACCEPTED_MESSAGE = (
    "Deployment Approved. All available remediations have been applied. "
    "Remaining vulnerabilities originate from upstream vendor packages. "
    "No vendor-provided fixes are currently available. Risk has been accepted."
)


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

    def has_blocking_dockerfile_findings(self, dockerfile_findings: list[dict] | None) -> bool:
        if not dockerfile_findings:
            return False
        blocking_severities = {"CRITICAL", "HIGH", "MEDIUM"}
        return any(
            finding.get("severity") in blocking_severities
            for finding in dockerfile_findings
        )

    def count_dockerfile_findings(self, dockerfile_findings: list[dict] | None) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in dockerfile_findings or []:
            severity = finding.get("severity", "LOW").upper()
            if severity in counts:
                counts[severity] += 1
            else:
                counts["LOW"] += 1
        return counts

    def evaluate_deployment(
        self,
        vulnerabilities: list[dict],
        remediation_state: str | None = None,
        pending_dependency_fixes: list[dict] | None = None,
        dockerfile_findings: list[dict] | None = None,
    ) -> str:
        if self.has_blocking_dockerfile_findings(dockerfile_findings):
            return "FAIL"

        if not vulnerabilities:
            return "PASS"

        classification = self.classify_vulnerabilities(vulnerabilities)

        if pending_dependency_fixes:
            critical_high_deps = [
                f for f in pending_dependency_fixes
                if f.get("severity") in ("CRITICAL", "HIGH")
            ]
            if critical_high_deps:
                return "FAIL"

        if classification["fixable_critical"] > 0 or classification["fixable_high"] > 0:
            return "FAIL"

        if classification["total_critical"] == 0 and classification["total_high"] == 0:
            return "PASS"

        remaining = len(vulnerabilities)
        all_unfixable = classification["fixable_count"] == 0 and remaining > 0

        if all_unfixable and remediation_state == REMEDIATION_EXHAUSTED:
            return "PASS"

        return "FAIL"

    def is_risk_accepted(
        self,
        vulnerabilities: list[dict],
        remediation_state: str | None = None,
        pending_dependency_fixes: list[dict] | None = None,
        remediation_states: list[str] | None = None,
    ) -> bool:
        if not vulnerabilities:
            return False

        classification = self.classify_vulnerabilities(vulnerabilities)
        if classification["fixable_count"] != 0:
            return False
        if classification["unfixable_count"] == 0:
            return False
        if pending_dependency_fixes:
            return False

        if remediation_states is not None:
            if not remediation_states:
                return False
            return all(state == REMEDIATION_EXHAUSTED for state in remediation_states)

        return remediation_state == REMEDIATION_EXHAUSTED

    def evaluate_repository(self, services: list[dict]) -> str:
        all_vulnerabilities = []
        remediation_states = []
        all_pending_deps = []
        all_dockerfile_findings = []

        for service in services:
            all_vulnerabilities.extend(service.get("vulnerabilities", []))
            state = service.get("remediation_state")
            if state:
                remediation_states.append(state)
            all_pending_deps.extend(service.get("pending_dependency_fixes", []))
            all_dockerfile_findings.extend(service.get("dockerfile_findings", []))

        if self.has_blocking_dockerfile_findings(all_dockerfile_findings):
            return "FAIL"

        if not all_vulnerabilities:
            return "PASS"

        aggregate_state = None
        if remediation_states and all(s == REMEDIATION_EXHAUSTED for s in remediation_states):
            aggregate_state = REMEDIATION_EXHAUSTED

        return self.evaluate_deployment(
            all_vulnerabilities,
            remediation_state=aggregate_state,
            pending_dependency_fixes=all_pending_deps,
            dockerfile_findings=all_dockerfile_findings,
        )

    def get_status_reason(
        self,
        vulnerabilities: list[dict],
        decision: str,
        remediation_state: str | None = None,
        pending_dependency_fixes: list[dict] | None = None,
        remediation_states: list[str] | None = None,
        dockerfile_findings: list[dict] | None = None,
    ) -> str:
        classification = self.classify_vulnerabilities(vulnerabilities)
        pending_deps = pending_dependency_fixes or []

        if decision == "PASS":
            if self.is_risk_accepted(
                vulnerabilities,
                remediation_state=remediation_state,
                pending_dependency_fixes=pending_deps,
                remediation_states=remediation_states,
            ):
                return RISK_ACCEPTED_MESSAGE
            return "No critical or high vulnerabilities detected."

        blocking_docker = [
            f for f in (dockerfile_findings or [])
            if isinstance(f, dict) and f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")
        ]
        if blocking_docker:
            return (
                f"{len(blocking_docker)} Dockerfile security misconfigurations "
                f"must be remediated before deployment."
            )

        if pending_deps:
            dep_files = sorted({f.get("source_file", "dependency file") for f in pending_deps})
            critical_high = sum(
                1 for f in pending_deps if f.get("severity") in ("CRITICAL", "HIGH")
            )
            if critical_high:
                return (
                    f"{critical_high} fixable critical/high dependency vulnerabilities "
                    f"require updates in {', '.join(dep_files)} before deployment."
                )
            return (
                f"{len(pending_deps)} dependency fixes required in "
                f"{', '.join(dep_files)} before deployment."
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
            return "Remediation available but not yet applied."

        return "Security gate failed. Remediation required before deployment."

    def evaluate(self, counts: dict) -> str:
        critical = counts.get("CRITICAL", 0)
        high = counts.get("HIGH", 0)
        if critical > 0 or high > 0:
            return "FAIL"
        return "PASS"

    def evaluate_service(self, counts: dict) -> str:
        return self.evaluate(counts)
