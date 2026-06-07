REMEDIATION_AVAILABLE = "REMEDIATION_AVAILABLE"
REMEDIATION_APPLIED = "REMEDIATION_APPLIED"
REMEDIATION_EXHAUSTED = "REMEDIATION_EXHAUSTED"

RISK_ACCEPTED_MESSAGE = (
    "Deployment Approved. No fixes are available in Dockerfile or dependency files. "
    "Remaining vulnerabilities originate from upstream vendor packages. "
    "No vendor-provided fixes are currently available. Risk has been accepted."
)

PASS_NO_ACTION_MESSAGE = (
    "Deployment Approved. No actionable fixes are required in Dockerfile or dependency files."
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

    def has_actionable_dependency_fixes(
        self, pending_dependency_fixes: list[dict] | None
    ) -> bool:
        return bool(pending_dependency_fixes)

    def has_blocking_dockerfile_findings(self, dockerfile_findings: list[dict] | None) -> bool:
        return bool(dockerfile_findings)

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
        has_actionable_dockerfile_fix: bool = False,
    ) -> str:
        _ = remediation_state, dockerfile_findings

        if self.has_actionable_dependency_fixes(pending_dependency_fixes):
            return "FAIL"

        if has_actionable_dockerfile_fix:
            return "FAIL"

        return "PASS"

    def is_risk_accepted(
        self,
        vulnerabilities: list[dict],
        remediation_state: str | None = None,
        pending_dependency_fixes: list[dict] | None = None,
        remediation_states: list[str] | None = None,
        has_actionable_dockerfile_fix: bool = False,
    ) -> bool:
        _ = remediation_state, remediation_states

        if self.has_actionable_dependency_fixes(pending_dependency_fixes):
            return False
        if has_actionable_dockerfile_fix:
            return False
        if not vulnerabilities:
            return False

        classification = self.classify_vulnerabilities(vulnerabilities)
        if classification["unfixable_count"] == 0:
            return False

        return classification["fixable_count"] == 0

    def evaluate_repository(self, services: list[dict]) -> str:
        all_pending_deps = []

        for service in services:
            pending_deps = service.get("pending_dependency_fixes", [])
            all_pending_deps.extend(pending_deps)
            if service.get("has_actionable_dockerfile_fix"):
                return "FAIL"

        if self.has_actionable_dependency_fixes(all_pending_deps):
            return "FAIL"

        return "PASS"

    def get_status_reason(
        self,
        vulnerabilities: list[dict],
        decision: str,
        remediation_state: str | None = None,
        pending_dependency_fixes: list[dict] | None = None,
        remediation_states: list[str] | None = None,
        dockerfile_findings: list[dict] | None = None,
        has_actionable_dockerfile_fix: bool = False,
    ) -> str:
        _ = remediation_state, remediation_states, dockerfile_findings
        pending_deps = pending_dependency_fixes or []

        if decision == "PASS":
            if self.is_risk_accepted(
                vulnerabilities,
                pending_dependency_fixes=pending_deps,
                has_actionable_dockerfile_fix=has_actionable_dockerfile_fix,
            ):
                return RISK_ACCEPTED_MESSAGE
            return PASS_NO_ACTION_MESSAGE

        if pending_deps:
            dep_files = sorted({f.get("source_file", "dependency file") for f in pending_deps})
            return (
                f"{len(pending_deps)} dependency update(s) required in "
                f"{', '.join(dep_files)} before deployment."
            )

        if has_actionable_dockerfile_fix:
            return (
                "Dockerfile remediations are available and must be applied before deployment."
            )

        return "Security gate failed. Remediation required before deployment."

    def evaluate(self, counts: dict) -> str:
        critical = counts.get("CRITICAL", 0)
        high = counts.get("HIGH", 0)
        if critical > 0 or high > 0:
            return "FAIL"
        return "PASS"

    def evaluate_service(self, counts: dict) -> str:
        return self.evaluate(counts)
