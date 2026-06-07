import re

from services.trivy_service import TrivyService


class DockerfileSecurityService:
    RULE_ALIASES = {
        "missing-user": "missing-user",
        "ds002": "missing-user",
        "ds026": "missing-healthcheck",
        "missing-healthcheck": "missing-healthcheck",
        "ds029": "latest-tag",
        "latest-tag": "latest-tag",
        "ds030": "unpinned-base-image",
        "unpinned-base-image": "unpinned-base-image",
        "ds031": "missing-label",
        "missing-label": "missing-label",
        "ds005": "privileged-container",
        "privileged-container": "privileged-container",
        "root-user": "root-user",
        "ds001": "root-user",
    }

    CUSTOM_CHECKS = [
        {
            "key": "missing-user",
            "rule": "Missing USER Instruction",
            "severity": "HIGH",
            "description": "Dockerfile does not define a USER instruction to run as non-root.",
            "recommendation": "Add a USER instruction (e.g. USER appuser) before CMD or ENTRYPOINT.",
            "check": "_check_missing_user",
        },
        {
            "key": "root-user",
            "rule": "Root User",
            "severity": "HIGH",
            "description": "Container is configured to run as the root user.",
            "recommendation": "Create a dedicated non-root user and switch with USER before runtime.",
            "check": "_check_root_user",
        },
        {
            "key": "missing-healthcheck",
            "rule": "Missing HEALTHCHECK",
            "severity": "MEDIUM",
            "description": "Dockerfile does not define a HEALTHCHECK instruction.",
            "recommendation": "Add HEALTHCHECK to monitor container health and enable orchestrator recovery.",
            "check": "_check_missing_healthcheck",
        },
        {
            "key": "latest-tag",
            "rule": "Latest Tag Usage",
            "severity": "HIGH",
            "description": "Base image uses the :latest tag which is mutable and unpinned.",
            "recommendation": "Pin the base image to a specific version tag (e.g. python:3.11.11-slim).",
            "check": "_check_latest_tag",
        },
        {
            "key": "unpinned-base-image",
            "rule": "Unpinned Base Image",
            "severity": "MEDIUM",
            "description": "Base image tag does not use a fully pinned semantic version.",
            "recommendation": "Use a fully pinned base image digest or explicit version tag.",
            "check": "_check_unpinned_base",
        },
        {
            "key": "missing-label",
            "rule": "Missing LABEL",
            "severity": "LOW",
            "description": "Dockerfile does not include LABEL metadata for ownership and versioning.",
            "recommendation": "Add LABEL instructions for maintainer, version, and description.",
            "check": "_check_missing_label",
        },
        {
            "key": "privileged-container",
            "rule": "Privileged Container Risk",
            "severity": "CRITICAL",
            "description": "Dockerfile contains instructions that grant elevated container privileges.",
            "recommendation": "Remove --privileged, dangerous cap_add, or insecure security_opt settings.",
            "check": "_check_privileged_risk",
        },
    ]

    def __init__(self):
        self.trivy_service = TrivyService()

    def scan(self, dockerfile_path: str, dockerfile_content: str = "") -> list[dict]:
        trivy_findings = self.trivy_service.scan_dockerfile(dockerfile_path)
        custom_findings = self._run_custom_checks(dockerfile_content or "")
        return self._merge_findings(trivy_findings, custom_findings)

    def _normalize_key(self, rule: str, rule_id: str = "") -> str:
        candidates = [rule_id, rule]
        for candidate in candidates:
            normalized = re.sub(r"[^a-z0-9]+", "-", (candidate or "").lower()).strip("-")
            if normalized in self.RULE_ALIASES:
                return self.RULE_ALIASES[normalized]
            for alias, key in self.RULE_ALIASES.items():
                if alias in normalized:
                    return key
        return normalized or "dockerfile-misconfiguration"

    def _merge_findings(self, trivy_findings: list[dict], custom_findings: list[dict]) -> list[dict]:
        merged: dict[str, dict] = {}

        for finding in trivy_findings + custom_findings:
            key = self._normalize_key(finding.get("rule", ""), finding.get("rule_id", ""))
            entry = {
                "severity": finding.get("severity", "LOW"),
                "rule": finding.get("rule", "Dockerfile Misconfiguration"),
                "description": finding.get("description", ""),
                "recommendation": finding.get("recommendation", ""),
                "source": finding.get("source", "trivy"),
                "rule_id": finding.get("rule_id", ""),
            }
            if key not in merged:
                merged[key] = entry
                continue
            existing = merged[key]
            severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            if severity_rank.get(entry["severity"], 0) > severity_rank.get(existing["severity"], 0):
                merged[key] = entry

        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return sorted(
            merged.values(),
            key=lambda f: (order.get(f.get("severity", "LOW"), 4), f.get("rule", "")),
        )

    def _run_custom_checks(self, content: str) -> list[dict]:
        if not content.strip():
            return []

        findings = []
        for spec in self.CUSTOM_CHECKS:
            checker = getattr(self, spec["check"])
            if checker(content):
                findings.append(
                    {
                        "severity": spec["severity"],
                        "rule": spec["rule"],
                        "description": spec["description"],
                        "recommendation": spec["recommendation"],
                        "source": "vulnsight",
                        "rule_id": spec["key"],
                    }
                )
        return findings

    def _check_missing_user(self, content: str) -> bool:
        return "USER " not in content.upper()

    def _check_root_user(self, content: str) -> bool:
        user_lines = re.findall(r"^USER\s+(.+)$", content, re.MULTILINE | re.IGNORECASE)
        if not user_lines:
            return True
        last_user = user_lines[-1].strip().lower()
        return last_user in ("0", "root", "0:0", "root:root")

    def _check_missing_healthcheck(self, content: str) -> bool:
        return "HEALTHCHECK" not in content.upper()

    def _check_latest_tag(self, content: str) -> bool:
        from_lines = re.findall(r"^FROM\s+(.+)$", content, re.MULTILINE | re.IGNORECASE)
        return any(":latest" in line.lower() or line.strip().endswith(":latest") for line in from_lines)

    def _check_unpinned_base(self, content: str) -> bool:
        from_lines = re.findall(r"^FROM\s+(.+)$", content, re.MULTILINE | re.IGNORECASE)
        if not from_lines:
            return False

        for line in from_lines:
            image_ref = line.strip().split("@")[0].split(" ")[0]
            if ":" not in image_ref:
                return True
            tag = image_ref.rsplit(":", 1)[-1]
            if tag == "latest":
                continue
            if re.fullmatch(r"[a-f0-9]{12,64}", tag):
                continue
            if re.search(r"\d+\.\d+", tag):
                continue
            return True
        return False

    def _check_missing_label(self, content: str) -> bool:
        return "LABEL " not in content.upper()

    def _check_privileged_risk(self, content: str) -> bool:
        patterns = (
            r"--privileged\b",
            r"--cap-add\s*=\s*ALL",
            r"cap_add:\s*\[?\s*['\"]?ALL",
            r"security_opt:\s*\[?\s*['\"]?seccomp:unconfined",
            r"--security-opt\s+seccomp=unconfined",
        )
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns)
