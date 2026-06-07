import re

from services.dependency_service import DependencyService
from services.dockerfile_security_service import DockerfileSecurityService
from services.policy_service import (
    PolicyService,
    REMEDIATION_AVAILABLE,
    REMEDIATION_APPLIED,
    REMEDIATION_EXHAUSTED,
)
from services.scoring_service import ScoringService
from services.trivy_service import TrivyService


class RemediationService:
    OS_PACKAGE_PREFIXES = (
        "lib", "libc", "openssl", "glibc", "zlib", "curl", "bash",
        "perl", "gnutls", "sqlite", "expat", "krb", "pam", "systemd",
        "apt", "dpkg", "gcc", "binutils", "coreutils", "tar", "gzip",
        "busybox", "musl", "alpine", "debian", "ubuntu",
    )

    REMEDIATION_MARKERS = (
        "apt-get upgrade",
        "apk upgrade",
        "pip install --upgrade pip",
        "--no-cache-dir",
        "user appuser",
        "user node",
    )

    BASE_IMAGE_UPGRADES = [
        (r"FROM\s+python:3\.12-slim\b", "FROM python:3.12.11-slim-bookworm"),
        (r"FROM\s+python:3\.11-slim\b", "FROM python:3.11.11-slim-bookworm"),
        (r"FROM\s+python:3\.10-slim\b", "FROM python:3.10.16-slim-bookworm"),
        (r"FROM\s+python:3\.9-slim\b", "FROM python:3.9.21-slim-bookworm"),
        (r"FROM\s+python:3\.12\b", "FROM python:3.12.11-slim-bookworm"),
        (r"FROM\s+python:3\.11\b", "FROM python:3.11.11-slim-bookworm"),
        (r"FROM\s+node:(\d+)-alpine\b", r"FROM node:\1.20.4-alpine3.20"),
        (r"FROM\s+node:(\d+)-slim\b", r"FROM node:\1.20.4-bookworm-slim"),
        (r"FROM\s+node:(\d+)\b", r"FROM node:\1.20.4-bookworm-slim"),
        (r"FROM\s+openjdk:(\d+)-slim\b", r"FROM eclipse-temurin:\1-jre-jammy"),
        (r"FROM\s+openjdk:(\d+)\b", r"FROM eclipse-temurin:\1-jre-jammy"),
        (r"FROM\s+eclipse-temurin:(\d+)-jre\b", r"FROM eclipse-temurin:\1-jre-jammy"),
        (r"FROM\s+nginx:latest\b", "FROM nginx:1.27.2-alpine"),
        (r"FROM\s+nginx:alpine\b", "FROM nginx:1.27.2-alpine"),
        (r"FROM\s+nginx:(\d+\.\d+)\b", r"FROM nginx:\1-alpine"),
        (r"FROM\s+golang:(\d+\.\d+)-alpine\b", r"FROM golang:\1.23-alpine3.20"),
        (r"FROM\s+golang:(\d+\.\d+)\b", r"FROM golang:\1.23-bookworm"),
        (r"FROM\s+redis:alpine\b", "FROM redis:7.4.1-alpine"),
        (r"FROM\s+redis:latest\b", "FROM redis:7.4.1-alpine"),
        (r"FROM\s+postgres:alpine\b", "FROM postgres:16.6-alpine"),
        (r"FROM\s+postgres:latest\b", "FROM postgres:16.6-alpine"),
        (r"FROM\s+ubuntu:(\d+\.\d+)\b", r"FROM ubuntu:\1.04"),
        (r"FROM\s+debian:bookworm-slim\b", "FROM debian:bookworm-20241202-slim"),
        (r"FROM\s+debian:bookworm\b", "FROM debian:bookworm-20241202-slim"),
        (r"FROM\s+debian:bullseye-slim\b", "FROM debian:bullseye-20241202-slim"),
    ]

    def __init__(self):
        self.trivy_service = TrivyService()
        self.scoring_service = ScoringService()
        self.policy_service = PolicyService()
        self.dependency_service = DependencyService()
        self.dockerfile_security_service = DockerfileSecurityService()

    def generate_remediation(
        self,
        dockerfile_content: str,
        vulnerabilities: list[dict],
        service_name: str,
        dockerfile_path: str,
        previous_remediation: dict | None = None,
        baseline: dict | None = None,
        build_context: str = "",
        dockerfile_findings: list[dict] | None = None,
    ) -> dict:
        dockerfile_findings = dockerfile_findings or []
        annotated_vulns = self.dependency_service.annotate_vulnerabilities(
            vulnerabilities,
            build_context,
            dockerfile_content,
            self.policy_service.is_fixable,
        )
        dependency_fixes = self.dependency_service.generate_dependency_fixes(
            vulnerabilities,
            build_context,
            dockerfile_content,
            self.policy_service.is_fixable,
        )
        pending_dependency_fixes = self.dependency_service.get_pending_dependency_fixes(
            dependency_fixes
        )
        dependency_patches = self.dependency_service.generate_dependency_patches(
            dependency_fixes, build_context
        )

        vuln_counts = self.trivy_service.count_by_severity(vulnerabilities)
        docker_counts = self.policy_service.count_dockerfile_findings(dockerfile_findings)
        current_counts = self.scoring_service.merge_counts(vuln_counts, docker_counts)
        classification = self.policy_service.classify_vulnerabilities(vulnerabilities)
        current_score = self.scoring_service.calculate_score(current_counts)
        vuln_summary = self._build_vulnerability_summary(annotated_vulns)

        baseline = baseline or {}
        original_score = baseline.get("original_score", current_score)
        original_counts = {
            "CRITICAL": baseline.get("original_critical", current_counts["CRITICAL"]),
            "HIGH": baseline.get("original_high", current_counts["HIGH"]),
            "MEDIUM": baseline.get("original_medium", current_counts["MEDIUM"]),
            "LOW": baseline.get("original_low", current_counts["LOW"]),
        }

        candidate_updated = self._generate_updated_dockerfile(
            dockerfile_content, annotated_vulns, dockerfile_findings
        )
        previous_updated = (
            (previous_remediation or {}).get("updated_dockerfile") or ""
        )

        state, status_message, show_generate_fix = self._determine_state(
            dockerfile_content=dockerfile_content,
            candidate_updated=candidate_updated,
            previous_updated=previous_updated,
            vulnerabilities=vulnerabilities,
            pending_dependency_fixes=pending_dependency_fixes,
            dependency_fixes=dependency_fixes,
        )

        if state in (REMEDIATION_APPLIED, REMEDIATION_EXHAUSTED):
            updated_dockerfile = ""
            root_causes = self._analyze_remaining_root_causes(
                vulnerabilities, dockerfile_content, service_name, dockerfile_path, state
            )
            recommended_fixes = self._generate_post_apply_guidance(
                vulnerabilities, state
            )
        else:
            updated_dockerfile = candidate_updated
            root_causes = self._analyze_root_causes(
                vulnerabilities,
                dockerfile_content,
                service_name,
                dockerfile_path,
                dependency_fixes,
                dockerfile_findings,
            )
            recommended_fixes = self._generate_recommended_fixes(
                annotated_vulns,
                dockerfile_content,
                root_causes,
                dependency_fixes,
                dockerfile_findings,
            )

        current_decision = self.policy_service.evaluate_deployment(
            vulnerabilities,
            remediation_state=state,
            pending_dependency_fixes=pending_dependency_fixes,
            dockerfile_findings=dockerfile_findings,
        )

        estimated_counts = (
            current_counts
            if state in (REMEDIATION_APPLIED, REMEDIATION_EXHAUSTED)
            else self._estimate_after_fix(
                annotated_vulns, current_counts, dependency_fixes
            )
        )
        estimated_vulns = self._build_estimated_vulnerabilities(
            annotated_vulns, estimated_counts
        )
        estimated_decision = self.policy_service.evaluate_deployment(
            estimated_vulns,
            remediation_state=REMEDIATION_EXHAUSTED if state != REMEDIATION_AVAILABLE else None,
            dockerfile_findings=[] if state != REMEDIATION_AVAILABLE else dockerfile_findings,
        )

        original_total = sum(original_counts.values())
        remaining_total = sum(current_counts.values())
        if original_total > 0:
            improvement_percentage = round(
                ((original_total - remaining_total) / original_total) * 100, 1
            )
        else:
            improvement_percentage = 0.0

        score_after = current_score

        return {
            "service_name": service_name,
            "dockerfile_path": dockerfile_path,
            "remediation_state": state,
            "status_message": status_message,
            "show_generate_fix": show_generate_fix,
            "current_dockerfile": dockerfile_content,
            "updated_dockerfile": updated_dockerfile,
            "previous_updated_dockerfile": previous_updated,
            "root_cause_analysis": root_causes,
            "recommended_fixes": recommended_fixes,
            "vulnerabilities_found": vuln_summary,
            "fixable_count": classification["fixable_count"],
            "unfixable_count": classification["unfixable_count"],
            "current_critical": current_counts["CRITICAL"],
            "current_high": current_counts["HIGH"],
            "current_medium": current_counts["MEDIUM"],
            "current_low": current_counts["LOW"],
            "estimated_critical": estimated_counts["CRITICAL"],
            "estimated_high": estimated_counts["HIGH"],
            "estimated_medium": estimated_counts["MEDIUM"],
            "estimated_low": estimated_counts["LOW"],
            "current_decision": current_decision,
            "estimated_decision": estimated_decision,
            "dependency_fixes": dependency_fixes,
            "dependency_patches": dependency_patches,
            "pending_dependency_count": len(pending_dependency_fixes),
            "dockerfile_security_findings": dockerfile_findings,
            "status_reason": self.policy_service.get_status_reason(
                vulnerabilities,
                current_decision,
                state,
                pending_dependency_fixes=pending_dependency_fixes,
                dockerfile_findings=dockerfile_findings,
            ),
            "original_score": original_score,
            "score_after_remediation": score_after,
            "improvement_percentage": improvement_percentage,
            "original_critical": original_counts["CRITICAL"],
            "original_high": original_counts["HIGH"],
            "original_medium": original_counts["MEDIUM"],
            "original_low": original_counts["LOW"],
            "remaining_critical": current_counts["CRITICAL"],
            "remaining_high": current_counts["HIGH"],
            "remaining_medium": current_counts["MEDIUM"],
            "remaining_low": current_counts["LOW"],
        }

    def _build_estimated_vulnerabilities(
        self, vulnerabilities: list[dict], estimated_counts: dict
    ) -> list[dict]:
        result = []
        severity_buckets = {k: [] for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}

        for vuln in vulnerabilities:
            sev = vuln.get("severity", "LOW")
            if sev in severity_buckets:
                severity_buckets[sev].append(vuln)

        for sev, limit in estimated_counts.items():
            for vuln in severity_buckets.get(sev, [])[:limit]:
                result.append(vuln)
            if limit > len(severity_buckets.get(sev, [])):
                pass

        if not result and sum(estimated_counts.values()) == 0:
            return []

        unfixable = [v for v in vulnerabilities if not self.policy_service.is_fixable(v)]
        if estimated_counts.get("CRITICAL", 0) == 0 and estimated_counts.get("HIGH", 0) == 0:
            return unfixable[: sum(estimated_counts.values())] or unfixable

        return result or unfixable

    def _determine_state(
        self,
        dockerfile_content: str,
        candidate_updated: str,
        previous_updated: str,
        vulnerabilities: list[dict],
        pending_dependency_fixes: list[dict],
        dependency_fixes: list[dict],
    ) -> tuple[str, str, bool]:
        classification = self.policy_service.classify_vulnerabilities(vulnerabilities)
        has_fixable = classification["fixable_count"] > 0
        has_pending_deps = len(pending_dependency_fixes) > 0

        dockerfile_applied = (
            (bool(previous_updated) and self._dockerfiles_match(dockerfile_content, previous_updated))
            or (bool(candidate_updated) and self._dockerfiles_match(dockerfile_content, candidate_updated))
        )
        has_dockerfile_fixes = bool(candidate_updated) and not dockerfile_applied
        show_dockerfile_fix = has_dockerfile_fixes

        if has_pending_deps:
            dep_files = sorted({f["source_file"] for f in pending_dependency_fixes})
            return (
                REMEDIATION_AVAILABLE,
                f"Dependency fixes required in {', '.join(dep_files)}.",
                show_dockerfile_fix,
            )

        if has_dockerfile_fixes:
            return (
                REMEDIATION_AVAILABLE,
                "Dockerfile security remediations exist and have not been applied.",
                True,
            )

        if dockerfile_applied and dependency_fixes and not has_pending_deps:
            if not has_fixable:
                return (
                    REMEDIATION_EXHAUSTED,
                    "All remediations applied. Remaining vulnerabilities are unfixable.",
                    False,
                )
            return (
                REMEDIATION_APPLIED,
                "Remediation Already Applied",
                False,
            )

        if not has_fixable:
            return (
                REMEDIATION_EXHAUSTED,
                "No further remediation available.",
                False,
            )

        return (
            REMEDIATION_EXHAUSTED,
            "No further remediation available.",
            False,
        )

    def _normalize_dockerfile(self, content: str) -> str:
        if not content:
            return ""
        lines = []
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("# VULNSIGHT"):
                continue
            if not stripped or stripped.startswith("#"):
                continue
            lines.append(re.sub(r"\s+", " ", stripped).lower())
        return "\n".join(lines)

    def _dockerfiles_match(self, dockerfile_a: str, dockerfile_b: str) -> bool:
        if not dockerfile_a or not dockerfile_b:
            return False
        norm_a = self._normalize_dockerfile(dockerfile_a)
        norm_b = self._normalize_dockerfile(dockerfile_b)
        if norm_a == norm_b:
            return True
        return self._contains_remediation_markers(dockerfile_a, dockerfile_b)

    def _contains_remediation_markers(self, current: str, recommended: str) -> bool:
        current_lower = current.lower()
        recommended_lower = recommended.lower()
        recommended_markers = [
            m for m in self.REMEDIATION_MARKERS if m in recommended_lower
        ]
        if not recommended_markers:
            from_current = re.search(
                r"^from\s+(.+)", current, re.MULTILINE | re.IGNORECASE
            )
            from_recommended = re.search(
                r"^from\s+(.+)", recommended, re.MULTILINE | re.IGNORECASE
            )
            if from_current and from_recommended:
                return (
                    from_current.group(1).strip().lower()
                    == from_recommended.group(1).strip().lower()
                )
            return False
        return all(marker in current_lower for marker in recommended_markers)

    def _build_vulnerability_summary(self, vulnerabilities: list[dict]) -> list[dict]:
        summary = []
        seen = set()
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: severity_order.get(v.get("severity", "LOW"), 4),
        )

        for vuln in sorted_vulns:
            key = (vuln.get("cve_id"), vuln.get("package_name"))
            if key in seen:
                continue
            seen.add(key)
            fixable = self.policy_service.is_fixable(vuln)
            summary.append(
                {
                    "cve_id": vuln.get("cve_id", "UNKNOWN"),
                    "severity": vuln.get("severity", "LOW"),
                    "package_name": vuln.get("package_name", "unknown"),
                    "installed_version": vuln.get("installed_version", ""),
                    "fixed_version": vuln.get("fixed_version", ""),
                    "description": (vuln.get("description") or "")[:300],
                    "classification": "FIXABLE" if fixable else "UNFIXABLE",
                    "remediation_source": vuln.get("remediation_source", "Dockerfile"),
                    "remediation_type": vuln.get("remediation_type", "DOCKERFILE"),
                }
            )
            if len(summary) >= 50:
                break

        return summary

    def _analyze_remaining_root_causes(
        self,
        vulnerabilities: list[dict],
        dockerfile_content: str,
        service_name: str,
        dockerfile_path: str,
        state: str,
    ) -> list[str]:
        causes = []
        classification = self.policy_service.classify_vulnerabilities(vulnerabilities)

        if state == REMEDIATION_APPLIED:
            causes.append(
                f"Recommended Dockerfile changes for '{service_name}' have been applied."
            )

        if classification["unfixable_count"] > 0:
            causes.append(
                f"{classification['unfixable_count']} vulnerabilities are UNFIXABLE — "
                f"Trivy reports FixedVersion as null or '-', meaning no vendor patch exists."
            )

        if classification["unfixable_critical"] > 0:
            causes.append(
                f"{classification['unfixable_critical']} critical vulnerabilities remain "
                f"but have no available vendor fix. These cannot be remediated via Dockerfile."
            )

        from_match = re.search(
            r"^FROM\s+(.+)", dockerfile_content, re.MULTILINE | re.IGNORECASE
        )
        if from_match:
            causes.append(
                f"Remaining CVEs are tied to base image '{from_match.group(1).strip()}'. "
                f"Upstream maintainer must release patched versions."
            )

        if state == REMEDIATION_EXHAUSTED:
            causes.append(
                "All available Dockerfile remediations have been applied. "
                "Remaining findings originate from upstream packages."
            )

        if not causes:
            causes.append(
                f"{len(vulnerabilities)} vulnerabilities remain after remediation."
            )

        return causes

    def _generate_post_apply_guidance(
        self, vulnerabilities: list[dict], state: str
    ) -> list[str]:
        classification = self.policy_service.classify_vulnerabilities(vulnerabilities)
        fixes = []

        if state == REMEDIATION_EXHAUSTED:
            fixes.append("No further Dockerfile remediation available.")
            fixes.append(
                "Dockerfile already optimized. Remaining findings require newer "
                "upstream base images or package maintainer fixes."
            )
        else:
            fixes.append("Remediation has been applied. Monitor upstream releases.")

        if classification["unfixable_count"] > 0:
            fixes.append(
                f"{classification['unfixable_count']} vulnerabilities have no vendor fix. "
                f"Deployment may proceed with risk acceptance."
            )

        fixes.append("Re-scan when upstream vendors publish security updates.")
        return fixes

    def _analyze_root_causes(
        self,
        vulnerabilities: list[dict],
        dockerfile_content: str,
        service_name: str,
        dockerfile_path: str,
        dependency_fixes: list[dict],
        dockerfile_findings: list[dict],
    ) -> list[str]:
        causes = []
        classification = self.policy_service.classify_vulnerabilities(vulnerabilities)
        pending_deps = self.dependency_service.get_pending_dependency_fixes(dependency_fixes)

        if dockerfile_findings:
            high_critical = [
                f for f in dockerfile_findings
                if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")
            ]
            causes.append(
                f"{len(dockerfile_findings)} Dockerfile security misconfigurations detected "
                f"({len(high_critical)} HIGH/CRITICAL/MEDIUM). "
                f"Includes root user, missing hardening, or insecure instructions."
            )

        if pending_deps:
            dep_files = sorted({f["source_file"] for f in pending_deps})
            total_cves = sum(f.get("impact", 1) for f in pending_deps)
            causes.append(
                f"{total_cves} application dependency vulnerabilities across "
                f"{len(pending_deps)} package(s) must be fixed in "
                f"{', '.join(dep_files)}, not in the Dockerfile."
            )

        if classification["fixable_critical"] > 0:
            causes.append(
                f"{classification['fixable_critical']} FIXABLE critical vulnerabilities "
                f"have vendor patches available and must be addressed."
            )

        if classification["fixable_high"] > 0:
            causes.append(
                f"{classification['fixable_high']} FIXABLE high vulnerabilities "
                f"have vendor patches available."
            )

        from_match = re.search(
            r"^FROM\s+(.+)", dockerfile_content, re.MULTILINE | re.IGNORECASE
        )
        if from_match and ":latest" in from_match.group(1).lower():
            causes.append(
                f"Unpinned base image '{from_match.group(1).strip()}' may contain fixable CVEs."
            )

        if not causes:
            causes.append(
                f"Service '{service_name}' requires Dockerfile hardening at '{dockerfile_path}'."
            )

        return causes

    def _generate_recommended_fixes(
        self,
        vulnerabilities: list[dict],
        dockerfile_content: str,
        root_causes: list[str],
        dependency_fixes: list[dict],
        dockerfile_findings: list[dict],
    ) -> list[str]:
        fixes = []
        pending_deps = self.dependency_service.get_pending_dependency_fixes(dependency_fixes)

        if dockerfile_findings:
            for finding in dockerfile_findings[:6]:
                fixes.append(
                    f"[{finding.get('severity', 'LOW')}] {finding.get('rule', 'Finding')}: "
                    f"{finding.get('recommendation', 'Apply Dockerfile hardening.')}"
                )
            fixes.append("Apply the updated security-hardened Dockerfile, then re-scan.")

        if pending_deps:
            for dep_fix in pending_deps[:5]:
                cve_list = ", ".join(dep_fix.get("cve_ids", [])[:3])
                suffix = "..." if len(dep_fix.get("cve_ids", [])) > 3 else ""
                fixes.append(
                    f"Update {dep_fix['package_name']} in {dep_fix['source_file']}: "
                    f"{dep_fix['current']} → {dep_fix['recommended']} "
                    f"({dep_fix.get('impact', 1)} CVEs: {cve_list}{suffix})."
                )
            fixes.append("Apply the dependency patch, rebuild the image, and re-scan.")

        dockerfile_vulns = [
            v for v in vulnerabilities
            if self.policy_service.is_fixable(v)
            and v.get("remediation_type") in ("OS_PACKAGE", "BASE_IMAGE", "DOCKERFILE")
        ]
        if dockerfile_vulns:
            fixes.append(
                f"Apply Dockerfile changes for {len(dockerfile_vulns)} "
                f"base image or OS package vulnerabilities."
            )
            fixes.append("Pin base image to a specific patched version tag.")

        if not pending_deps and not dockerfile_vulns and not dockerfile_findings:
            fixes.append("Re-scan after applying available fixes.")

        return fixes

    def _upgrade_base_image(self, from_line: str) -> str:
        for pattern, replacement in self.BASE_IMAGE_UPGRADES:
            if re.search(pattern, from_line, re.IGNORECASE):
                return re.sub(pattern, replacement, from_line, flags=re.IGNORECASE)
        if ":latest" in from_line.lower():
            return re.sub(r":latest\b", ":stable", from_line, flags=re.IGNORECASE)
        return from_line

    def _is_alpine_base(self, dockerfile_content: str) -> bool:
        from_match = re.search(
            r"^FROM\s+(.+)", dockerfile_content, re.MULTILINE | re.IGNORECASE
        )
        return bool(from_match and "alpine" in from_match.group(1).lower())

    def _has_dockerfile_relevant_fixes(
        self,
        dockerfile_content: str,
        vulnerabilities: list[dict],
        dockerfile_findings: list[dict],
    ) -> bool:
        if self.dockerfile_security_service.has_pending_findings(dockerfile_findings):
            return True
        return any(
            self.policy_service.is_fixable(v)
            and v.get("remediation_type") in ("OS_PACKAGE", "BASE_IMAGE", "DOCKERFILE")
            for v in vulnerabilities
        )

    def _generate_updated_dockerfile(
        self,
        dockerfile_content: str,
        vulnerabilities: list[dict],
        dockerfile_findings: list[dict],
    ) -> str:
        if not self._has_dockerfile_relevant_fixes(
            dockerfile_content, vulnerabilities, dockerfile_findings
        ):
            return ""

        if self.dockerfile_security_service.has_pending_findings(dockerfile_findings):
            hardened = self.dockerfile_security_service.apply_remediations(
                dockerfile_content, dockerfile_findings
            )
            if hardened and not self._dockerfiles_match(dockerfile_content, hardened):
                return hardened

        lines = dockerfile_content.splitlines()
        result_lines = []
        from_processed = False
        is_alpine = self._is_alpine_base(dockerfile_content)

        header = [
            "# VULNSIGHT-V2 Remediation Dockerfile",
            "# Complete replacement — copy to your repository and re-scan",
            "",
        ]

        for line in lines:
            stripped = line.strip()
            if re.match(r"^FROM\s+", stripped, re.IGNORECASE) and not from_processed:
                result_lines.append(self._upgrade_base_image(stripped))
                result_lines.append("")
                if is_alpine:
                    result_lines.append("RUN apk update && apk upgrade --no-cache")
                else:
                    result_lines.append("RUN apt-get update && \\")
                    result_lines.append("    apt-get upgrade -y && \\")
                    result_lines.append("    rm -rf /var/lib/apt/lists/*")
                result_lines.append("")
                from_processed = True
                continue

            if re.search(r"pip\s+install", stripped, re.IGNORECASE):
                indent = line[: len(line) - len(line.lstrip())]
                if "requirements" in stripped.lower():
                    result_lines.append(f"{indent}RUN pip install --upgrade pip && \\")
                    result_lines.append(
                        f"{indent}    pip install --no-cache-dir -r requirements.txt"
                    )
                else:
                    result_lines.append(line)
                continue

            result_lines.append(line)

        if "USER " not in dockerfile_content.upper():
            result_lines.append("USER appuser")

        return "\n".join(header + result_lines) + "\n"

    def _estimate_after_fix(
        self,
        vulnerabilities: list[dict],
        current_counts: dict,
        dependency_fixes: list[dict],
    ) -> dict:
        remaining = []
        for v in vulnerabilities:
            if not self.policy_service.is_fixable(v):
                remaining.append(v)
            elif v.get("remediation_type") == "DEPENDENCY":
                pass
            elif v.get("remediation_type") in ("OS_PACKAGE", "BASE_IMAGE", "DOCKERFILE"):
                pass
            else:
                remaining.append(v)

        return self.trivy_service.count_by_severity(remaining)

    def find_previous_remediation(self, db, repo_url: str, dockerfile_path: str):
        from models import Remediation, Service, Repository

        return (
            db.query(Remediation)
            .join(Service)
            .join(Repository)
            .filter(Repository.repo_url == repo_url)
            .filter(Service.dockerfile_path == dockerfile_path)
            .filter(Remediation.updated_dockerfile != "")
            .order_by(Remediation.created_at.desc())
            .first()
        )

    def find_baseline(self, db, repo_url: str, dockerfile_path: str):
        from models import Remediation, Service, Repository

        first = (
            db.query(Remediation)
            .join(Service)
            .join(Repository)
            .filter(Repository.repo_url == repo_url)
            .filter(Service.dockerfile_path == dockerfile_path)
            .order_by(Remediation.created_at.asc())
            .first()
        )
        if not first:
            return None

        return {
            "original_score": self.scoring_service.calculate_score(
                {
                    "CRITICAL": first.current_critical,
                    "HIGH": first.current_high,
                    "MEDIUM": first.current_medium,
                    "LOW": first.current_low,
                }
            ),
            "original_critical": first.current_critical,
            "original_high": first.current_high,
            "original_medium": first.current_medium,
            "original_low": first.current_low,
        }

    def needs_remediation_record(
        self,
        vulnerabilities: list[dict],
        decision: str,
        dockerfile_findings: list[dict] | None = None,
    ) -> bool:
        if decision == "FAIL":
            return True
        if dockerfile_findings:
            return True
        classification = self.policy_service.classify_vulnerabilities(vulnerabilities)
        return classification["fixable_count"] > 0 or classification["unfixable_critical"] > 0
