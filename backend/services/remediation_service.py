import re

from services.policy_service import PolicyService
from services.scoring_service import ScoringService
from services.trivy_service import TrivyService

REMEDIATION_AVAILABLE = "REMEDIATION_AVAILABLE"
REMEDIATION_APPLIED = "REMEDIATION_APPLIED"
REMEDIATION_EXHAUSTED = "REMEDIATION_EXHAUSTED"


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

    def generate_remediation(
        self,
        dockerfile_content: str,
        vulnerabilities: list[dict],
        service_name: str,
        dockerfile_path: str,
        previous_remediation: dict | None = None,
        baseline: dict | None = None,
    ) -> dict:
        current_counts = self.trivy_service.count_by_severity(vulnerabilities)
        current_score = self.scoring_service.calculate_score(current_counts)
        current_decision = self.policy_service.evaluate(current_counts)
        vuln_summary = self._build_vulnerability_summary(vulnerabilities)

        baseline = baseline or {}
        original_score = baseline.get("original_score", current_score)
        original_counts = {
            "CRITICAL": baseline.get("original_critical", current_counts["CRITICAL"]),
            "HIGH": baseline.get("original_high", current_counts["HIGH"]),
            "MEDIUM": baseline.get("original_medium", current_counts["MEDIUM"]),
            "LOW": baseline.get("original_low", current_counts["LOW"]),
        }

        candidate_updated = self._generate_updated_dockerfile(
            dockerfile_content, vulnerabilities
        )
        previous_updated = (
            (previous_remediation or {}).get("updated_dockerfile") or ""
        )

        state, status_message, show_generate_fix = self._determine_state(
            dockerfile_content=dockerfile_content,
            candidate_updated=candidate_updated,
            previous_updated=previous_updated,
            vulnerabilities=vulnerabilities,
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
                vulnerabilities, dockerfile_content, service_name, dockerfile_path
            )
            recommended_fixes = self._generate_recommended_fixes(
                vulnerabilities, dockerfile_content, root_causes
            )

        estimated_counts = (
            current_counts
            if state in (REMEDIATION_APPLIED, REMEDIATION_EXHAUSTED)
            else self._estimate_after_fix(vulnerabilities, current_counts)
        )
        estimated_decision = self.policy_service.evaluate(estimated_counts)

        original_total = sum(original_counts.values())
        remaining_total = sum(current_counts.values())
        if original_total > 0:
            improvement_percentage = round(
                ((original_total - remaining_total) / original_total) * 100, 1
            )
        else:
            improvement_percentage = 0.0

        score_after = current_score if state == REMEDIATION_APPLIED else (
            self.scoring_service.calculate_score(estimated_counts)
            if state == REMEDIATION_AVAILABLE
            else current_score
        )

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

    def _determine_state(
        self,
        dockerfile_content: str,
        candidate_updated: str,
        previous_updated: str,
        vulnerabilities: list[dict],
    ) -> tuple[str, str, bool]:
        matches_previous = (
            bool(previous_updated)
            and self._dockerfiles_match(dockerfile_content, previous_updated)
        )
        matches_candidate = self._dockerfiles_match(
            dockerfile_content, candidate_updated
        )
        upstream_only = self._remaining_are_upstream_only(vulnerabilities)

        if matches_previous:
            if upstream_only:
                return (
                    REMEDIATION_EXHAUSTED,
                    "Dockerfile already optimized. Remaining findings require newer "
                    "upstream base images or package maintainer fixes.",
                    False,
                )
            return (
                REMEDIATION_APPLIED,
                "Remediation Already Applied",
                False,
            )

        if matches_candidate:
            if upstream_only:
                return (
                    REMEDIATION_EXHAUSTED,
                    "Dockerfile already optimized. Remaining findings require newer "
                    "upstream base images or package maintainer fixes.",
                    False,
                )
            return (
                REMEDIATION_APPLIED,
                "Remediation Already Applied",
                False,
            )

        candidate_differs = not self._dockerfiles_match(
            dockerfile_content, candidate_updated
        )
        if candidate_differs:
            return (
                REMEDIATION_AVAILABLE,
                "A new Dockerfile remediation is available for this service.",
                True,
            )

        if upstream_only:
            return (
                REMEDIATION_EXHAUSTED,
                "No additional Dockerfile remediation available.",
                False,
            )

        return (
            REMEDIATION_EXHAUSTED,
            "Dockerfile already optimized. Remaining findings require newer "
            "upstream base images or package maintainer fixes.",
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

        if self._contains_remediation_markers(dockerfile_a, dockerfile_b):
            return True

        return False

    def _contains_remediation_markers(
        self, current: str, recommended: str
    ) -> bool:
        current_lower = current.lower()
        recommended_lower = recommended.lower()

        recommended_markers = []
        for marker in self.REMEDIATION_MARKERS:
            if marker in recommended_lower:
                recommended_markers.append(marker)

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

    def _is_os_package(self, package_name: str) -> bool:
        pkg = (package_name or "").lower()
        if not pkg:
            return False
        return any(
            pkg.startswith(prefix) or pkg == prefix
            for prefix in self.OS_PACKAGE_PREFIXES
        )

    def _remaining_are_upstream_only(self, vulnerabilities: list[dict]) -> bool:
        if not vulnerabilities:
            return True

        for vuln in vulnerabilities:
            pkg = vuln.get("package_name", "")
            has_fix = bool(vuln.get("fixed_version"))
            is_os = self._is_os_package(pkg)

            if is_os:
                continue
            if has_fix:
                return False
            if vuln.get("severity") in ("CRITICAL", "HIGH"):
                return False

        return True

    def _analyze_remaining_root_causes(
        self,
        vulnerabilities: list[dict],
        dockerfile_content: str,
        service_name: str,
        dockerfile_path: str,
        state: str,
    ) -> list[str]:
        causes = []

        os_vulns = [v for v in vulnerabilities if self._is_os_package(v.get("package_name", ""))]
        app_vulns = [v for v in vulnerabilities if not self._is_os_package(v.get("package_name", ""))]
        no_fix_vulns = [v for v in vulnerabilities if not v.get("fixed_version")]

        if state == REMEDIATION_APPLIED:
            causes.append(
                f"The Dockerfile for '{service_name}' already contains the previously "
                f"recommended security hardening changes."
            )

        if os_vulns:
            os_pkgs = sorted({v.get("package_name") for v in os_vulns})[:6]
            causes.append(
                f"{len(os_vulns)} remaining vulnerabilities originate from the base image "
                f"or upstream OS packages ({', '.join(os_pkgs)}). These are not fully "
                f"addressable through Dockerfile changes alone."
            )

        if no_fix_vulns:
            causes.append(
                f"{len(no_fix_vulns)} vulnerabilities have no fixed version published yet — "
                f"package maintainers or upstream vendors must release patches."
            )

        from_match = re.search(
            r"^FROM\s+(.+)", dockerfile_content, re.MULTILINE | re.IGNORECASE
        )
        if from_match:
            base_image = from_match.group(1).strip()
            causes.append(
                f"Remaining CVEs are tied to base image '{base_image}'. A newer upstream "
                f"image release is required to fully resolve them."
            )

        if app_vulns and not os_vulns:
            pkgs = sorted({v.get("package_name") for v in app_vulns})[:5]
            causes.append(
                f"Application-level packages ({', '.join(pkgs)}) still carry vulnerabilities "
                f"that may require dependency updates beyond Dockerfile hardening."
            )

        if state == REMEDIATION_EXHAUSTED:
            causes.append(
                "No additional Dockerfile remediation available. The Dockerfile is already "
                "optimized with pinned base images, OS patching, and security best practices."
            )

        if not causes:
            causes.append(
                f"Service '{service_name}' at '{dockerfile_path}' still has "
                f"{len(vulnerabilities)} remaining findings after remediation was applied."
            )

        return causes

    def _generate_post_apply_guidance(
        self, vulnerabilities: list[dict], state: str
    ) -> list[str]:
        fixes = []

        if state == REMEDIATION_APPLIED:
            fixes.append(
                "Remediation has been applied. Monitor upstream base image releases "
                "for updated patched versions."
            )
        else:
            fixes.append(
                "Dockerfile already optimized. Remaining findings require newer upstream "
                "base images or package maintainer fixes."
            )

        if self._remaining_are_upstream_only(vulnerabilities):
            fixes.append(
                "No additional Dockerfile remediation available. Wait for upstream "
                "maintainers to publish patched base images or OS package updates."
            )

        upstream_pkgs = sorted(
            {v.get("package_name") for v in vulnerabilities if self._is_os_package(v.get("package_name", ""))}
        )[:5]
        if upstream_pkgs:
            fixes.append(
                f"Track security advisories for upstream packages: {', '.join(upstream_pkgs)}."
            )

        fixes.append(
            "Re-scan periodically to detect when newer base image versions become available."
        )

        return fixes

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
            summary.append(
                {
                    "cve_id": vuln.get("cve_id", "UNKNOWN"),
                    "severity": vuln.get("severity", "LOW"),
                    "package_name": vuln.get("package_name", "unknown"),
                    "installed_version": vuln.get("installed_version", ""),
                    "fixed_version": vuln.get("fixed_version", ""),
                    "description": (vuln.get("description") or "")[:300],
                }
            )
            if len(summary) >= 50:
                break

        return summary

    def _analyze_root_causes(
        self,
        vulnerabilities: list[dict],
        dockerfile_content: str,
        service_name: str,
        dockerfile_path: str,
    ) -> list[str]:
        causes = []

        from_match = re.search(
            r"^FROM\s+(.+)", dockerfile_content, re.MULTILINE | re.IGNORECASE
        )
        base_image = from_match.group(1).strip() if from_match else "unknown"

        if ":latest" in base_image.lower():
            causes.append(
                f"Service '{service_name}' uses floating tag ':latest' on base image "
                f"'{base_image}', pulling unpatched OS packages with known CVEs."
            )
        elif not re.search(r":[\w][\w.\-]+", base_image):
            causes.append(
                f"Service '{service_name}' uses an unpinned base image '{base_image}' "
                f"without a specific version digest."
            )

        if (
            "apt-get upgrade" not in dockerfile_content
            and "apk upgrade" not in dockerfile_content
        ):
            if any(
                kw in base_image.lower()
                for kw in ("slim", "bookworm", "bullseye", "ubuntu", "debian")
            ):
                causes.append(
                    f"Dockerfile at '{dockerfile_path}' does not apply OS security patches."
                )

        critical_vulns = [
            v for v in vulnerabilities if v.get("severity") == "CRITICAL"
        ]
        if critical_vulns:
            pkgs = sorted({v.get("package_name", "unknown") for v in critical_vulns})
            causes.append(
                f"{len(critical_vulns)} critical CVE(s) in packages: "
                f"{', '.join(pkgs[:5])}."
            )

        if not causes:
            causes.append(
                f"Service '{service_name}' failed due to "
                f"{len(vulnerabilities)} vulnerability findings."
            )

        return causes

    def _generate_recommended_fixes(
        self,
        vulnerabilities: list[dict],
        dockerfile_content: str,
        root_causes: list[str],
    ) -> list[str]:
        fixes = []

        from_match = re.search(
            r"^FROM\s+(.+)", dockerfile_content, re.MULTILINE | re.IGNORECASE
        )
        base_image = from_match.group(1).strip().lower() if from_match else ""

        fixes.append(
            "Pin the base image to a specific patched version tag."
        )

        if any(
            kw in base_image
            for kw in ("slim", "bookworm", "bullseye", "ubuntu", "debian")
        ):
            fixes.append(
                "Add apt-get update && apt-get upgrade -y to patch OS-level CVEs."
            )
        elif "alpine" in base_image:
            fixes.append("Add apk update && apk upgrade to patch Alpine OS packages.")

        if re.search(r"pip\s+install", dockerfile_content, re.IGNORECASE):
            fixes.append(
                "Upgrade pip and use --no-cache-dir for dependency installation."
            )

        fixable = [v for v in vulnerabilities if v.get("fixed_version")]
        if fixable:
            fixes.append(
                f"Update {len(fixable)} packages with available security patches."
            )

        fixes.append(
            "Apply the updated Dockerfile manually, then re-scan to verify improvements."
        )

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
        if from_match:
            return "alpine" in from_match.group(1).lower()
        return False

    def _generate_updated_dockerfile(
        self, dockerfile_content: str, vulnerabilities: list[dict]
    ) -> str:
        lines = dockerfile_content.splitlines()
        result_lines = []
        from_processed = False
        is_alpine = self._is_alpine_base(dockerfile_content)

        header = [
            "# VULNSIGHT-V2 Remediation Dockerfile",
            "# Complete replacement — copy to your repository and re-scan",
            "# Do NOT auto-apply: developer must manually update GitHub",
            "",
        ]

        for line in lines:
            stripped = line.strip()

            if re.match(r"^FROM\s+", stripped, re.IGNORECASE) and not from_processed:
                upgraded_from = self._upgrade_base_image(stripped)
                result_lines.append(upgraded_from)
                result_lines.append("")

                if is_alpine:
                    result_lines.append(
                        "# Security: patch Alpine OS packages at build time"
                    )
                    result_lines.append("RUN apk update && \\")
                    result_lines.append("    apk upgrade --no-cache")
                else:
                    result_lines.append(
                        "# Security: patch OS packages at build time"
                    )
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
                    upgraded = re.sub(
                        r"pip\s+install\b",
                        "pip install --no-cache-dir",
                        stripped,
                        flags=re.IGNORECASE,
                    )
                    if "upgrade pip" not in upgraded.lower():
                        result_lines.append(
                            f"{indent}RUN pip install --upgrade pip && \\"
                        )
                        pkg_part = upgraded.replace("RUN ", "").strip()
                        result_lines.append(f"{indent}    {pkg_part}")
                    else:
                        result_lines.append(line)
                continue

            if re.search(r"npm\s+install", stripped, re.IGNORECASE):
                upgraded = re.sub(
                    r"npm\s+install\b",
                    "npm ci --only=production",
                    stripped,
                    flags=re.IGNORECASE,
                )
                indent = line[: len(line) - len(line.lstrip())]
                result_lines.append(f"{indent}{upgraded}")
                continue

            result_lines.append(line)

        if "USER " not in dockerfile_content.upper():
            result_lines.append("")
            result_lines.append("# Security: run as non-root user")
            if is_alpine:
                result_lines.append(
                    "RUN addgroup -S appgroup && adduser -S appuser -G appgroup"
                )
            else:
                result_lines.append(
                    "RUN groupadd -r appgroup && useradd -r -g appgroup appuser"
                )
            result_lines.append("USER appuser")

        return "\n".join(header + result_lines) + "\n"

    def _estimate_after_fix(
        self, vulnerabilities: list[dict], current_counts: dict
    ) -> dict:
        remaining = []

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "LOW")
            has_fix = bool(vuln.get("fixed_version"))
            is_os = self._is_os_package(vuln.get("package_name", ""))

            if has_fix or is_os or severity == "CRITICAL":
                continue

            if severity == "HIGH" and hash(vuln.get("cve_id", "")) % 8 != 0:
                continue
            if severity == "MEDIUM" and hash(vuln.get("cve_id", "")) % 7 != 0:
                continue
            if severity == "LOW" and hash(vuln.get("cve_id", "")) % 6 != 0:
                continue

            remaining.append(vuln)

        estimated = self.trivy_service.count_by_severity(remaining)
        if current_counts["CRITICAL"] > 0:
            estimated["CRITICAL"] = 0

        return estimated

    def find_previous_remediation(
        self, db, repo_url: str, dockerfile_path: str, exclude_service_id: int | None = None
    ):
        from models import Remediation, Service, Repository

        query = (
            db.query(Remediation)
            .join(Service)
            .join(Repository)
            .filter(Repository.repo_url == repo_url)
            .filter(Service.dockerfile_path == dockerfile_path)
            .filter(Remediation.updated_dockerfile != "")
        )
        if exclude_service_id:
            query = query.filter(Service.id != exclude_service_id)

        return query.order_by(Remediation.created_at.desc()).first()

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

        original_total = (
            first.current_critical
            + first.current_high
            + first.current_medium
            + first.current_low
        )
        original_score = self.scoring_service.calculate_score(
            {
                "CRITICAL": first.current_critical,
                "HIGH": first.current_high,
                "MEDIUM": first.current_medium,
                "LOW": first.current_low,
            }
        )

        return {
            "original_score": original_score,
            "original_critical": first.current_critical,
            "original_high": first.current_high,
            "original_medium": first.current_medium,
            "original_low": first.current_low,
            "original_total": original_total,
        }
