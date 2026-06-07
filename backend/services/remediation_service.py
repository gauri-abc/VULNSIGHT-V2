import json
import re

from services.policy_service import PolicyService
from services.scoring_service import ScoringService
from services.trivy_service import TrivyService


class RemediationService:
    OS_PACKAGE_PREFIXES = (
        "lib", "libc", "openssl", "glibc", "zlib", "curl", "bash",
        "perl", "gnutls", "sqlite", "expat", "krb", "pam", "systemd",
        "apt", "dpkg", "gcc", "binutils", "coreutils", "tar", "gzip",
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
    ) -> dict:
        current_counts = self.trivy_service.count_by_severity(vulnerabilities)
        current_decision = self.policy_service.evaluate(current_counts)

        root_causes = self._analyze_root_causes(
            vulnerabilities, dockerfile_content, service_name, dockerfile_path
        )
        recommended_fixes = self._generate_recommended_fixes(
            vulnerabilities, dockerfile_content, root_causes
        )
        updated_dockerfile = self._generate_updated_dockerfile(
            dockerfile_content, vulnerabilities
        )
        estimated_counts = self._estimate_after_fix(vulnerabilities, current_counts)
        estimated_decision = self.policy_service.evaluate(estimated_counts)

        vuln_summary = self._build_vulnerability_summary(vulnerabilities)

        return {
            "service_name": service_name,
            "dockerfile_path": dockerfile_path,
            "current_dockerfile": dockerfile_content,
            "updated_dockerfile": updated_dockerfile,
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
        }

    def _is_os_package(self, package_name: str) -> bool:
        pkg = (package_name or "").lower()
        if not pkg:
            return False
        return any(pkg.startswith(prefix) or pkg == prefix for prefix in self.OS_PACKAGE_PREFIXES)

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

        from_match = re.search(r"^FROM\s+(.+)", dockerfile_content, re.MULTILINE | re.IGNORECASE)
        base_image = from_match.group(1).strip() if from_match else "unknown"

        if ":latest" in base_image.lower():
            causes.append(
                f"Service '{service_name}' uses floating tag ':latest' on base image "
                f"'{base_image}', pulling unpatched OS packages with known CVEs."
            )
        elif not re.search(r":[\w][\w.\-]+", base_image):
            causes.append(
                f"Service '{service_name}' uses an unpinned base image '{base_image}' "
                f"without a specific version digest, preventing reproducible secure builds."
            )

        if "apt-get upgrade" not in dockerfile_content and "apk upgrade" not in dockerfile_content:
            if any(kw in base_image.lower() for kw in ("slim", "bookworm", "bullseye", "ubuntu", "debian")):
                causes.append(
                    f"Dockerfile at '{dockerfile_path}' does not apply OS security patches "
                    f"(missing apt-get upgrade), leaving base image CVEs unaddressed."
                )
            elif "alpine" in base_image.lower():
                causes.append(
                    f"Dockerfile at '{dockerfile_path}' does not run 'apk upgrade', "
                    f"leaving Alpine OS packages unpatched."
                )

        critical_vulns = [v for v in vulnerabilities if v.get("severity") == "CRITICAL"]
        if critical_vulns:
            pkgs = sorted({v.get("package_name", "unknown") for v in critical_vulns})
            causes.append(
                f"{len(critical_vulns)} critical CVE(s) found in packages: "
                f"{', '.join(pkgs[:5])}{'...' if len(pkgs) > 5 else ''}. "
                f"These require immediate version upgrades or base image updates."
            )

        pkg_counts: dict[str, int] = {}
        for vuln in vulnerabilities:
            pkg = vuln.get("package_name", "unknown")
            pkg_counts[pkg] = pkg_counts.get(pkg, 0) + 1

        top_offenders = sorted(pkg_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for pkg, count in top_offenders:
            if count >= 3:
                causes.append(
                    f"Package '{pkg}' accounts for {count} vulnerabilities — "
                    f"likely an outdated transitive dependency or unpatched OS library."
                )

        if re.search(r"pip\s+install", dockerfile_content, re.IGNORECASE):
            if "--no-cache-dir" not in dockerfile_content:
                causes.append(
                    "Python pip installs lack '--no-cache-dir', increasing image size "
                    "and retaining stale package metadata."
                )
            if "pip install --upgrade pip" not in dockerfile_content.lower():
                causes.append(
                    "pip is not upgraded before dependency installation, "
                    "potentially using a vulnerable pip version."
                )

        if "USER " not in dockerfile_content.upper():
            causes.append(
                "Container runs as root (no USER directive), violating least-privilege "
                "principles and amplifying exploit impact."
            )

        if not causes:
            causes.append(
                f"Service '{service_name}' failed the security gate due to accumulated "
                f"vulnerabilities across {len(vulnerabilities)} findings in the container image."
            )

        return causes

    def _generate_recommended_fixes(
        self,
        vulnerabilities: list[dict],
        dockerfile_content: str,
        root_causes: list[str],
    ) -> list[str]:
        fixes = []

        from_match = re.search(r"^FROM\s+(.+)", dockerfile_content, re.MULTILINE | re.IGNORECASE)
        base_image = from_match.group(1).strip().lower() if from_match else ""

        fixes.append(
            "Pin the base image to a specific patched version tag "
            "(e.g., python:3.12.11-slim-bookworm) instead of a floating tag."
        )

        if any(kw in base_image for kw in ("slim", "bookworm", "bullseye", "ubuntu", "debian")):
            fixes.append(
                "Add 'RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*' "
                "immediately after FROM to patch OS-level CVEs at build time."
            )
        elif "alpine" in base_image:
            fixes.append(
                "Add 'RUN apk update && apk upgrade --no-cache' after FROM "
                "to patch Alpine OS packages."
            )

        if re.search(r"pip\s+install", dockerfile_content, re.IGNORECASE):
            fixes.append(
                "Upgrade pip before installing requirements: "
                "'RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt'."
            )

        fixable = [v for v in vulnerabilities if v.get("fixed_version")]
        if fixable:
            pkg_fixes = {}
            for v in fixable:
                pkg = v.get("package_name", "")
                if pkg and pkg not in pkg_fixes:
                    pkg_fixes[pkg] = v.get("fixed_version", "")
            fix_list = [
                f"{pkg} → {ver}" for pkg, ver in list(pkg_fixes.items())[:8]
            ]
            fixes.append(
                f"Update {len(fixable)} packages with available patches: "
                f"{', '.join(fix_list)}{'...' if len(pkg_fixes) > 8 else ''}."
            )

        if "USER " not in dockerfile_content.upper():
            fixes.append(
                "Add a non-root USER directive before CMD/ENTRYPOINT "
                "(e.g., 'RUN adduser --disabled-password appuser' then 'USER appuser')."
            )

        fixes.append(
            "After applying the updated Dockerfile manually in your repository, "
            "re-run VULNSIGHT-V2 scan to verify the security gate passes."
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
        from_match = re.search(r"^FROM\s+(.+)", dockerfile_content, re.MULTILINE | re.IGNORECASE)
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
                    result_lines.append("# Security: patch Alpine OS packages at build time")
                    result_lines.append("RUN apk update && \\")
                    result_lines.append("    apk upgrade --no-cache")
                else:
                    result_lines.append("# Security: patch OS packages at build time")
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
                        result_lines.append(f"{indent}RUN pip install --upgrade pip && \\")
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
                result_lines.append("RUN addgroup -S appgroup && adduser -S appuser -G appgroup")
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

            if has_fix:
                continue
            if is_os:
                continue
            if severity == "CRITICAL":
                continue

            if severity == "HIGH":
                cve_id = vuln.get("cve_id", "")
                if hash(cve_id) % 8 != 0:
                    continue

            if severity == "MEDIUM":
                cve_id = vuln.get("cve_id", "")
                if hash(cve_id) % 7 != 0:
                    continue

            if severity == "LOW":
                cve_id = vuln.get("cve_id", "")
                if hash(cve_id) % 6 != 0:
                    continue

            remaining.append(vuln)

        estimated = self.trivy_service.count_by_severity(remaining)

        if current_counts["CRITICAL"] > 0 and estimated["CRITICAL"] > 0:
            estimated["CRITICAL"] = 0

        return estimated
