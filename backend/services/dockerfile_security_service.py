import re

from services.trivy_service import TrivyService


class DockerfileSecurityService:
    UNNECESSARY_PACKAGES = (
        "telnet", "ftp", "rsh", "rlogin", "tcpdump", "nmap", "netcat",
        "nc", "nmap", "wireshark", "tftp",
    )

    INTERACTIVE_SHELLS = ("bash", "sh", "/bin/bash", "/bin/sh", "zsh", "/bin/zsh")

    CUSTOM_CHECKS = [
        {
            "key": "VS-ROOT-USER",
            "rule": "Running as Root",
            "severity": "HIGH",
            "description": "Container runs as the root user, granting full host-level privileges if escaped.",
            "recommendation": "Create a dedicated non-root user and set USER before CMD or ENTRYPOINT.",
            "check": "_check_running_as_root",
        },
        {
            "key": "VS-MISSING-NONROOT-USER",
            "rule": "Missing Non-Root USER",
            "severity": "HIGH",
            "description": "Dockerfile does not switch to a non-root user before container startup.",
            "recommendation": "Add RUN useradd/groupadd and USER appuser before CMD or ENTRYPOINT.",
            "check": "_check_missing_nonroot_user",
        },
        {
            "key": "VS-CHMOD-777",
            "rule": "World-Writable Permissions (chmod 777)",
            "severity": "HIGH",
            "description": "Dockerfile sets world-writable permissions (chmod 777), allowing any user to modify files.",
            "recommendation": "Use least-privilege permissions (e.g. chmod 755) and chown to the application user.",
            "check": "_check_chmod_777",
        },
        {
            "key": "VS-WORLD-WRITABLE",
            "rule": "World-Writable Files or Directories",
            "severity": "HIGH",
            "description": "Dockerfile configures world-writable paths via chmod or permissive install modes.",
            "recommendation": "Restrict file permissions and ownership to the application user only.",
            "check": "_check_world_writable",
        },
        {
            "key": "VS-UNNECESSARY-PACKAGES",
            "rule": "Unnecessary Packages Installed",
            "severity": "MEDIUM",
            "description": "Dockerfile installs packages commonly abused for lateral movement or reconnaissance.",
            "recommendation": "Remove telnet, ftp, and other non-essential packages from the image.",
            "check": "_check_unnecessary_packages",
        },
        {
            "key": "VS-MISSING-HEALTHCHECK",
            "rule": "Missing HEALTHCHECK",
            "severity": "MEDIUM",
            "description": "Dockerfile does not define a HEALTHCHECK instruction.",
            "recommendation": "Add HEALTHCHECK so orchestrators can detect and replace unhealthy containers.",
            "check": "_check_missing_healthcheck",
        },
        {
            "key": "VS-MISSING-LABEL",
            "rule": "Missing LABEL Metadata",
            "severity": "LOW",
            "description": "Dockerfile does not include LABEL metadata for ownership and versioning.",
            "recommendation": "Add LABEL instructions for maintainer, version, and description.",
            "check": "_check_missing_label",
        },
        {
            "key": "VS-MUTABLE-BASE-TAG",
            "rule": "Mutable Base Image Tag",
            "severity": "MEDIUM",
            "description": "Base image uses a mutable tag without an immutable digest pin.",
            "recommendation": "Pin the base image using a digest (@sha256:...) or fully versioned tag.",
            "check": "_check_mutable_base_tag",
        },
        {
            "key": "VS-UNPINNED-DIGEST",
            "rule": "Unpinned Image Digest",
            "severity": "MEDIUM",
            "description": "Base image is not pinned to an immutable digest.",
            "recommendation": "Use FROM image@sha256:<digest> to prevent silent base image changes.",
            "check": "_check_unpinned_digest",
        },
        {
            "key": "VS-LATEST-TAG",
            "rule": "Latest Tag Usage",
            "severity": "HIGH",
            "description": "Base image uses the :latest tag which is mutable and unpinned.",
            "recommendation": "Pin the base image to a specific version tag.",
            "check": "_check_latest_tag",
        },
        {
            "key": "VS-INTERACTIVE-SHELL",
            "rule": "Interactive Shell Entrypoint",
            "severity": "HIGH",
            "description": "Container starts an interactive shell instead of the application process.",
            "recommendation": "Use CMD or ENTRYPOINT to start the application directly (e.g. python app.py).",
            "check": "_check_interactive_shell",
        },
        {
            "key": "VS-PRIVILEGED-CONTAINER",
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
        trivy_findings = []
        if dockerfile_path:
            trivy_findings = self.trivy_service.scan_dockerfile(dockerfile_path)
        custom_findings = self._run_custom_checks(dockerfile_content or "")
        return self._merge_findings(trivy_findings, custom_findings)

    def _merge_findings(self, trivy_findings: list[dict], custom_findings: list[dict]) -> list[dict]:
        merged: dict[str, dict] = {}
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        for finding in trivy_findings + custom_findings:
            key = (finding.get("rule_id") or finding.get("rule") or "").strip()
            if not key:
                key = f"finding-{len(merged)}"

            entry = {
                "severity": finding.get("severity", "LOW"),
                "rule": finding.get("rule", "Dockerfile Misconfiguration"),
                "description": finding.get("description", ""),
                "recommendation": finding.get("recommendation", ""),
                "source": finding.get("source", "trivy"),
                "rule_id": finding.get("rule_id", key),
            }

            if key not in merged:
                merged[key] = entry
                continue

            if severity_rank.get(entry["severity"], 0) > severity_rank.get(merged[key]["severity"], 0):
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

    def _last_user(self, content: str) -> str | None:
        users = re.findall(r"^USER\s+(.+)$", content, re.MULTILINE | re.IGNORECASE)
        return users[-1].strip().lower() if users else None

    def _is_root_user(self, user_value: str | None) -> bool:
        if not user_value:
            return True
        return user_value in ("0", "root", "0:0", "root:root")

    def _check_running_as_root(self, content: str) -> bool:
        return self._is_root_user(self._last_user(content))

    def _check_missing_nonroot_user(self, content: str) -> bool:
        last = self._last_user(content)
        return last is None or self._is_root_user(last)

    def _check_chmod_777(self, content: str) -> bool:
        return bool(re.search(r"chmod\s+777\b", content, re.IGNORECASE))

    def _check_world_writable(self, content: str) -> bool:
        patterns = (
            r"chmod\s+777\b",
            r"chmod\s+-R\s+777\b",
            r"chmod\s+a\+w",
            r"chmod\s+o\+w",
            r"--mode=777",
            r"-m\s+777",
        )
        return any(re.search(p, content, re.IGNORECASE) for p in patterns)

    def _check_unnecessary_packages(self, content: str) -> bool:
        install_blocks = re.findall(
            r"(?:apt-get|apk|yum|dnf)\s+install[^\n\\]*(?:\\[^\n]*)*",
            content,
            re.IGNORECASE,
        )
        combined = " ".join(install_blocks).lower()
        return any(pkg in combined for pkg in self.UNNECESSARY_PACKAGES)

    def _check_missing_healthcheck(self, content: str) -> bool:
        return "HEALTHCHECK" not in content.upper()

    def _check_missing_label(self, content: str) -> bool:
        return "LABEL " not in content.upper()

    def _get_from_lines(self, content: str) -> list[str]:
        return re.findall(r"^FROM\s+(.+)$", content, re.MULTILINE | re.IGNORECASE)

    def _check_latest_tag(self, content: str) -> bool:
        return any(":latest" in line.lower() for line in self._get_from_lines(content))

    def _check_unpinned_digest(self, content: str) -> bool:
        for line in self._get_from_lines(content):
            if "@sha256:" in line.lower():
                continue
            return True
        return False

    def _check_mutable_base_tag(self, content: str) -> bool:
        for line in self._get_from_lines(content):
            if "@sha256:" in line.lower():
                return False
            if ":latest" in line.lower():
                return True
            image_ref = line.strip().split(" ")[0]
            if ":" not in image_ref:
                return True
        return True

    def _check_interactive_shell(self, content: str) -> bool:
        for pattern in (
            r'CMD\s*\[\s*"(?:/)?bin/(?:ba)?sh"\s*\]',
            r"CMD\s*\[\s*'(?:/)?bin/(?:ba)?sh'\s*\]",
            r'CMD\s*\[\s*"(?:ba)?sh"\s*\]',
            r"CMD\s*\[\s*'(?:ba)?sh'\s*\]",
            r"ENTRYPOINT\s*\[\s*\"(?:/)?bin/(?:ba)?sh\"",
            r"CMD\s+(?:ba)?sh\s*$",
        ):
            if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                return True
        return False

    def _check_privileged_risk(self, content: str) -> bool:
        patterns = (
            r"--privileged\b",
            r"--cap-add\s*=\s*ALL",
            r"cap_add:\s*\[?\s*['\"]?ALL",
            r"security_opt:\s*\[?\s*['\"]?seccomp:unconfined",
            r"--security-opt\s+seccomp=unconfined",
        )
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns)

    def apply_remediations(self, dockerfile_content: str, findings: list[dict] | None = None) -> str:
        if not dockerfile_content.strip():
            return ""

        finding_keys = {
            (f.get("rule_id") or f.get("rule", "")).upper()
            for f in (findings or [])
        }
        if not finding_keys and not findings:
            finding_keys = {spec["key"] for spec in self.CUSTOM_CHECKS}

        lines = dockerfile_content.splitlines()
        result: list[str] = [
            "# VULNSIGHT-V2 Remediation Dockerfile",
            "# Security-hardened — copy to your repository and re-scan",
            "",
        ]

        from_processed = False
        user_added = False
        healthcheck_added = False
        label_added = False
        skip_next_lines = 0

        for idx, line in enumerate(lines):
            if skip_next_lines > 0:
                skip_next_lines -= 1
                continue

            stripped = line.strip()
            upper = stripped.upper()

            if re.match(r"^FROM\s+", stripped, re.IGNORECASE) and not from_processed:
                if any(
                    k in finding_keys
                    for k in (
                        "VS-MUTABLE-BASE-TAG",
                        "VS-UNPINNED-DIGEST",
                        "VS-LATEST-TAG",
                        "DS029",
                        "DS030",
                    )
                ):
                    result.append(
                        "# Pin base image with a digest, e.g. "
                        "FROM python:3.12-slim-bookworm@sha256:<digest>"
                    )
                result.append(stripped)
                result.append("")
                if "VS-MISSING-LABEL" in finding_keys or "DS031" in finding_keys:
                    result.append('LABEL maintainer="security-team" version="1.0"')
                    label_added = True
                from_processed = True
                continue

            if upper.startswith("USER ") and (
                "VS-ROOT-USER" in finding_keys
                or "VS-MISSING-NONROOT-USER" in finding_keys
                or "DS001" in finding_keys
                or "DS002" in finding_keys
            ):
                continue

            if "APT-GET INSTALL" in upper or "APK ADD" in upper:
                if "VS-UNNECESSARY-PACKAGES" in finding_keys:
                    cleaned = stripped
                    for pkg in self.UNNECESSARY_PACKAGES:
                        cleaned = re.sub(rf"\b{pkg}\b", "", cleaned, flags=re.IGNORECASE)
                    cleaned = re.sub(r"\s+", " ", cleaned).replace("\\ ", "\\\n    ")
                    if cleaned.strip():
                        result.append(cleaned)
                    continue

            if "VS-CHMOD-777" in finding_keys or "VS-WORLD-WRITABLE" in finding_keys:
                if re.search(r"chmod\s+777", stripped, re.IGNORECASE):
                    continue

            if upper.startswith("CMD ") or upper.startswith("ENTRYPOINT "):
                if "VS-INTERACTIVE-SHELL" in finding_keys and re.search(
                    r"\b(?:ba)?sh\b", stripped, re.IGNORECASE
                ):
                    result.append('CMD ["python", "app.py"]')
                    continue

            result.append(line)

        body = "\n".join(result)

        if ("VS-MISSING-NONROOT-USER" in finding_keys or "VS-ROOT-USER" in finding_keys) and "USER " not in body.upper():
            insert = (
                "\nRUN groupadd -r appuser && useradd -r -g appuser appuser\n"
                "RUN chown -R appuser:appuser /app || true\n"
                "USER appuser\n"
            )
            if "CMD " in body:
                body = body.replace("\nCMD ", insert + "\nCMD ", 1)
            else:
                body += insert
            user_added = True

        if ("VS-MISSING-HEALTHCHECK" in finding_keys or "DS026" in finding_keys) and "HEALTHCHECK" not in body.upper():
            body += (
                "\nHEALTHCHECK --interval=30s --timeout=5s --retries=3 "
                'CMD python -c "import sys; sys.exit(0)"\n'
            )
            healthcheck_added = True

        if ("VS-MISSING-LABEL" in finding_keys) and not label_added and "LABEL " not in body.upper():
            body = body.replace("\n\n", '\nLABEL maintainer="security-team" version="1.0"\n\n', 1)

        _ = user_added, healthcheck_added
        return body.strip() + "\n"

    def has_pending_findings(self, findings: list[dict]) -> bool:
        return bool(findings)
