import os
import re


class DependencyService:
    OS_PACKAGE_PREFIXES = (
        "lib", "libc", "openssl", "glibc", "zlib", "curl", "bash",
        "perl", "gnutls", "sqlite", "expat", "krb", "pam", "systemd",
        "apt", "dpkg", "gcc", "binutils", "coreutils", "tar", "gzip",
        "busybox", "musl", "alpine", "debian", "ubuntu",
    )

    ECOSYSTEM_FILES = {
        "python": ["requirements.txt", "requirements-dev.txt", "pyproject.toml", "Pipfile"],
        "node": ["package.json"],
        "java": ["pom.xml", "build.gradle", "build.gradle.kts"],
        "go": ["go.mod"],
    }

    def detect_ecosystem(self, dockerfile_content: str, build_context: str) -> str:
        from_match = re.search(
            r"^FROM\s+(.+)", dockerfile_content or "", re.MULTILINE | re.IGNORECASE
        )
        base = from_match.group(1).lower() if from_match else ""
        docker_lower = (dockerfile_content or "").lower()

        if any(k in base for k in ("python", "django", "flask")) or "pip install" in docker_lower:
            return "python"
        if any(k in base for k in ("node", "npm")) or "npm install" in docker_lower or "npm ci" in docker_lower:
            return "node"
        if any(k in base for k in ("openjdk", "temurin", "maven", "gradle", "java")) or "mvn " in docker_lower:
            return "java"
        if any(k in base for k in ("golang", "go:")) or "go build" in docker_lower or "go mod" in docker_lower:
            return "go"

        for eco, files in self.ECOSYSTEM_FILES.items():
            for filename in files:
                if os.path.isfile(os.path.join(build_context or "", filename)):
                    return eco

        return "python"

    def get_source_file(self, ecosystem: str, build_context: str) -> str:
        candidates = self.ECOSYSTEM_FILES.get(ecosystem, ["requirements.txt"])
        for filename in candidates:
            if os.path.isfile(os.path.join(build_context or "", filename)):
                return filename
        return candidates[0]

    def is_os_package(self, package_name: str) -> bool:
        pkg = (package_name or "").lower()
        if not pkg:
            return False
        return any(pkg.startswith(p) or pkg == p for p in self.OS_PACKAGE_PREFIXES)

    def classify_vulnerability_source(
        self, vulnerability: dict, ecosystem: str, dockerfile_content: str
    ) -> str:
        pkg = vulnerability.get("package_name", "")

        if self.is_os_package(pkg):
            return "OS_PACKAGE"

        from_match = re.search(
            r"^FROM\s+(.+)", dockerfile_content or "", re.MULTILINE | re.IGNORECASE
        )
        base = from_match.group(1).lower() if from_match else ""

        if pkg.lower() in base or pkg.lower() in ("debian", "ubuntu", "alpine"):
            return "BASE_IMAGE"

        if ecosystem in ("python", "node", "java", "go"):
            return "DEPENDENCY"

        return "OS_PACKAGE"

    def _normalize_pkg_name(self, name: str) -> str:
        return re.sub(r"[-_.]+", "-", (name or "").lower())

    def _parse_version(self, version: str) -> tuple:
        cleaned = re.sub(r"^v", "", (version or "").strip(), flags=re.IGNORECASE)
        parts = []
        for segment in re.split(r"[.\-+]", cleaned):
            match = re.match(r"(\d+)", segment)
            parts.append(int(match.group(1)) if match else 0)
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts)

    def _highest_version(self, versions: list[str]) -> str:
        candidates = [v.strip() for v in versions if v and v.strip() and v.strip() != "-"]
        if not candidates:
            return ""
        return max(candidates, key=lambda v: self._parse_version(v))

    def _severity_rank(self, severity: str) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(
            (severity or "").upper(), 0
        )

    def _extract_version_from_line(self, line: str, ecosystem: str) -> str:
        if ecosystem == "python":
            for sep in ("==", ">=", "<=", "~=", "!="):
                if sep in line:
                    return line.split(sep, 1)[1].strip()
        if ecosystem == "node" and ":" in line:
            match = re.search(r':\s*"([^"]+)"', line)
            return match.group(1) if match else ""
        return ""

    def _format_recommended(self, package_name: str, fixed_version: str, ecosystem: str) -> str:
        fixed = (fixed_version or "").strip()
        if not fixed or fixed == "-":
            return package_name

        if ecosystem == "python":
            if "==" in fixed or ">=" in fixed or "<=" in fixed:
                return fixed if fixed.lower().startswith(package_name.lower()) else f"{package_name}=={fixed}"
            return f"{package_name}=={fixed}"

        if ecosystem == "node":
            return f'"{package_name}": "{fixed}"'

        if ecosystem == "java":
            return f"<dependency><artifactId>{package_name}</artifactId><version>{fixed}</version></dependency>"

        if ecosystem == "go":
            return f"{package_name} {fixed}"

        return f"{package_name}=={fixed}"

    def _read_current_from_file(
        self, build_context: str, source_file: str, package_name: str, installed_version: str, ecosystem: str
    ) -> str:
        path = os.path.join(build_context or "", source_file)
        if not os.path.isfile(path):
            if installed_version:
                return f"{package_name}=={installed_version}" if ecosystem == "python" else f"{package_name}@{installed_version}"
            return package_name

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            return package_name

        norm_pkg = self._normalize_pkg_name(package_name)

        if ecosystem == "python" and source_file.endswith((".txt", ".in")):
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if self._normalize_pkg_name(line.split("==")[0].split(">=")[0].split("<=")[0]) == norm_pkg:
                    return line

        if ecosystem == "node" and source_file == "package.json":
            pattern = rf'"{re.escape(package_name)}"\s*:\s*"([^"]+)"'
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return f'"{package_name}": "{match.group(1)}"'

        if ecosystem == "java" and source_file == "pom.xml":
            pattern = rf"<artifactId>{re.escape(package_name)}</artifactId>\s*<version>([^<]+)</version>"
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return f"{package_name}:{match.group(1)}"

        if ecosystem == "go" and source_file == "go.mod":
            for line in content.splitlines():
                if package_name in line and ("require" in line or line.strip().startswith(package_name.split("/")[0])):
                    return line.strip()

        if installed_version:
            return f"{package_name}=={installed_version}" if ecosystem == "python" else f"{package_name}@{installed_version}"
        return package_name

    def _read_source_file_content(self, build_context: str, source_file: str) -> str:
        path = os.path.join(build_context or "", source_file)
        if not os.path.isfile(path):
            return ""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def _replace_line_for_package(
        self, line: str, norm_pkg: str, new_line: str, ecosystem: str
    ) -> str:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return line
        if ecosystem == "python":
            pkg_part = stripped.split("==")[0].split(">=")[0].split("<=")[0]
            if self._normalize_pkg_name(pkg_part) == norm_pkg:
                return new_line
        return line

    def is_dependency_fix_applied(
        self, build_context: str, source_file: str, package_name: str, fixed_version: str, ecosystem: str
    ) -> bool:
        path = os.path.join(build_context or "", source_file)
        if not os.path.isfile(path) or not fixed_version or fixed_version == "-":
            return False

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            return False

        fixed = fixed_version.strip()
        norm_pkg = self._normalize_pkg_name(package_name)

        if ecosystem == "python":
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                pkg_part = line.split("==")[0].split(">=")[0].split("<=")[0]
                if self._normalize_pkg_name(pkg_part) != norm_pkg:
                    continue
                installed = self._extract_version_from_line(line, ecosystem)
                if installed and self._parse_version(installed) >= self._parse_version(fixed):
                    return True
                if f"=={fixed}" in line or f">={fixed}" in line:
                    return True

        if ecosystem == "node":
            return f'"{package_name}": "{fixed}"' in content or f'"{package_name}":"{fixed}"' in content.replace(" ", "")

        if ecosystem == "java":
            return (
                f"<artifactId>{package_name}</artifactId>" in content
                and f"<version>{fixed}</version>" in content
            )

        if ecosystem == "go":
            return fixed in content and package_name in content

        return False

    def generate_dependency_fixes(
        self,
        vulnerabilities: list[dict],
        build_context: str,
        dockerfile_content: str,
        is_fixable_fn,
    ) -> list[dict]:
        ecosystem = self.detect_ecosystem(dockerfile_content, build_context)
        source_file = self.get_source_file(ecosystem, build_context)
        grouped: dict[str, dict] = {}

        for vuln in vulnerabilities:
            if not is_fixable_fn(vuln):
                continue

            source_type = self.classify_vulnerability_source(
                vuln, ecosystem, dockerfile_content
            )
            if source_type != "DEPENDENCY":
                continue

            pkg = vuln.get("package_name", "unknown")
            norm_pkg = self._normalize_pkg_name(pkg)
            cve_id = vuln.get("cve_id", "UNKNOWN")
            fixed_version = (vuln.get("fixed_version") or "").strip()

            if norm_pkg not in grouped:
                current_line = self._read_current_from_file(
                    build_context,
                    source_file,
                    pkg,
                    vuln.get("installed_version", ""),
                    ecosystem,
                )
                grouped[norm_pkg] = {
                    "source_file": source_file,
                    "package_name": pkg,
                    "current_line": current_line,
                    "current_version": vuln.get("installed_version", "")
                    or self._extract_version_from_line(current_line, ecosystem),
                    "fixed_versions": [],
                    "cve_ids": [],
                    "severities": [],
                    "ecosystem": ecosystem,
                }

            entry = grouped[norm_pkg]
            if cve_id not in entry["cve_ids"]:
                entry["cve_ids"].append(cve_id)
            if fixed_version and fixed_version not in entry["fixed_versions"]:
                entry["fixed_versions"].append(fixed_version)
            entry["severities"].append(vuln.get("severity", "LOW"))

        fixes = []
        for entry in grouped.values():
            pkg = entry["package_name"]
            highest_fix = self._highest_version(entry["fixed_versions"])
            recommended_line = self._format_recommended(pkg, highest_fix, entry["ecosystem"])
            applied = self.is_dependency_fix_applied(
                build_context, source_file, pkg, highest_fix, entry["ecosystem"]
            )
            impact = len(entry["cve_ids"])
            highest_severity = max(
                entry["severities"], key=lambda s: self._severity_rank(s)
            )

            fixes.append(
                {
                    "source_file": source_file,
                    "package_name": pkg,
                    "current": entry["current_version"],
                    "recommended": highest_fix,
                    "current_line": entry["current_line"],
                    "recommended_line": recommended_line,
                    "reason": f"Fixes {impact} vulnerabilit{'y' if impact == 1 else 'ies'}",
                    "cve_id": entry["cve_ids"][0],
                    "cve_ids": entry["cve_ids"],
                    "fixes": entry["cve_ids"],
                    "impact": impact,
                    "severity": highest_severity,
                    "installed_version": entry["current_version"],
                    "fixed_version": highest_fix,
                    "ecosystem": entry["ecosystem"],
                    "applied": applied,
                }
            )

        fixes.sort(key=lambda f: (-f["impact"], f["package_name"].lower()))
        return fixes

    def generate_dependency_patches(
        self, dependency_fixes: list[dict], build_context: str
    ) -> list[dict]:
        if not dependency_fixes:
            return []

        by_file: dict[str, list[dict]] = {}
        for fix in dependency_fixes:
            if fix.get("applied"):
                continue
            by_file.setdefault(fix["source_file"], []).append(fix)

        patches = []
        for source_file, fixes in by_file.items():
            ecosystem = fixes[0].get("ecosystem", "python")
            file_content = self._read_source_file_content(build_context, source_file)
            current_lines = []
            recommended_lines = []
            recommended_full = file_content

            for fix in fixes:
                current_lines.append(fix.get("current_line") or fix.get("current", ""))
                recommended_lines.append(fix.get("recommended_line") or fix.get("recommended", ""))
                norm_pkg = self._normalize_pkg_name(fix["package_name"])
                if file_content and ecosystem == "python":
                    updated = []
                    for line in file_content.splitlines(keepends=True):
                        line_body = line.rstrip("\r\n")
                        suffix = line[len(line_body):]
                        new_body = self._replace_line_for_package(
                            line_body,
                            norm_pkg,
                            fix.get("recommended_line", ""),
                            ecosystem,
                        )
                        updated.append(new_body + suffix)
                    recommended_full = "".join(updated) if updated else file_content

            if not recommended_full and recommended_lines:
                recommended_full = "\n".join(recommended_lines) + "\n"

            patches.append(
                {
                    "source_file": source_file,
                    "current_section": "\n".join(current_lines),
                    "recommended_section": "\n".join(recommended_lines),
                    "recommended_file_content": recommended_full.strip() + "\n"
                    if recommended_full
                    else "\n".join(recommended_lines) + "\n",
                    "package_count": len(fixes),
                    "vulnerability_count": sum(f.get("impact", 1) for f in fixes),
                }
            )

        return patches

    def get_pending_dependency_fixes(self, dependency_fixes: list[dict]) -> list[dict]:
        return [f for f in dependency_fixes if not f.get("applied")]

    def needs_dockerfile_remediation(
        self, vulnerabilities: list[dict], dockerfile_content: str, is_fixable_fn
    ) -> bool:
        ecosystem = self.detect_ecosystem(dockerfile_content, "")
        for vuln in vulnerabilities:
            if not is_fixable_fn(vuln):
                continue
            source = self.classify_vulnerability_source(vuln, ecosystem, dockerfile_content)
            if source in ("OS_PACKAGE", "BASE_IMAGE"):
                return True

        if ":latest" in dockerfile_content.lower():
            return True
        if "apt-get upgrade" not in dockerfile_content and "apk upgrade" not in dockerfile_content:
            if re.search(r"FROM\s+.*(slim|bookworm|bullseye|ubuntu|debian|alpine)", dockerfile_content, re.I):
                return True
        if "USER " not in dockerfile_content.upper():
            return True

        return False

    def annotate_vulnerabilities(
        self,
        vulnerabilities: list[dict],
        build_context: str,
        dockerfile_content: str,
        is_fixable_fn,
    ) -> list[dict]:
        ecosystem = self.detect_ecosystem(dockerfile_content, build_context)
        source_file = self.get_source_file(ecosystem, build_context)
        annotated = []

        for vuln in vulnerabilities:
            v = dict(vuln)
            fixable = is_fixable_fn(vuln)
            source_type = self.classify_vulnerability_source(vuln, ecosystem, dockerfile_content)

            if source_type == "DEPENDENCY":
                v["remediation_source"] = source_file
                v["remediation_type"] = "DEPENDENCY"
            elif source_type == "OS_PACKAGE":
                v["remediation_source"] = "Dockerfile"
                v["remediation_type"] = "OS_PACKAGE"
            elif source_type == "BASE_IMAGE":
                v["remediation_source"] = "Dockerfile"
                v["remediation_type"] = "BASE_IMAGE"
            else:
                v["remediation_source"] = "Dockerfile"
                v["remediation_type"] = "DOCKERFILE"

            v["classification"] = "FIXABLE" if fixable else "UNFIXABLE"
            annotated.append(v)

        return annotated
