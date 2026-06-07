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
                if f"=={fixed}" in line or f">={fixed}" in line or line.endswith(fixed):
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
        fixes = []
        seen = set()

        for vuln in vulnerabilities:
            if not is_fixable_fn(vuln):
                continue

            source_type = self.classify_vulnerability_source(
                vuln, ecosystem, dockerfile_content
            )
            if source_type != "DEPENDENCY":
                continue

            pkg = vuln.get("package_name", "unknown")
            key = (pkg, vuln.get("cve_id"))
            if key in seen:
                continue
            seen.add(key)

            fixed_version = vuln.get("fixed_version", "")
            current = self._read_current_from_file(
                build_context,
                source_file,
                pkg,
                vuln.get("installed_version", ""),
                ecosystem,
            )
            recommended = self._format_recommended(pkg, fixed_version, ecosystem)
            applied = self.is_dependency_fix_applied(
                build_context, source_file, pkg, fixed_version, ecosystem
            )

            fixes.append(
                {
                    "source_file": source_file,
                    "package_name": pkg,
                    "current": current,
                    "recommended": recommended,
                    "reason": f"Fixes {vuln.get('cve_id', 'UNKNOWN')}",
                    "cve_id": vuln.get("cve_id", "UNKNOWN"),
                    "severity": vuln.get("severity", "LOW"),
                    "installed_version": vuln.get("installed_version", ""),
                    "fixed_version": fixed_version,
                    "ecosystem": ecosystem,
                    "applied": applied,
                }
            )

        return fixes

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
