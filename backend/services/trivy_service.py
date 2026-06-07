import json
import subprocess
from typing import Any


class TrivyService:
    SEVERITY_MAP = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "UNKNOWN": "LOW",
    }

    def scan_dockerfile(self, dockerfile_path: str) -> list[dict]:
        cmd = [
            "trivy",
            "config",
            "--format",
            "json",
            "--quiet",
            "--severity",
            "CRITICAL,HIGH,MEDIUM,LOW",
            dockerfile_path,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        raw_output = (result.stdout or "").strip()
        if not raw_output:
            return []

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return []

        return self._parse_config_output(data)

    def _parse_config_output(self, data: Any) -> list[dict]:
        findings = []
        results = data if isinstance(data, list) else data.get("Results", [])

        if not isinstance(results, list):
            results = [results] if results else []

        for result in results:
            if not isinstance(result, dict):
                continue

            for misconfig in result.get("Misconfigurations") or []:
                findings.append(self._misconfig_to_finding(misconfig))

            for cause in result.get("Causes") or []:
                if isinstance(cause, dict) and cause.get("Misconfigurations"):
                    for misconfig in cause.get("Misconfigurations") or []:
                        findings.append(self._misconfig_to_finding(misconfig))

        return findings

    def _misconfig_to_finding(self, misconfig: dict) -> dict:
        severity = self.SEVERITY_MAP.get(
            (misconfig.get("Severity") or "LOW").upper(),
            "LOW",
        )
        rule_id = misconfig.get("ID") or misconfig.get("AVDID") or ""
        title = misconfig.get("Title") or rule_id or "Dockerfile Misconfiguration"
        description = misconfig.get("Description") or misconfig.get("Message") or ""
        if not description and isinstance(misconfig.get("CauseMetadata"), dict):
            lines = misconfig["CauseMetadata"].get("Code", {}).get("Lines", [])
            if lines and isinstance(lines[0], dict):
                description = lines[0].get("Content", "")
        if not description:
            description = title
        recommendation = (
            misconfig.get("Resolution")
            or misconfig.get("PrimaryURL")
            or "Review and remediate the Dockerfile misconfiguration."
        )

        return {
            "severity": severity,
            "rule": title,
            "description": str(description)[:2000],
            "recommendation": str(recommendation)[:2000],
            "source": "trivy",
            "rule_id": rule_id,
        }

    def scan_image(self, image_name: str) -> list[dict]:
        cmd = [
            "trivy",
            "image",
            "--format",
            "json",
            "--quiet",
            "--scanners",
            "vuln",
            image_name,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )

        if result.returncode != 0 and not result.stdout.strip():
            raise RuntimeError(
                f"Trivy scan failed for {image_name}: {result.stderr[-2000:]}"
            )

        raw_output = result.stdout.strip()
        if not raw_output:
            return []

        data = json.loads(raw_output)
        return self._parse_trivy_output(data)

    def _parse_trivy_output(self, data: Any) -> list[dict]:
        vulnerabilities = []
        results = data if isinstance(data, list) else data.get("Results", [])

        if not isinstance(results, list):
            results = [results] if results else []

        for result in results:
            if not isinstance(result, dict):
                continue

            for vuln in result.get("Vulnerabilities") or []:
                severity = self.SEVERITY_MAP.get(
                    (vuln.get("Severity") or "LOW").upper(),
                    "LOW",
                )

                cve_id = vuln.get("VulnerabilityID") or vuln.get("ID") or "UNKNOWN"
                package_name = vuln.get("PkgName") or vuln.get("PackageName") or "unknown"
                installed_version = vuln.get("InstalledVersion") or ""
                fixed_version = vuln.get("FixedVersion") or ""
                description = vuln.get("Description") or vuln.get("Title") or ""

                vulnerabilities.append(
                    {
                        "cve_id": cve_id,
                        "severity": severity,
                        "package_name": package_name,
                        "installed_version": installed_version,
                        "fixed_version": fixed_version,
                        "description": description[:2000],
                    }
                )

        return vulnerabilities

    def count_by_severity(self, vulnerabilities: list[dict]) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "LOW").upper()
            if severity in counts:
                counts[severity] += 1
            else:
                counts["LOW"] += 1
        return counts
