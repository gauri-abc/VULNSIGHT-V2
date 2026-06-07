from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class RepositoryScanRequest(BaseModel):
    repo_url: str


class DockerSecurityFindingResponse(BaseModel):
    severity: str
    rule: str
    description: str
    recommendation: str
    source: str = "trivy"
    rule_id: str = ""


class RepositoryScanResponse(BaseModel):
    scan_id: int
    repository: str
    dockerfiles_found: int
    images_built: int
    critical: int
    high: int
    medium: int
    low: int
    score: float
    decision: str
    fixable_count: int = 0
    unfixable_count: int = 0
    risk_accepted: bool = False
    status_reason: str = ""
    dependency_findings: int = 0
    dockerfile_findings: int = 0
    image_findings: int = 0


class ServiceResponse(BaseModel):
    id: int
    service_name: str
    dockerfile_path: str
    image_name: str
    critical: int
    high: int
    medium: int
    low: int
    score: float
    status: str
    fixable_count: int = 0
    unfixable_count: int = 0
    status_reason: str = ""
    remediation_state: Optional[str] = None
    risk_accepted: bool = False
    dependency_findings: int = 0
    dockerfile_findings: int = 0
    image_findings: int = 0


class ScanHistoryResponse(BaseModel):
    id: int
    repository_name: str
    repo_url: str
    critical: int
    high: int
    medium: int
    low: int
    security_score: float
    decision: str
    fixable_count: int = 0
    unfixable_count: int = 0
    risk_accepted: bool = False
    created_at: datetime


class DashboardStats(BaseModel):
    repositories_scanned: int
    images_scanned: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    pass_count: int
    pass_with_risk_count: int
    fail_count: int
    warning_count: int
    average_security_score: float


class SeverityChartItem(BaseModel):
    severity: str
    count: int


class TopVulnerableService(BaseModel):
    service_name: str
    repository_name: str
    total_vulnerabilities: int
    critical: int
    high: int


class ScoreTrendItem(BaseModel):
    date: str
    score: float
    repository_name: str


class AlertResponse(BaseModel):
    id: int
    message: str
    severity: str
    created_at: datetime
    repository_name: Optional[str] = None


class VulnerabilitySummary(BaseModel):
    cve_id: str
    severity: str
    package_name: str
    installed_version: str
    fixed_version: str
    description: str
    classification: Optional[str] = None
    remediation_source: Optional[str] = None
    remediation_type: Optional[str] = None


class SecurityBreakdownResponse(BaseModel):
    dependency_vulnerabilities: list[VulnerabilitySummary]
    dockerfile_security_findings: list[DockerSecurityFindingResponse]
    image_vulnerabilities: list[VulnerabilitySummary]
    dependency_counts: dict = {}
    dockerfile_counts: dict = {}
    image_counts: dict = {}
    combined_score: float = 100.0
    dependency_score: float = 100.0
    dockerfile_score: float = 100.0
    image_score: float = 100.0


class DependencyFix(BaseModel):
    source_file: str
    package_name: str
    current: str
    recommended: str
    reason: str
    cve_id: str
    severity: str
    installed_version: str = ""
    fixed_version: str = ""
    ecosystem: str = ""
    applied: bool = False
    current_line: str = ""
    recommended_line: str = ""
    cve_ids: list[str] = []
    fixes: list[str] = []
    impact: int = 1


class DependencyPatch(BaseModel):
    source_file: str
    current_section: str
    recommended_section: str
    recommended_file_content: str
    package_count: int = 0
    vulnerability_count: int = 0


class RemediationResponse(BaseModel):
    id: int
    service_id: int
    service_name: str
    dockerfile_path: str
    remediation_state: str
    status_message: str
    show_generate_fix: bool
    current_dockerfile: str
    updated_dockerfile: str
    previous_updated_dockerfile: str
    root_cause_analysis: list[str]
    recommended_fixes: list[str]
    vulnerabilities_found: list[VulnerabilitySummary]
    current_critical: int
    current_high: int
    current_medium: int
    current_low: int
    estimated_critical: int
    estimated_high: int
    estimated_medium: int
    estimated_low: int
    remaining_critical: int
    remaining_high: int
    remaining_medium: int
    remaining_low: int
    current_decision: str
    estimated_decision: str
    original_score: float
    score_after_remediation: float
    improvement_percentage: float
    original_critical: int
    original_high: int
    original_medium: int
    original_low: int
    fixable_count: int = 0
    unfixable_count: int = 0
    status_reason: str = ""
    dependency_fixes: list[DependencyFix] = []
    dependency_patches: list[DependencyPatch] = []
    pending_dependency_count: int = 0
    risk_accepted: bool = False


class RemediationHistoryResponse(BaseModel):
    id: int
    service_name: str
    dockerfile_path: str
    remediation_state: str
    original_score: float
    score_after_remediation: float
    remaining_critical: int
    remaining_high: int
    remaining_medium: int
    remaining_low: int
    improvement_percentage: float
    created_at: datetime
