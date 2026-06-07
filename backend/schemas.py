from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class RepositoryScanRequest(BaseModel):
    repo_url: str


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
    created_at: datetime


class DashboardStats(BaseModel):
    repositories_scanned: int
    images_scanned: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    pass_count: int
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
