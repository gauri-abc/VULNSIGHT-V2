import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import Service, ScanHistory
from schemas import ServiceResponse, SecurityBreakdownResponse, VulnerabilitySummary, DockerSecurityFindingResponse
from services.scoring_service import ScoringService
from services.policy_service import PolicyService

router = APIRouter(prefix="/api/services", tags=["services"])

scoring_service = ScoringService()
policy_service = PolicyService()


def _vuln_dict(v):
    return {
        "severity": v.severity,
        "fixed_version": v.fixed_version or "",
        "package_name": v.package_name,
        "cve_id": v.cve_id,
    }


def _vuln_summary(v) -> VulnerabilitySummary:
    fixable = policy_service.is_fixable({"fixed_version": v.fixed_version or ""})
    return VulnerabilitySummary(
        cve_id=v.cve_id,
        severity=v.severity,
        package_name=v.package_name,
        installed_version=v.installed_version or "",
        fixed_version=v.fixed_version or "",
        description=v.description or "",
        classification="FIXABLE" if fixable else "UNFIXABLE",
        remediation_source="requirements.txt" if getattr(v, "category", "image") == "dependency" else "Dockerfile",
        remediation_type="DEPENDENCY" if getattr(v, "category", "image") == "dependency" else "OS_PACKAGE",
    )


def _service_metrics(service: Service) -> dict:
    dependency_vulns = [
        v for v in service.vulnerabilities if getattr(v, "category", "image") == "dependency"
    ]
    image_vulns = [
        v for v in service.vulnerabilities if getattr(v, "category", "image") != "dependency"
    ]
    docker_findings = [
        {
            "severity": f.severity,
            "rule": f.rule,
            "description": f.description or "",
            "recommendation": f.recommendation or "",
            "source": f.source or "trivy",
            "rule_id": f.rule_id or "",
        }
        for f in service.docker_security_findings
    ]

    dep_counts = scoring_service.count_severities(dependency_vulns)
    image_counts = scoring_service.count_severities(image_vulns)
    docker_counts = scoring_service.count_severities(docker_findings)
    combined_counts = scoring_service.merge_counts(dep_counts, image_counts, docker_counts)

    return {
        "dependency_vulns": dependency_vulns,
        "image_vulns": image_vulns,
        "docker_findings": docker_findings,
        "dep_counts": dep_counts,
        "image_counts": image_counts,
        "docker_counts": docker_counts,
        "combined_counts": combined_counts,
        "combined_score": scoring_service.calculate_score(combined_counts),
    }


@router.get("/scan/{scan_id}", response_model=list[ServiceResponse])
def get_services_by_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    services = (
        db.query(Service)
        .filter(Service.repository_id == scan.repository_id)
        .all()
    )

    results = []
    for service in services:
        metrics = _service_metrics(service)
        vulns = [_vuln_dict(v) for v in service.vulnerabilities]
        classification = policy_service.classify_vulnerabilities(vulns)

        remediation_state = None
        pending_dependency_fixes = []
        if service.remediation:
            remediation_state = service.remediation.remediation_state
            dep_raw = json.loads(service.remediation.dependency_fixes_json or "[]")
            pending_dependency_fixes = [f for f in dep_raw if not f.get("applied")]

        status = policy_service.evaluate_deployment(
            vulns,
            remediation_state=remediation_state,
            pending_dependency_fixes=pending_dependency_fixes,
            dockerfile_findings=metrics["docker_findings"],
        )
        risk_accepted = policy_service.is_risk_accepted(
            vulns,
            remediation_state=remediation_state,
            pending_dependency_fixes=pending_dependency_fixes,
        )
        status_reason = policy_service.get_status_reason(
            vulns,
            status,
            remediation_state,
            pending_dependency_fixes=pending_dependency_fixes,
            dockerfile_findings=metrics["docker_findings"],
        )

        combined = metrics["combined_counts"]
        results.append(
            ServiceResponse(
                id=service.id,
                service_name=service.service_name,
                dockerfile_path=service.dockerfile_path,
                image_name=service.image_name,
                critical=combined["CRITICAL"],
                high=combined["HIGH"],
                medium=combined["MEDIUM"],
                low=combined["LOW"],
                score=metrics["combined_score"],
                status=status,
                fixable_count=classification["fixable_count"],
                unfixable_count=classification["unfixable_count"],
                status_reason=status_reason,
                remediation_state=remediation_state,
                risk_accepted=risk_accepted,
                dependency_findings=len(metrics["dependency_vulns"]),
                dockerfile_findings=len(metrics["docker_findings"]),
                image_findings=len(metrics["image_vulns"]),
            )
        )

    return results


@router.get("/latest", response_model=list[ServiceResponse])
def get_latest_services(db: Session = Depends(get_db)):
    latest_scan = (
        db.query(ScanHistory)
        .order_by(ScanHistory.created_at.desc())
        .first()
    )
    if not latest_scan:
        return []

    return get_services_by_scan(latest_scan.id, db)


@router.get("/{service_id}/security-breakdown", response_model=SecurityBreakdownResponse)
def get_service_security_breakdown(service_id: int, db: Session = Depends(get_db)):
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")

    metrics = _service_metrics(service)

    return SecurityBreakdownResponse(
        dependency_vulnerabilities=[_vuln_summary(v) for v in metrics["dependency_vulns"]],
        dockerfile_security_findings=[
            DockerSecurityFindingResponse(**finding) for finding in metrics["docker_findings"]
        ],
        image_vulnerabilities=[_vuln_summary(v) for v in metrics["image_vulns"]],
        dependency_counts=metrics["dep_counts"],
        dockerfile_counts=metrics["docker_counts"],
        image_counts=metrics["image_counts"],
        combined_score=metrics["combined_score"],
        dependency_score=scoring_service.calculate_score(metrics["dep_counts"]),
        dockerfile_score=scoring_service.calculate_score(metrics["docker_counts"]),
        image_score=scoring_service.calculate_score(metrics["image_counts"]),
    )
