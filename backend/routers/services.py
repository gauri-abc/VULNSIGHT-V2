import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import Service, ScanHistory
from schemas import ServiceResponse
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
        vulns = [_vuln_dict(v) for v in service.vulnerabilities]
        classification = policy_service.classify_vulnerabilities(vulns)
        score = scoring_service.calculate_service_score(vulns)

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
        )
        status_reason = policy_service.get_status_reason(
            vulns,
            status,
            remediation_state,
            pending_dependency_fixes=pending_dependency_fixes,
        )

        results.append(
            ServiceResponse(
                id=service.id,
                service_name=service.service_name,
                dockerfile_path=service.dockerfile_path,
                image_name=service.image_name,
                critical=classification["total_critical"],
                high=classification["total_high"],
                medium=classification["fixable_medium"] + classification["unfixable_medium"],
                low=classification["fixable_low"] + classification["unfixable_low"],
                score=score,
                status=status,
                fixable_count=classification["fixable_count"],
                unfixable_count=classification["unfixable_count"],
                status_reason=status_reason,
                remediation_state=remediation_state,
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
