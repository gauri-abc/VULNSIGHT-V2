import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from database import get_db
from models import Remediation, Service, ScanHistory
from schemas import RemediationResponse, VulnerabilitySummary

router = APIRouter(prefix="/api/remediation", tags=["remediation"])


def _to_response(remediation: Remediation, service: Service) -> RemediationResponse:
    vulns_raw = json.loads(remediation.vulnerabilities_json or "[]")
    vulnerabilities = [VulnerabilitySummary(**v) for v in vulns_raw]

    return RemediationResponse(
        id=remediation.id,
        service_id=service.id,
        service_name=service.service_name,
        dockerfile_path=service.dockerfile_path,
        current_dockerfile=remediation.current_dockerfile,
        updated_dockerfile=remediation.updated_dockerfile,
        root_cause_analysis=json.loads(remediation.root_cause_analysis or "[]"),
        recommended_fixes=json.loads(remediation.recommended_fixes or "[]"),
        vulnerabilities_found=vulnerabilities,
        current_critical=remediation.current_critical,
        current_high=remediation.current_high,
        current_medium=remediation.current_medium,
        current_low=remediation.current_low,
        estimated_critical=remediation.estimated_critical,
        estimated_high=remediation.estimated_high,
        estimated_medium=remediation.estimated_medium,
        estimated_low=remediation.estimated_low,
        current_decision=remediation.current_decision,
        estimated_decision=remediation.estimated_decision,
    )


@router.get("/scan/{scan_id}", response_model=list[RemediationResponse])
def get_remediations_by_scan(scan_id: int, db: Session = Depends(get_db)):
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
        if service.remediation:
            results.append(_to_response(service.remediation, service))

    return results


@router.get("/latest", response_model=list[RemediationResponse])
def get_latest_remediations(db: Session = Depends(get_db)):
    latest_scan = (
        db.query(ScanHistory)
        .order_by(ScanHistory.created_at.desc())
        .first()
    )
    if not latest_scan:
        return []

    return get_remediations_by_scan(latest_scan.id, db)


@router.get("/service/{service_id}", response_model=RemediationResponse)
def get_remediation_by_service(service_id: int, db: Session = Depends(get_db)):
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    if not service.remediation:
        raise HTTPException(
            status_code=404,
            detail="No remediation available. Service may have passed the security gate.",
        )

    return _to_response(service.remediation, service)


@router.get("/service/{service_id}/download")
def download_updated_dockerfile(service_id: int, db: Session = Depends(get_db)):
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service or not service.remediation:
        raise HTTPException(status_code=404, detail="Remediation not found")

    filename = service.dockerfile_path.replace("/", "_")
    return PlainTextResponse(
        content=service.remediation.updated_dockerfile,
        media_type="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="Dockerfile.remediated.{filename}"'
        },
    )
