import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from database import get_db
from models import Remediation, Service, ScanHistory, RemediationHistory, Repository
from schemas import RemediationResponse, VulnerabilitySummary, RemediationHistoryResponse

router = APIRouter(prefix="/api/remediation", tags=["remediation"])


def _to_response(remediation: Remediation, service: Service) -> RemediationResponse:
    vulns_raw = json.loads(remediation.vulnerabilities_json or "[]")
    vulnerabilities = [VulnerabilitySummary(**v) for v in vulns_raw]

    return RemediationResponse(
        id=remediation.id,
        service_id=service.id,
        service_name=service.service_name,
        dockerfile_path=service.dockerfile_path,
        remediation_state=remediation.remediation_state,
        status_message=remediation.status_message or "",
        show_generate_fix=bool(remediation.show_generate_fix),
        current_dockerfile=remediation.current_dockerfile,
        updated_dockerfile=remediation.updated_dockerfile or "",
        previous_updated_dockerfile=remediation.previous_updated_dockerfile or "",
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
        remaining_critical=remediation.remaining_critical,
        remaining_high=remediation.remaining_high,
        remaining_medium=remediation.remaining_medium,
        remaining_low=remediation.remaining_low,
        current_decision=remediation.current_decision,
        estimated_decision=remediation.estimated_decision,
        original_score=remediation.original_score,
        score_after_remediation=remediation.score_after_remediation,
        improvement_percentage=remediation.improvement_percentage,
        original_critical=remediation.original_critical,
        original_high=remediation.original_high,
        original_medium=remediation.original_medium,
        original_low=remediation.original_low,
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


@router.get("/history/scan/{scan_id}", response_model=list[RemediationHistoryResponse])
def get_remediation_history_by_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    repo_url = scan.repository.repo_url
    records = (
        db.query(RemediationHistory)
        .join(Repository)
        .filter(Repository.repo_url == repo_url)
        .order_by(RemediationHistory.created_at.asc())
        .all()
    )

    return [
        RemediationHistoryResponse(
            id=record.id,
            service_name=record.service_name,
            dockerfile_path=record.dockerfile_path,
            remediation_state=record.remediation_state,
            original_score=record.original_score,
            score_after_remediation=record.score_after_remediation,
            remaining_critical=record.remaining_critical,
            remaining_high=record.remaining_high,
            remaining_medium=record.remaining_medium,
            remaining_low=record.remaining_low,
            improvement_percentage=record.improvement_percentage,
            created_at=record.created_at,
        )
        for record in records
    ]


@router.get("/history/latest", response_model=list[RemediationHistoryResponse])
def get_latest_remediation_history(db: Session = Depends(get_db)):
    latest_scan = (
        db.query(ScanHistory)
        .order_by(ScanHistory.created_at.desc())
        .first()
    )
    if not latest_scan:
        return []

    return get_remediation_history_by_scan(latest_scan.id, db)


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

    remediation = service.remediation
    if not remediation.show_generate_fix or not remediation.updated_dockerfile:
        raise HTTPException(
            status_code=400,
            detail=remediation.status_message or "No Dockerfile remediation available to download.",
        )

    filename = service.dockerfile_path.replace("/", "_")
    return PlainTextResponse(
        content=remediation.updated_dockerfile,
        media_type="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="Dockerfile.remediated.{filename}"'
        },
    )
