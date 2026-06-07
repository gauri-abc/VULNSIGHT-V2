from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import Service, ScanHistory
from schemas import ServiceResponse
from services.scoring_service import ScoringService
from services.policy_service import PolicyService
from services.trivy_service import TrivyService

router = APIRouter(prefix="/api/services", tags=["services"])

scoring_service = ScoringService()
policy_service = PolicyService()
trivy_service = TrivyService()


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
        vulns = service.vulnerabilities
        counts = trivy_service.count_by_severity(
            [{"severity": v.severity} for v in vulns]
        )
        score = scoring_service.calculate_service_score(
            [{"severity": v.severity} for v in vulns]
        )
        status = policy_service.evaluate_service(counts)

        results.append(
            ServiceResponse(
                id=service.id,
                service_name=service.service_name,
                dockerfile_path=service.dockerfile_path,
                image_name=service.image_name,
                critical=counts["CRITICAL"],
                high=counts["HIGH"],
                medium=counts["MEDIUM"],
                low=counts["LOW"],
                score=score,
                status=status,
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
