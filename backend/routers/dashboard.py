from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import get_db
from models import Repository, Service, Vulnerability, ScanHistory
from schemas import (
    DashboardStats,
    SeverityChartItem,
    TopVulnerableService,
    ScoreTrendItem,
)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db)):
    repositories_scanned = db.query(func.count(Repository.id)).scalar() or 0
    images_scanned = db.query(func.count(Service.id)).scalar() or 0

    severity_counts = (
        db.query(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
        .all()
    )
    severity_map = {s: c for s, c in severity_counts}

    pass_count = (
        db.query(func.count(ScanHistory.id))
        .filter(ScanHistory.decision == "PASS")
        .scalar()
        or 0
    )
    pass_with_risk_count = (
        db.query(func.count(ScanHistory.id))
        .filter(ScanHistory.decision == "PASS_WITH_RISK")
        .scalar()
        or 0
    )
    fail_count = (
        db.query(func.count(ScanHistory.id))
        .filter(ScanHistory.decision == "FAIL")
        .scalar()
        or 0
    )
    warning_count = (
        db.query(func.count(ScanHistory.id))
        .filter(ScanHistory.decision == "WARNING")
        .scalar()
        or 0
    )

    avg_score = db.query(func.avg(ScanHistory.security_score)).scalar()
    average_security_score = round(float(avg_score), 2) if avg_score else 100.0

    return DashboardStats(
        repositories_scanned=repositories_scanned,
        images_scanned=images_scanned,
        critical_vulnerabilities=severity_map.get("CRITICAL", 0),
        high_vulnerabilities=severity_map.get("HIGH", 0),
        medium_vulnerabilities=severity_map.get("MEDIUM", 0),
        low_vulnerabilities=severity_map.get("LOW", 0),
        pass_count=pass_count,
        pass_with_risk_count=pass_with_risk_count,
        fail_count=fail_count,
        warning_count=warning_count,
        average_security_score=average_security_score,
    )


@router.get("/severity-chart", response_model=list[SeverityChartItem])
def get_severity_chart(db: Session = Depends(get_db)):
    results = (
        db.query(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
        .all()
    )

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    chart_data = {s: 0 for s in order}
    for severity, count in results:
        chart_data[severity] = count

    return [SeverityChartItem(severity=s, count=chart_data[s]) for s in order]


@router.get("/top-vulnerable-services", response_model=list[TopVulnerableService])
def get_top_vulnerable_services(db: Session = Depends(get_db)):
    services = db.query(Service).all()
    ranked = []

    for service in services:
        vulns = service.vulnerabilities
        critical = sum(1 for v in vulns if v.severity == "CRITICAL")
        high = sum(1 for v in vulns if v.severity == "HIGH")
        ranked.append(
            TopVulnerableService(
                service_name=service.service_name,
                repository_name=service.repository.name,
                total_vulnerabilities=len(vulns),
                critical=critical,
                high=high,
            )
        )

    ranked.sort(key=lambda x: (x.critical, x.high, x.total_vulnerabilities), reverse=True)
    return ranked[:10]


@router.get("/score-trend", response_model=list[ScoreTrendItem])
def get_score_trend(db: Session = Depends(get_db)):
    scans = (
        db.query(ScanHistory)
        .join(Repository)
        .order_by(ScanHistory.created_at.asc())
        .limit(50)
        .all()
    )

    return [
        ScoreTrendItem(
            date=scan.created_at.strftime("%Y-%m-%d %H:%M"),
            score=scan.security_score,
            repository_name=scan.repository.name,
        )
        for scan in scans
    ]
