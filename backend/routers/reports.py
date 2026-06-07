import csv
import io
import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.orm import Session

from database import get_db
from models import Repository, Service, ScanHistory
from schemas import ScanHistoryResponse
from services.policy_service import PolicyService

policy_service = PolicyService()

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/history", response_model=list[ScanHistoryResponse])
def get_scan_history(db: Session = Depends(get_db)):
    scans = (
        db.query(ScanHistory)
        .join(Repository)
        .order_by(ScanHistory.created_at.desc())
        .all()
    )

    return [
        ScanHistoryResponse(
            id=scan.id,
            repository_name=scan.repository.name,
            repo_url=scan.repository.repo_url,
            critical=scan.critical,
            high=scan.high,
            medium=scan.medium,
            low=scan.low,
            security_score=scan.security_score,
            decision=scan.decision,
            fixable_count=getattr(scan, "fixable_count", 0) or 0,
            unfixable_count=getattr(scan, "unfixable_count", 0) or 0,
            created_at=scan.created_at,
        )
        for scan in scans
    ]


def _build_report_data(scan_id: int, db: Session) -> dict:
    scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    repository = scan.repository
    services = (
        db.query(Service)
        .filter(Service.repository_id == repository.id)
        .all()
    )

    all_vulns = []
    services_data = []
    for service in services:
        vulns = [
            {
                "cve_id": v.cve_id,
                "severity": v.severity,
                "package_name": v.package_name,
                "installed_version": v.installed_version,
                "fixed_version": v.fixed_version,
                "description": v.description,
                "classification": (
                    "FIXABLE" if policy_service.is_fixable(
                        {"fixed_version": v.fixed_version or ""}
                    ) else "UNFIXABLE"
                ),
            }
            for v in service.vulnerabilities
        ]
        all_vulns.extend(vulns)
        services_data.append(
            {
                "service_name": service.service_name,
                "dockerfile_path": service.dockerfile_path,
                "image_name": service.image_name,
                "vulnerabilities": vulns,
            }
        )

    classification = policy_service.classify_vulnerabilities(all_vulns)

    return {
        "scan_id": scan.id,
        "repository": repository.name,
        "repo_url": repository.repo_url,
        "scan_date": scan.created_at.isoformat(),
        "summary": {
            "critical": scan.critical,
            "high": scan.high,
            "medium": scan.medium,
            "low": scan.low,
            "security_score": scan.security_score,
            "decision": scan.decision,
            "fixable_count": getattr(scan, "fixable_count", None) or classification["fixable_count"],
            "unfixable_count": getattr(scan, "unfixable_count", None) or classification["unfixable_count"],
        },
        "services": services_data,
    }


@router.get("/{scan_id}/json")
def download_json_report(scan_id: int, db: Session = Depends(get_db)):
    report = _build_report_data(scan_id, db)
    content = json.dumps(report, indent=2)
    return StreamingResponse(
        io.BytesIO(content.encode("utf-8")),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="vulnsight-report-{scan_id}.json"'
        },
    )


@router.get("/{scan_id}/csv")
def download_csv_report(scan_id: int, db: Session = Depends(get_db)):
    report = _build_report_data(scan_id, db)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "Repository",
            "Service",
            "Dockerfile",
            "CVE ID",
            "Severity",
            "Package",
            "Installed Version",
            "Fixed Version",
            "Description",
        ]
    )

    for service in report["services"]:
        for vuln in service["vulnerabilities"]:
            writer.writerow(
                [
                    report["repository"],
                    service["service_name"],
                    service["dockerfile_path"],
                    vuln["cve_id"],
                    vuln["severity"],
                    vuln["package_name"],
                    vuln["installed_version"],
                    vuln["fixed_version"],
                    vuln["description"],
                ]
            )

    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="vulnsight-report-{scan_id}.csv"'
        },
    )


@router.get("/{scan_id}/pdf")
def download_pdf_report(scan_id: int, db: Session = Depends(get_db)):
    report = _build_report_data(scan_id, db)
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title",
        parent=styles["Heading1"],
        fontSize=20,
        textColor=colors.HexColor("#3b82f6"),
        spaceAfter=12,
    )
    elements = []

    elements.append(Paragraph("VULNSIGHT-V2 Security Report", title_style))
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(Paragraph(f"Repository: <b>{report['repository']}</b>", styles["Normal"]))
    elements.append(Paragraph(f"URL: {report['repo_url']}", styles["Normal"]))
    elements.append(Paragraph(f"Scan Date: {report['scan_date']}", styles["Normal"]))
    elements.append(Spacer(1, 0.3 * inch))

    summary = report["summary"]
    summary_data = [
        ["Metric", "Value"],
        ["Critical", str(summary["critical"])],
        ["High", str(summary["high"])],
        ["Medium", str(summary["medium"])],
        ["Low", str(summary["low"])],
        ["Security Score", str(summary["security_score"])],
        ["Decision", summary["decision"]],
        ["Fixable Vulnerabilities", str(summary.get("fixable_count", 0))],
        ["Unfixable Vulnerabilities", str(summary.get("unfixable_count", 0))],
    ]
    summary_table = Table(summary_data, colWidths=[2.5 * inch, 3 * inch])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ]
        )
    )
    elements.append(summary_table)
    elements.append(Spacer(1, 0.4 * inch))

    for service in report["services"]:
        elements.append(
            Paragraph(
                f"Service: {service['service_name']} ({service['dockerfile_path']})",
                styles["Heading2"],
            )
        )
        if not service["vulnerabilities"]:
            elements.append(Paragraph("No vulnerabilities found.", styles["Normal"]))
            continue

        vuln_rows = [["CVE", "Severity", "Package", "Version"]]
        for vuln in service["vulnerabilities"][:25]:
            vuln_rows.append(
                [
                    vuln["cve_id"],
                    vuln["severity"],
                    vuln["package_name"],
                    vuln["installed_version"],
                ]
            )

        vuln_table = Table(vuln_rows, colWidths=[1.5 * inch, 1 * inch, 2 * inch, 1.5 * inch])
        vuln_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]
            )
        )
        elements.append(vuln_table)
        elements.append(Spacer(1, 0.2 * inch))

    doc.build(elements)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="vulnsight-report-{scan_id}.pdf"'
        },
    )
