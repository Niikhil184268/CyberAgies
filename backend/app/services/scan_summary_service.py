from sqlalchemy.orm import Session

from backend.app.models.finding import Finding
from backend.app.services.finding_group_service import group_vulnerabilities
from backend.app.services.risk_analyzer import calculate_scan_risk


def generate_scan_summary(scan_id: int, db: Session):

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .all()
    )

    # Group duplicate vulnerabilities
    grouped_findings = group_vulnerabilities(findings)

    # Use the central risk calculation
    risk_result = calculate_scan_risk(grouped_findings)

    return {
        "scan_id": scan_id,
        "risk": risk_result["risk"],
        "risk_score": risk_result["risk_score"],
        "total_findings": len(grouped_findings),
        "severity_counts": risk_result["severity_counts"],
    }