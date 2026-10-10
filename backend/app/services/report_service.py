from sqlalchemy.orm import Session

from backend.app.models.scan import Scan
from backend.app.models.finding import Finding
from backend.app.services.scan_summary_service import generate_scan_summary
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from pathlib import Path
from backend.app.services.finding_group_service import group_vulnerabilities

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)


def generate_security_report(scan_id: int, db: Session):
    """
    Generate a structured SOC-style security report for a scan.
    """

    # --------------------------------------------------
    # 1. Get scan
    # --------------------------------------------------

    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if scan is None:
        return None

    # --------------------------------------------------
    # 2. Get findings
    # --------------------------------------------------

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .all()
    )
    grouped_findings = group_vulnerabilities(findings)

    # --------------------------------------------------
    # 3. Generate scan summary
    # --------------------------------------------------

    summary = generate_scan_summary(scan_id, db)

    severity_counts = summary["severity_counts"]

    # --------------------------------------------------
    # 4. Build executive summary
    # --------------------------------------------------

    risk = summary["risk"]
    total_findings = summary["total_findings"]

    if risk == "critical":
        executive_summary = (
            f"The scan identified {total_findings} findings with an "
            "overall critical risk level. Immediate investigation and "
            "remediation of critical findings is recommended."
        )

    elif risk == "high":
        executive_summary = (
            f"The scan identified {total_findings} findings with an "
            "overall high risk level. High-priority findings should be "
            "reviewed and remediated as soon as possible."
        )

    elif risk == "medium":
        executive_summary = (
            f"The scan identified {total_findings} findings with an "
            "overall medium risk level. Medium-risk findings and "
            "exposed services should be reviewed and remediated."
        )

    elif risk == "low":
        executive_summary = (
            f"The scan identified {total_findings} findings with an "
            "overall low risk level. Review the findings and address "
            "any unnecessary exposed services."
        )

    else:
        executive_summary = (
            f"The scan identified {total_findings} findings with "
            "no significant risk classification."
        )

    # --------------------------------------------------
    # 5. Categorize findings
    # --------------------------------------------------

    critical_findings = []
    high_findings = []
    medium_findings = []
    low_findings = []
    info_findings = []

    for finding in grouped_findings:

        finding_data = {
            "ports": finding["ports"],
            "service": finding["service"],
            "product": finding["product"],
            "severity": finding["severity"],
            "description": finding["description"],
            "cve_id": finding["cve_id"],
            "cvss_score": finding["cvss_score"],
            "remediation": finding["remediation"],
            }

        severity = (finding["severity"] or "info").lower()

    

        if severity == "critical":
            critical_findings.append(finding_data)

        elif severity == "high":
            high_findings.append(finding_data)

        elif severity == "medium":
            medium_findings.append(finding_data)

        elif severity == "low":
            low_findings.append(finding_data)

        else:
            info_findings.append(finding_data)

    # --------------------------------------------------
    # 6. Generate recommendations
    # --------------------------------------------------

    recommendations = []

    if severity_counts["critical"] > 0:
        recommendations.append(
            "Immediately investigate and remediate critical findings."
        )

    if severity_counts["high"] > 0:
        recommendations.append(
            "Prioritize remediation of high-severity vulnerabilities."
        )

    if severity_counts["medium"] > 0:
        recommendations.append(
            "Review medium-risk findings and exposed services."
        )

    if severity_counts["low"] > 0:
        recommendations.append(
            "Review low-severity findings and determine whether "
            "additional hardening is required."
        )

    if severity_counts["info"] > 0:
        recommendations.append(
            "Review informational findings and verify that exposed "
            "services are required."
        )

    if not recommendations:
        recommendations.append(
            "No immediate remediation actions were identified."
        )

    # --------------------------------------------------
    # 7. Return structured report
    # --------------------------------------------------

    return {
        "report_title": "CyberAgiesAI Security Assessment Report",

        "scan": {
            "id": scan.id,
            "target": scan.target,
            "status": scan.status,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
        },

        "executive_summary": executive_summary,

        "risk_assessment": {
            "level": risk,
            "score": summary["risk_score"],
        },

        "severity_breakdown": severity_counts,

        "findings_summary": {
            "total": total_findings,
            "critical": len(critical_findings),
            "high": len(high_findings),
            "medium": len(medium_findings),
            "low": len(low_findings),
            "info": len(info_findings),
        },

        "findings": {
            "critical": critical_findings,
            "high": high_findings,
            "medium": medium_findings,
            "low": low_findings,
            "info": info_findings,
        },

        "recommendations": recommendations,
    }







def generate_scan_report(scan, summary, findings):

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    report_path = reports_dir / f"scan_{scan.id}_report.pdf"

    doc = SimpleDocTemplate(
        str(report_path),
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=20,
        leading=24,
        alignment=TA_CENTER,
        spaceAfter=15
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        spaceBefore=12,
        spaceAfter=8
    )

    normal_style = ParagraphStyle(
        "NormalText",
        parent=styles["Normal"],
        fontSize=9,
        leading=13
    )

    small_style = ParagraphStyle(
        "SmallText",
        parent=styles["Normal"],
        fontSize=8,
        leading=11
    )

    story = []

    # --------------------------------------------------
    # TITLE
    # --------------------------------------------------

    story.append(
        Paragraph(
            "CYBERAGIES AI",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Security Assessment Report",
            heading_style
        )
    )

    story.append(Spacer(1, 10))

    # --------------------------------------------------
    # SCAN INFORMATION
    # --------------------------------------------------

    scan_data = [
        ["Scan ID", str(scan.id)],
        ["Target", str(scan.target)],
        ["Status", str(scan.status).upper()],
        ["Started At", str(scan.started_at)],
        ["Completed At", str(scan.completed_at)]
    ]

    scan_table = Table(
        scan_data,
        colWidths=[120, 360]
    )

    scan_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6)
        ])
    )

    story.append(scan_table)

    # --------------------------------------------------
    # RISK SUMMARY
    # --------------------------------------------------

    story.append(
        Paragraph(
            "Executive Risk Summary",
            heading_style
        )
    )

    risk = summary.get("risk", "info")
    risk_score = summary.get("risk_score", 0)
    total_findings = summary.get("total_findings", 0)

    summary_data = [
        ["Overall Risk", str(risk).upper()],
        ["Risk Score", f"{risk_score}/10"],
        ["Total Findings", str(total_findings)]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[150, 330]
    )

    summary_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7)
        ])
    )

    story.append(summary_table)

    # --------------------------------------------------
    # SEVERITY DISTRIBUTION
    # --------------------------------------------------

    story.append(
        Paragraph(
            "Severity Distribution",
            heading_style
        )
    )

    severity_counts = summary.get(
        "severity_counts",
        {}
    )

    severity_data = [
        ["Severity", "Count"],
        ["Critical", str(severity_counts.get("critical", 0))],
        ["High", str(severity_counts.get("high", 0))],
        ["Medium", str(severity_counts.get("medium", 0))],
        ["Low", str(severity_counts.get("low", 0))],
        ["Info", str(severity_counts.get("info", 0))]
    ]

    severity_table = Table(
        severity_data,
        colWidths=[250, 230]
    )

    severity_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (1, 1), (1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6)
        ])
    )

    story.append(severity_table)

    # --------------------------------------------------
    # FINDINGS
    # --------------------------------------------------

    story.append(
        Paragraph(
            "Security Findings",
            heading_style
        )
    )

    if not findings:

        story.append(
            Paragraph(
                "No findings were identified during the scan.",
                normal_style
            )
        )

    else:

        for index, finding in enumerate(findings, start=1):

            story.append(
                Paragraph(
                    f"Finding {index}",
                    ParagraphStyle(
                        "FindingTitle",
                        parent=styles["Heading3"],
                        fontSize=11,
                        spaceBefore=10,
                        spaceAfter=5
                    )
                )
            )

            finding_data = [
                    ["Ports", ", ".join(map(str, finding["ports"]))],
                    ["Service", str(finding["service"] or "N/A")],
                    ["Product", str(finding["product"] or "N/A")],
                    ["Severity", str(finding["severity"] or "info").upper()],
                    ["CVE", str(finding["cve_id"] or "N/A")],
                    [
                        "CVSS Score",
                        str(
                            finding["cvss_score"]
                            if finding["cvss_score"] is not None
                            else "N/A"
                        )
                    ],
                    ["Description", str(finding["description"] or "N/A")],
                    ["Remediation", str(finding["remediation"] or "N/A")],
                ]

            finding_table = Table(
                finding_data,
                colWidths=[100, 380]
            )

            finding_table.setStyle(
                TableStyle([
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                    ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5)
                ])
            )

            story.append(finding_table)

            # Description

            if finding["description"]:

                story.append(
                    Spacer(1, 5)
                )

                story.append(
                    Paragraph(
                        f"<b>Description:</b> "
                        f"{finding["description"]}",
                        small_style
                    )
                )

            # Remediation

            if finding["remediation"]:

                story.append(
                    Spacer(1, 5)
                )

                story.append(
                    Paragraph(
                        f"<b>Remediation:</b> "
                        f"{finding["remediation"]   }",
                        small_style
                    )
                )

            story.append(
                Spacer(1, 10)
            )

    # --------------------------------------------------
    # FINAL RECOMMENDATION
    # --------------------------------------------------

    story.append(
        Paragraph(
            "Recommended Actions",
            heading_style
        )
    )

    if risk == "critical":

        recommendation = (
            "Immediately investigate and remediate critical "
            "security findings. Restrict exposed services where "
            "possible and apply vendor security updates."
        )

    elif risk == "high":

        recommendation = (
            "Prioritize remediation of high-severity findings "
            "and review exposed network services."
        )

    elif risk == "medium":

        recommendation = (
            "Review medium-risk findings, exposed services, "
            "and available security updates."
        )

    elif risk == "low":

        recommendation = (
            "Review identified findings and perform appropriate "
            "security hardening."
        )

    else:

        recommendation = (
            "No immediate high-risk remediation was identified. "
            "Continue monitoring exposed services."
        )

    story.append(
        Paragraph(
            recommendation,
            normal_style
        )
    )

    # --------------------------------------------------
    # PAGE NUMBER
    # --------------------------------------------------

    def add_page_number(canvas, doc):

        canvas.saveState()

        canvas.setFont(
            "Helvetica",
            8
        )

        canvas.drawString(
            40,
            20,
            "CyberAgies AI - Security Assessment"
        )

        canvas.drawRightString(
            A4[0] - 40,
            20,
            f"Page {doc.page}"
        )

        canvas.restoreState()

    # --------------------------------------------------
    # BUILD PDF
    # --------------------------------------------------

    doc.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number
    )

    return str(report_path)