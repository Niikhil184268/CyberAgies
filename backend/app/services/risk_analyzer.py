def calculate_severity(port: int, service: str | None) -> str:
    """
    Assign a basic risk level based on the exposed port/service.

    This is a simple classification system.
    An open port does NOT automatically mean a vulnerability.
    """

    high_risk_ports = {
        23,    # Telnet
        445,   # SMB
        3389,  # RDP
    }

    medium_risk_ports = {
        21,    # FTP
        22,    # SSH
        25,    # SMTP
        139,   # NetBIOS
        3306,  # MySQL
        5432,  # PostgreSQL
    }

    if port in high_risk_ports:
        return "high"

    if port in medium_risk_ports:
        return "medium"

    return "info"


def calculate_overall_risk(
    port: int,
    service: str | None,
    cvss_score: float | None = None,
    vulnerability_severity: str | None = None
) -> str:

    port_risk = calculate_severity(port, service)

    severity_levels = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }

    risks = [port_risk]

    if vulnerability_severity:
        risks.append(vulnerability_severity.lower())

    if cvss_score is not None:
        if cvss_score >= 9.0:
            risks.append("critical")
        elif cvss_score >= 7.0:
            risks.append("high")
        elif cvss_score >= 4.0:
            risks.append("medium")
        elif cvss_score > 0:
            risks.append("low")
        else:
            risks.append("info")

    return max(
        risks,
        key=lambda risk: severity_levels.get(risk, 0)
    )


def calculate_scan_risk(findings):
    """
    Calculate overall scan risk using grouped findings.

    The findings passed to this function are dictionaries
    produced by group_vulnerabilities().
    """

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    highest_cvss = 0.0
    highest_severity = "info"

    severity_levels = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }

    for finding in findings:

        severity = (finding.get("severity") or "info").lower()

        if severity not in severity_levels:
            severity = "info"

        severity_counts[severity] += 1

        # Track highest severity
        if severity_levels[severity] > severity_levels[highest_severity]:
            highest_severity = severity

        # Track highest CVSS score
        cvss_score = finding.get("cvss_score")

        if cvss_score is not None:
            if cvss_score > highest_cvss:
                highest_cvss = cvss_score

    # Determine overall risk from highest CVSS
    if highest_cvss >= 9.0:
        risk = "critical"
    elif highest_cvss >= 7.0:
        risk = "high"
    elif highest_cvss >= 4.0:
        risk = "medium"
    elif highest_cvss > 0:
        risk = "low"
    else:
        risk = highest_severity

    return {
        "risk": risk,
        "risk_score": highest_cvss,
        "severity_counts": severity_counts
    }

def generate_recommendation(risk: str, severity_counts: dict) -> str:
    """
    Generate a basic security recommendation
    based on the overall scan risk.
    """

    if risk == "critical":
        return "Immediate investigation and remediation are required."

    if risk == "high":
        return "Review high-priority findings and remediate exposed vulnerabilities."

    if risk == "medium":
        return "Review medium-risk findings and exposed services."

    if risk == "low":
        return "Monitor the identified findings and address low-risk issues."

    return "No significant vulnerabilities were identified."