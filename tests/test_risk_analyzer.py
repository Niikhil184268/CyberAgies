from backend.app.services.risk_analyzer import calculate_scan_risk


def create_finding(
    severity="info",
    cvss_score=None,
):
    return {
        "severity": severity,
        "cvss_score": cvss_score,
    }


def test_critical_cvss_produces_critical_risk():
    findings = [
        create_finding("critical", 9.8)
    ]

    result = calculate_scan_risk(findings)

    assert result["risk"] == "critical"
    assert result["risk_score"] == 9.8


def test_high_cvss_produces_high_risk():
    findings = [
        create_finding("high", 7.5)
    ]

    result = calculate_scan_risk(findings)

    assert result["risk"] == "high"
    assert result["risk_score"] == 7.5


def test_medium_cvss_produces_medium_risk():
    findings = [
        create_finding("medium", 5.0)
    ]

    result = calculate_scan_risk(findings)

    assert result["risk"] == "medium"
    assert result["risk_score"] == 5.0


def test_low_cvss_produces_low_risk():
    findings = [
        create_finding("low", 2.5)
    ]

    result = calculate_scan_risk(findings)

    assert result["risk"] == "low"
    assert result["risk_score"] == 2.5


def test_highest_cvss_determines_overall_risk():
    findings = [
        create_finding("medium", 5.0),
        create_finding("high", 7.5),
        create_finding("low", 2.0),
    ]

    result = calculate_scan_risk(findings)

    assert result["risk"] == "high"
    assert result["risk_score"] == 7.5


def test_severity_counts_are_correct():
    findings = [
        create_finding("critical", 9.8),
        create_finding("high", 7.5),
        create_finding("medium", 5.0),
        create_finding("medium", 4.5),
        create_finding("low", 2.0),
        create_finding("info", None),
    ]

    result = calculate_scan_risk(findings)

    assert result["severity_counts"] == {
        "critical": 1,
        "high": 1,
        "medium": 2,
        "low": 1,
        "info": 1,
    }


def test_info_findings_without_cvss_produce_info_risk():
    findings = [
        create_finding("info", None),
        create_finding("info", None),
    ]

    result = calculate_scan_risk(findings)

    assert result["risk"] == "info"
    assert result["risk_score"] == 0.0