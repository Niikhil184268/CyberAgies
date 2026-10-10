from types import SimpleNamespace

from backend.app.services.finding_group_service import group_vulnerabilities


def create_finding(
    finding_id,
    cve_id,
    port,
    severity="medium",
    cvss_score=5.0,
    description="Test vulnerability",
    product="Test Product",
    service="test-service",
    remediation="Test remediation",
):
    return SimpleNamespace(
        id=finding_id,
        cve_id=cve_id,
        port=port,
        severity=severity,
        cvss_score=cvss_score,
        description=description,
        product=product,
        service=service,
        remediation=remediation,
    )


def test_same_cve_is_grouped_across_ports():
    findings = [
        create_finding(1, "CVE-2009-3707", 902),
        create_finding(2, "CVE-2009-3707", 912),
    ]

    grouped = group_vulnerabilities(findings)

    assert len(grouped) == 1
    assert grouped[0]["cve_id"] == "CVE-2009-3707"
    assert set(grouped[0]["ports"]) == {902, 912}


def test_different_cves_remain_separate():
    findings = [
        create_finding(1, "CVE-2009-3707", 902),
        create_finding(2, "CVE-2009-4811", 902),
    ]

    grouped = group_vulnerabilities(findings)

    assert len(grouped) == 2


def test_same_cve_on_same_port_is_not_duplicated():
    findings = [
        create_finding(1, "CVE-2009-3707", 902),
        create_finding(2, "CVE-2009-3707", 902),
    ]

    grouped = group_vulnerabilities(findings)

    assert len(grouped) == 1
    assert grouped[0]["ports"] == [902]


def test_info_findings_without_cve_remain_separate():
    findings = [
        create_finding(
            1,
            None,
            902,
            severity="info",
            cvss_score=None,
            description="Service information",
        ),
        create_finding(
            2,
            None,
            912,
            severity="info",
            cvss_score=None,
            description="Another service",
        ),
    ]

    grouped = group_vulnerabilities(findings)

    assert len(grouped) == 2