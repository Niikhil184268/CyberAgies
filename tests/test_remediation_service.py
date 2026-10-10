from backend.app.services.remediation_service import get_remediation


def test_telnet_remediation():
    result = get_remediation(
        port=23,
        service="telnet",
        severity="high"
    )

    assert "Disable Telnet" in result
    assert "SSH" in result
    assert "firewall" in result


def test_smb_remediation():
    result = get_remediation(
        port=445,
        service="microsoft-ds",
        severity="high"
    )

    assert "SMB" in result
    assert "SMBv1" in result
    assert "security updates" in result


def test_rdp_remediation():
    result = get_remediation(
        port=3389,
        service="ms-wbt-server",
        severity="high"
    )

    assert "RDP" in result
    assert "VPN" in result
    assert "Network Level Authentication" in result


def test_ftp_remediation():
    result = get_remediation(
        port=21,
        service="ftp",
        severity="medium"
    )

    assert "FTP" in result
    assert "SFTP" in result
    assert "FTPS" in result


def test_ssh_remediation():
    result = get_remediation(
        port=22,
        service="ssh",
        severity="medium"
    )

    assert "SSH" in result
    assert "key-based authentication" in result


def test_smtp_remediation():
    result = get_remediation(
        port=25,
        service="smtp",
        severity="medium"
    )

    assert "SMTP" in result
    assert "authentication" in result
    assert "patched" in result


def test_critical_cve_remediation():
    result = get_remediation(
        port=8080,
        service="http",
        severity="critical",
        cve_id="CVE-2025-1234"
    )

    assert "CVE-2025-1234" in result
    assert "Prioritize remediation" in result
    assert "vendor security update" in result


def test_high_cve_remediation():
    result = get_remediation(
        port=8080,
        service="http",
        severity="high",
        cve_id="CVE-2025-5678"
    )

    assert "CVE-2025-5678" in result
    assert "Prioritize remediation" in result


def test_medium_cve_remediation():
    result = get_remediation(
        port=8080,
        service="http",
        severity="medium",
        cve_id="CVE-2025-9999"
    )

    assert "CVE-2025-9999" in result
    assert "Review" in result
    assert "vendor security update" in result


def test_low_severity_remediation():
    result = get_remediation(
        port=8080,
        service="http",
        severity="low"
    )

    assert "security updates" in result
    assert "configuration hardening" in result


def test_general_remediation():
    result = get_remediation(
        port=8080,
        service="http",
        severity="info"
    )

    assert "exposed service" in result
    assert "properly configured" in result
    assert "up to date" in result


def test_none_values_are_handled():
    result = get_remediation(
        port=8080,
        service=None,
        severity=None,
        cve_id=None
    )

    assert isinstance(result, str)
    assert len(result) > 0