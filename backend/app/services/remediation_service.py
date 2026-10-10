def get_remediation(
    port: int,
    service: str | None,
    severity: str | None,
    cve_id: str | None = None
) -> str:

    """
    Generate a basic remediation recommendation
    based on the exposed service/port and vulnerability severity.
    """

    service = (service or "").lower()
    severity = (severity or "info").lower()

    # High-risk services
    if port == 23 or service == "telnet":
        return (
            "Disable Telnet and migrate to SSH. "
            "Restrict remote access using firewall rules."
        )

    if port == 445 or service in ["microsoft-ds", "smb"]:
        return (
            "Restrict SMB access to trusted hosts, "
            "disable SMBv1 if enabled, and apply the latest security updates."
        )

    if port == 3389 or service in ["ms-wbt-server", "rdp"]:
        return (
            "Restrict RDP access to trusted networks or VPN, "
            "enable Network Level Authentication, and apply security updates."
        )

    # Medium-risk services
    if port == 21 or service == "ftp":
        return (
            "Avoid unencrypted FTP where possible. "
            "Use SFTP or FTPS and restrict access with firewall rules."
        )

    if port == 22 or service == "ssh":
        return (
            "Restrict SSH access to trusted hosts, "
            "disable password authentication where possible, "
            "and use key-based authentication."
        )

    if port == 25 or service == "smtp":
        return (
            "Restrict SMTP access, require authentication where appropriate, "
            "and ensure the mail service is fully patched."
        )

    # Vulnerability-based recommendation
    if cve_id and severity in ["critical", "high"]:
        return (
            f"Prioritize remediation of {cve_id}. "
            "Apply the vendor security update or upgrade to a patched version."
        )

    if cve_id and severity == "medium":
        return (
            f"Review {cve_id} and apply the vendor security update "
            "or upgrade to a patched version."
        )

    # General recommendation
    if severity == "low":
        return (
            "Review the finding and apply available security updates "
            "or configuration hardening."
        )

    return (
        "Review the exposed service and ensure it is required, "
        "properly configured, and up to date."
    )