def group_vulnerabilities(findings):
    """
    Group duplicate vulnerabilities that affect multiple ports.

    Findings with the same CVE are grouped together while
    preserving the affected ports.
    """

    grouped = {}

    for finding in findings:

        # If there is no CVE, keep the finding separate
        if not finding.cve_id:
            key = f"no-cve-{finding.id}"

            grouped[key] = {
                "cve_id": None,
                "cvss_score": finding.cvss_score,
                "severity": finding.severity or "info",
                "description": finding.description,
                "product": finding.product,
                "service": finding.service,
                "ports": [finding.port],
                "remediation": finding.remediation,
            }

            continue

        # Use CVE as the grouping key
        key = finding.cve_id

        if key not in grouped:
            grouped[key] = {
                "cve_id": finding.cve_id,
                "cvss_score": finding.cvss_score,
                "severity": finding.severity or "info",
                "description": finding.description,
                "product": finding.product,
                "service": finding.service,
                "ports": [],
                "remediation": finding.remediation,
            }

        # Add the affected port only once
        if finding.port not in grouped[key]["ports"]:
            grouped[key]["ports"].append(finding.port)

    return list(grouped.values())