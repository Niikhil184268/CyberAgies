from backend.app.services.remediation_service import get_remediation


print(
    get_remediation(
        port=23,
        service="telnet",
        severity="high"
    )
)

print()

print(
    get_remediation(
        port=902,
        service="vmware-auth",
        severity="medium",
        cve_id="CVE-2009-3707"
    )
)

print()

print(
    get_remediation(
        port=8000,
        service="http-alt",
        severity="info"
    )
)