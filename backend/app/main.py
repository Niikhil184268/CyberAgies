from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi.responses import FileResponse

from backend.app.database import Base, engine, get_db
from backend.app.models.asset import Asset
from backend.app.models.scan import Scan
from backend.app.models.finding import Finding
from backend.app.services.remediation_service import get_remediation
from backend.app.services.report_service import(
     generate_security_report,
     generate_scan_report                                           )
from backend.app.services.scan_summary_service import generate_scan_summary
from backend.app.scanners.nmap_scanner import scan_target
from backend.app.schemas.finding import FindingResponse
from backend.app.schemas.scan_summary import ScanSummaryResponse 
from backend.app.services.finding_group_service import group_vulnerabilities






from backend.app.services.vulnerability_service import (
    lookup_vulnerabilities,
    severity_from_cvss
)

from backend.app.schemas.asset import (
    AssetCreate,
    AssetUpdate,
    AssetResponse
)

from backend.app.schemas.scan import (
    ScanCreate,
    ScanResponse
)

from backend.app.services.risk_analyzer import (
    calculate_severity,
    calculate_overall_risk,
    calculate_scan_risk,
    generate_recommendation
)

# Create database tables
Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="CyberAgis AI",
    description="AI-powered cybersecurity risk assessment platform",
    version="0.1.0"
)





# ALL THE GET POST IS HERE
@app.get("/")
def root():
    return {
        "project": "CyberAgis AI",
        "status": "online",
        "message": "CyberAgis AI backend is running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }

@app.get(
    "/assets",
    response_model=list[AssetResponse]
)
def get_assets(db: Session = Depends(get_db)):
    assets = db.query(Asset).all()

    return assets


@app.get(
    "/assets/{asset_id}",
    response_model=AssetResponse
)
def get_asset(
    asset_id: int,
    db: Session = Depends(get_db)
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()

    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )

    return asset

@app.get(
    "/scans/{scan_id}/findings",
    response_model=list[FindingResponse]
)
def get_scan_findings(
    scan_id: int,
    db: Session = Depends(get_db)
):
    findings = db.query(Finding).filter(
        Finding.scan_id == scan_id
    ).all()

    return findings

@app.get(
    "/scans/{scan_id}/summary",
    response_model=ScanSummaryResponse
)
def get_scan_summary(
    scan_id: int,
    db: Session = Depends(get_db)
):
    return generate_scan_summary(scan_id, db)



@app.get("/scans/{scan_id}/report")
def get_scan_report(
    scan_id: int,
    db: Session = Depends(get_db)
):
    # Find the scan
    scan = db.query(Scan).filter(
        Scan.id == scan_id
    ).first()

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    # Get findings
    findings = db.query(Finding).filter(
        Finding.scan_id == scan_id
    ).all()

    # Group duplicate vulnerabilities
    grouped_findings = group_vulnerabilities(findings)  

    # Generate summary using your existing function
    summary = generate_scan_summary(
        scan_id,
        db
    )

    # Generate PDF
    report_path = generate_scan_report(
        scan,
        summary,
        grouped_findings
    )

    # Return PDF
    return FileResponse(
        report_path,
        media_type="application/pdf",
        filename=f"scan_{scan_id}_report.pdf"
    )



@app.get("/scans/{scan_id}/risk")
def get_scan_risk(
    scan_id: int,
    db: Session = Depends(get_db)
):
    findings = db.query(Finding).filter(
        Finding.scan_id == scan_id
    ).all()

    # Group duplicate vulnerabilities
    grouped_findings = group_vulnerabilities(findings)

    risk_result = calculate_scan_risk(grouped_findings)

    recommendation = generate_recommendation(
        risk_result["risk"],
        risk_result["severity_counts"]
    )

    return {
        "scan_id": scan_id,
        "risk": risk_result["risk"],
        "risk_score": risk_result["risk_score"],
        "total_findings": len(grouped_findings),
        "severity_counts": risk_result["severity_counts"],
        "recommendation": recommendation
    }





# ALL THE POST IS HERE
@app.post(
    "/assets",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED
)
def create_asset(
    asset: AssetCreate,
    db: Session = Depends(get_db)
):
    db_asset = Asset(
        name=asset.name,
        asset_type=asset.asset_type,
        target=asset.target,
        description=asset.description
    )

    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)

    return db_asset

@app.post(
    "/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED
)
def create_scan(
    scan_data: ScanCreate,
    db: Session = Depends(get_db)
):
    asset = db.query(Asset).filter(
        Asset.id == scan_data.asset_id
    ).first()

    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )

    if scan_data.target != asset.target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan target does not match asset target"
        )

    db_scan = Scan(
        asset_id=scan_data.asset_id,
        target=scan_data.target,
        status="pending"
    )

    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    return db_scan

@app.post(
    "/assets/{asset_id}/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED
)
def scan_asset(
    asset_id: int,
    db: Session = Depends(get_db)
):
    # Find the asset
    asset = db.query(Asset).filter(
        Asset.id == asset_id
    ).first()

    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )

    # Create scan record
    scan = Scan(
        asset_id=asset.id,
        target=asset.target,
        status="running",
        started_at=datetime.utcnow()
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        # Run Nmap against the asset target
        result = scan_target(asset.target)

        if result is None:
            scan.status = "failed"
            scan.completed_at = datetime.utcnow()

            db.commit()
            db.refresh(scan)

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Nmap scan failed"
            )

        # Store each discovered port as a Finding
        for port_data in result["ports"]:

            vulnerabilities = []

            product = port_data.get("product")
            version = port_data.get("version")

            if product and version:
                vulnerabilities = lookup_vulnerabilities(
                    product,
                    version
                )

            if vulnerabilities:

                for vulnerability in vulnerabilities:
                    finding_severity = (
                    vulnerability.get("severity")
                    or severity_from_cvss(vulnerability.get("cvss_score"))
                    )

                    remediation = get_remediation(
                    port=port_data["port"],
                    service=port_data.get("service"),
                    severity=finding_severity,
                    cve_id=vulnerability.get("cve_id")
                    )
                
                    finding = Finding(
                        scan_id=scan.id,
                        port=port_data["port"],
                        protocol=port_data["protocol"],
                        state=port_data["state"],
                        service=port_data["service"],
                        product=port_data["product"],
                        version=port_data["version"],
                        severity=calculate_overall_risk(
                            port=port_data["port"],
                            service=port_data["service"],
                            cvss_score=vulnerability.get("cvss_score"),
                            vulnerability_severity=(
                                vulnerability.get("severity")
                                or severity_from_cvss(vulnerability.get("cvss_score"))
                                    )
                            ),
                        description=vulnerability.get("description"),
                        cve_id=vulnerability.get("cve_id"),
                        cvss_score=vulnerability.get("cvss_score"),
                        remediation=remediation
                    )

                    db.add(finding)

            else:
            
                finding = Finding(
                    scan_id=scan.id,
                    port=port_data["port"],
                    protocol=port_data["protocol"],
                    state=port_data["state"],
                    service=port_data["service"],
                    product=port_data["product"],
                    version=port_data["version"],
                    severity="info",
                    description="Port discovered by Nmap"
                )

                db.add(finding)

        # Mark scan as completed
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()

        db.commit()
        db.refresh(scan)

        return scan

    except HTTPException:
        raise

    except Exception as error:
        db.rollback()

        scan.status = "failed"
        scan.completed_at = datetime.utcnow()

        db.commit()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {str(error)}"
        )





# ALL THE PUT ENDPOINT IS HERE
@app.put(
    "/assets/{asset_id}",
    response_model=AssetResponse
)
def update_asset(
    asset_id: int,
    asset_data: AssetUpdate,
    db: Session = Depends(get_db)
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()

    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )

    if asset_data.name is not None:
        asset.name = asset_data.name

    if asset_data.asset_type is not None:
        asset.asset_type = asset_data.asset_type

    if asset_data.target is not None:
        asset.target = asset_data.target

    if asset_data.description is not None:
        asset.description = asset_data.description

    if asset_data.status is not None:
        asset.status = asset_data.status

    db.commit()
    db.refresh(asset)

    return asset





# ALL THE DELETE ENDPOINT IS HERE
@app.delete("/assets/{asset_id}")
def delete_asset(
    asset_id: int,
    db: Session = Depends(get_db)
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()

    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )

    db.delete(asset)
    db.commit()

    return {
        "message": "Asset deleted successfully",
        "asset_id": asset_id
    }



