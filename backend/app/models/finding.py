from sqlalchemy import Column, ForeignKey, Integer, String, Text, Float

from backend.app.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    scan_id = Column(
        Integer,
        ForeignKey("scans.id"),
        nullable=False
    )

    port = Column(
        Integer,
        nullable=True
    )

    protocol = Column(
        String(20),
        nullable=True
    )

    state = Column(
        String(50),
        nullable=True
    )

    service = Column(
        String(100),
        nullable=True
    )

    product = Column(
        String(255),
        nullable=True
    )

    version = Column(
        String(100),
        nullable=True
    )

    severity = Column(
        String(20),
        default="info",
        nullable=False
    )

    description = Column(
        Text,
        nullable=True
    )

    remediation = Column(
    Text,
    nullable=True
    )

    cve_id = Column(
    String(30),
    nullable=True
    )

    cvss_score = Column(
    Float,
    nullable=True
    )

    cve_description = Column(
    Text,
    nullable=True
    )