from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String

from backend.app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    asset_id = Column(
        Integer,
        ForeignKey("assets.id"),
        nullable=False
    )

    target = Column(
        String(255),
        nullable=False
    )

    status = Column(
        String(50),
        default="pending"
    )

    started_at = Column(
        DateTime,
        nullable=True
    )

    completed_at = Column(
        DateTime,
        nullable=True
    )