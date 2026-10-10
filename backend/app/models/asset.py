from sqlalchemy import Column, Integer, String, Text

from backend.app.database import Base


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)

    name = Column(
        String(100),
        nullable=False
    )

    asset_type = Column(
        String(50),
        nullable=False
    )

    target = Column(
        String(255),
        nullable=False
    )

    description = Column(
        Text,
        nullable=True
    )

    status = Column(
        String(50),
        default="active"
    )