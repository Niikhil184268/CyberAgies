from typing import Optional

from pydantic import BaseModel, Field, ConfigDict


class AssetCreate(BaseModel):
    name: str = Field(
        ...,
        description="The name of the asset"
    )

    asset_type: str = Field(
        ...,
        description="The type or category of the asset"
    )

    target: str = Field(
        ...,
        description="The host, IP address, domain, URL, or other target associated with the asset"
    )

    description: Optional[str] = Field(
        None,
        description="Additional information about the asset"
    )


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    asset_type: Optional[str] = None
    target: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None


class AssetResponse(BaseModel):
    id: int
    name: str
    asset_type: str
    target: str
    description: Optional[str] = None
    status: str

    model_config = ConfigDict(from_attributes=True)