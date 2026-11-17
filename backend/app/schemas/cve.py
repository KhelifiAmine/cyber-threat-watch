from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class CVECreate(BaseModel):
    cve_id: str = Field(..., max_length=20)
    title: Optional[str] = None
    description: Optional[str] = None
    affected_products: Optional[str] = None
    vendor: Optional[str] = None
    cvss_base_score: Optional[float] = Field(default=None, ge=0, le=10)
    cvss_vector: Optional[str] = None
    cvss_severity: Optional[str] = None
    exploit_available: str = "unknown"
    patch_available: str = "unknown"
    patch_url: Optional[str] = None
    source_url: Optional[str] = None
    references: Optional[str] = None
    source: Optional[str] = None
    enrichment_data: Optional[dict] = None
    threat_id: Optional[int] = None
    published_at: Optional[datetime] = None


class CVEUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    affected_products: Optional[str] = None
    vendor: Optional[str] = None
    cvss_base_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cvss_severity: Optional[str] = None
    exploit_available: Optional[str] = None
    patch_available: Optional[str] = None
    patch_url: Optional[str] = None
    source_url: Optional[str] = None
    references: Optional[str] = None
    enrichment_data: Optional[dict] = None
    threat_id: Optional[int] = None


class CVEResponse(BaseModel):
    id: int
    cve_id: str
    title: Optional[str]
    description: Optional[str]
    affected_products: Optional[str]
    vendor: Optional[str]
    cvss_base_score: Optional[float]
    cvss_vector: Optional[str]
    cvss_severity: Optional[str]
    exploit_available: str
    patch_available: str
    patch_url: Optional[str]
    source_url: Optional[str]
    source: Optional[str] = None
    references: Optional[str] = None
    enrichment_data: Optional[dict] = None
    threat_id: Optional[int]
    published_at: Optional[datetime]
    created_at: datetime
    advisory_sent_at: Optional[datetime] = None
    advisory_sent_by: Optional[str] = None
    review_status: Optional[str] = None
    edited_by: Optional[str] = None

    model_config = {"from_attributes": True}