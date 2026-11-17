from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ─── What the API accepts when creating a threat ───
class ThreatCreate(BaseModel):
    title: str = Field(..., max_length=500)
    description: str
    source: str = Field(..., max_length=200)
    source_url: Optional[str] = None
    severity: str = "medium"
    threat_type: Optional[str] = None
    ttp_codes: Optional[str] = None
    risk_score: float = Field(default=0.0, ge=0, le=100)
    confidence: float = Field(default=0.0, ge=0, le=1)
    regions: Optional[str] = None
    is_mena_relevant: bool = False
    enrichment_data: Optional[dict] = None
    published_at: Optional[datetime] = None


# ─── What the API accepts when updating a threat ───
class ThreatUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    threat_type: Optional[str] = None
    ttp_codes: Optional[str] = None
    risk_score: Optional[float] = None
    regions: Optional[str] = None
    is_mena_relevant: Optional[bool] = None
    source_url: Optional[str] = None
    enrichment_data: Optional[dict] = None


# ─── What the API returns for a single threat ───
class ThreatResponse(BaseModel):
    id: int
    title: str
    description: str
    source: str
    source_url: Optional[str]
    severity: str
    threat_type: Optional[str]
    ttp_codes: Optional[str]
    risk_score: float
    confidence: float
    regions: Optional[str]
    is_mena_relevant: bool
    status: str
    published_at: Optional[datetime]
    discovered_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    enrichment_data: Optional[dict] = None
    advisory_sent_at: Optional[datetime] = None
    advisory_sent_by: Optional[str] = None
    review_status: Optional[str] = None
    edited_by: Optional[str] = None

    model_config = {"from_attributes": True}


# ─── Paginated list response ───
class ThreatListResponse(BaseModel):
    items: list[ThreatResponse]
    total: int
    page: int
    per_page: int
    pages: int