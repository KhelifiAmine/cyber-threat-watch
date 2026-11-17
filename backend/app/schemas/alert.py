from datetime import datetime
from typing import Optional, Any

from pydantic import BaseModel, Field


class AlertCreate(BaseModel):
    title: str = Field(..., max_length=500)
    message: str
    priority: str = "medium"
    trigger_rule: Optional[str] = None
    threat_id: Optional[int] = None
    cve_id: Optional[int] = None


class AlertUpdate(BaseModel):
    status: Optional[str] = None
    acknowledged_by: Optional[str] = None


class AlertResponse(BaseModel):
    id: int
    title: str
    message: str
    priority: str
    status: str
    trigger_rule: Optional[str]
    threat_id: Optional[int]
    cve_id: Optional[int] = None
    email_sent: bool
    acknowledged_by: Optional[str]
    acknowledged_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    # Enrichment — joined from linked threat or CVE
    source_label: Optional[str] = None
    source_url: Optional[str] = None
    cve_ref: Optional[str] = None
    cvss_score: Optional[float] = None
    risk_score: Optional[float] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    enrichment_data: Optional[dict[str, Any]] = None

    model_config = {"from_attributes": True}