from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class NewsArticleCreate(BaseModel):
    title: str
    summary: Optional[str] = None
    description: Optional[str] = None
    url: str
    source: str
    sectors: list[str] = []
    language: Optional[str] = None
    published_at: Optional[datetime] = None


class NewsArticleUpdate(BaseModel):
    title: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    sectors: Optional[list[str]] = None


class NewsArticleResponse(BaseModel):
    id: int
    title: str
    summary: Optional[str]
    description: Optional[str]
    url: str
    source: str
    sectors: list[str]
    language: Optional[str]
    published_at: Optional[datetime]
    scraped_at: datetime
    status: str
    review_status: Optional[str]
    edited_by: Optional[str]
    advisory_sent_at: Optional[datetime]
    advisory_sent_by: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
