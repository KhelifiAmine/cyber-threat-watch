import enum
from datetime import datetime

from sqlalchemy import Column, Integer, String, Text, DateTime, Enum as PgEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from app.database import Base


class NewsStatus(str, enum.Enum):
    NEW = "NEW"
    FLAGGED = "FLAGGED"
    REVIEWED = "REVIEWED"
    DISMISSED = "DISMISSED"


class NewsArticle(Base):
    __tablename__ = "news_articles"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(500), nullable=False, index=True)
    summary = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    url = Column(String(1000), unique=True, index=True, nullable=False)  # dedup key
    source = Column(String(100), nullable=False, index=True)
    sectors = Column(JSONB, nullable=False, server_default='[]')
    language = Column(String(10), nullable=True)
    published_at = Column(DateTime, nullable=True, index=True)
    scraped_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = Column(PgEnum(NewsStatus, name="newsstatus", create_type=False), default=NewsStatus.NEW, nullable=False, index=True)
    review_status = Column(String(20), nullable=True, index=True)  # PENDING | APPROVED | REJECTED | null
    flag_note = Column(Text, nullable=True)
    edited_by = Column(String(255), nullable=True)
    advisory_sent_at = Column(DateTime, nullable=True)
    advisory_sent_by = Column(String(255), nullable=True)
    enrichment_data = Column(JSONB, nullable=True)

    proposals = relationship("NewsEnrichmentProposal", back_populates="news", lazy="selectin")

    def __repr__(self):
        return f"<NewsArticle(id={self.id}, title='{self.title[:50]}')>"
