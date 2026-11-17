from datetime import datetime

from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from app.database import Base


class NewsEnrichmentProposal(Base):
    __tablename__ = "news_enrichment_proposals"

    id = Column(Integer, primary_key=True, index=True)
    news_id = Column(Integer, ForeignKey("news_articles.id", ondelete="CASCADE"), nullable=False, index=True)
    news = relationship("NewsArticle", back_populates="proposals")
    source = Column(String(100), nullable=False)
    origin = Column(String(20), nullable=False, default="SCRAPER")  # SCRAPER | MANUAL
    proposed_fields = Column(JSONB, nullable=False, default={})
    status = Column(String(20), nullable=False, default="PENDING", index=True)
    reviewed_by = Column(String(255), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    applied_fields = Column(JSONB, nullable=True, default={})
    flag_note = Column(Text, nullable=True)
    client_email_sent_at = Column(DateTime, nullable=True)
    client_matches = Column(JSONB, nullable=False, server_default='[]')
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<NewsEnrichmentProposal(id={self.id}, news_id={self.news_id}, status='{self.status}')>"
