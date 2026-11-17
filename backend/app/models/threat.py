import enum
from datetime import datetime

from sqlalchemy import Column, Integer, String, Text, Float, DateTime, Enum, Boolean
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from app.database import Base


class SeverityLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatStatus(str, enum.Enum):
    ACTIVE = "active"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)

    # ─── Core Info ───
    title = Column(String(500), nullable=False, index=True)
    description = Column(Text, nullable=False)
    source = Column(String(200), nullable=False)
    source_url = Column(String(1000), nullable=True)

    # ─── Classification ───
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.MEDIUM, index=True)
    threat_type = Column(String(100), nullable=True)
    ttp_codes = Column(String(500), nullable=True)

    # ─── Risk Scoring ───
    risk_score = Column(Float, default=0.0, index=True)
    confidence = Column(Float, default=0.0)

    # ─── Regional Relevance ───
    regions = Column(String(500), nullable=True)
    is_mena_relevant = Column(Boolean, default=False, index=True)

    # ─── Status ───
    status = Column(Enum(ThreatStatus), default=ThreatStatus.ACTIVE, index=True)

    # ─── Enrichment (LLM-extracted fields) ───
    enrichment_data = Column(JSONB, nullable=True)

    # ─── Advisory sent tracking ───
    advisory_sent_at = Column(DateTime, nullable=True)
    advisory_sent_by = Column(String(255), nullable=True)

    # ─── Direct edit tracking ───
    edited_by = Column(String(255), nullable=True)  # email of last analyst who edited directly

    # ─── Timestamps ───
    published_at = Column(DateTime, nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # ─── Relationships ───
    cves = relationship("CVE", back_populates="threat", lazy="selectin")
    alerts = relationship("Alert", back_populates="threat", lazy="selectin")

    def __repr__(self):
        return f"<Threat(id={self.id}, title='{self.title[:50]}', severity={self.severity})>"

