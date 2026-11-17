from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Index, Text
from sqlalchemy.dialects.postgresql import JSONB

from app.database import Base


class ThreatEnrichmentProposal(Base):
    __tablename__ = "threat_enrichment_proposals"

    id = Column(Integer, primary_key=True, index=True)

    threat_id = Column(Integer, ForeignKey("threats.id"), nullable=False, index=True)
    source = Column(String(100), nullable=False)
    origin = Column(String(20), default="SCRAPER", nullable=False)

    proposed_fields = Column(JSONB, nullable=False)

    # Lifecycle: PENDING -> APPROVED / REJECTED
    status = Column(String(20), default="PENDING", nullable=False, index=True)

    reviewed_by = Column(String(255), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    applied_fields = Column(JSONB, nullable=True)
    flag_note = Column(Text, nullable=True)  # note from analyst when manually flagging
    client_email_sent_at = Column(DateTime, nullable=True)
    client_matches = Column(JSONB, nullable=True, default=list)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index(
            "ix_threat_proposals_unique_pending",
            "threat_id", "source",
            unique=True,
            postgresql_where=(status == "PENDING"),
        ),
    )

    def __repr__(self):
        return f"<ThreatProposal(id={self.id}, threat={self.threat_id}, src={self.source}, status={self.status})>"
