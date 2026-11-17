from datetime import datetime

from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from app.database import Base


class CVE(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, index=True)

    # ─── CVE Identity ───
    cve_id = Column(String(20), unique=True, nullable=False, index=True)

    # ─── Details ───
    title = Column(String(500), nullable=True)
    description = Column(Text, nullable=True)
    affected_products = Column(Text, nullable=True)
    vendor = Column(String(200), nullable=True)

    # ─── CVSS Scoring ───
    cvss_base_score = Column(Float, nullable=True)
    cvss_vector = Column(String(200), nullable=True)
    cvss_severity = Column(String(20), nullable=True)

    # ─── Exploit Info ───
    exploit_available = Column(String(50), default="unknown")
    patch_available = Column(String(50), default="unknown")
    patch_url = Column(String(1000), nullable=True)

    # ─── Source ───
    source = Column(String(100), nullable=True)  # e.g. NVD, CISA, ZDI, GitHub Advisory
    source_url = Column(String(1000), nullable=True)
    references = Column(Text, nullable=True)

    # ─── Linked Threat ───
    threat_id = Column(Integer, ForeignKey("threats.id"), nullable=True)
    threat = relationship("Threat", back_populates="cves")

    # ─── Enrichment (LLM-extracted fields) ───
    enrichment_data = Column(JSONB, nullable=True)

    # ─── Advisory sent tracking ───
    advisory_sent_at = Column(DateTime, nullable=True)
    advisory_sent_by = Column(String(255), nullable=True)

    # ─── Direct edit tracking ───
    edited_by = Column(String(255), nullable=True)  # email of last analyst who edited directly

    # ─── Timestamps ───
    published_at = Column(DateTime, nullable=True)
    last_modified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<CVE(id={self.id}, cve_id='{self.cve_id}', cvss={self.cvss_base_score})>"