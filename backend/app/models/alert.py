import enum
from datetime import datetime

from sqlalchemy import Column, Integer, String, Text, DateTime, Enum, Boolean, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base


class AlertPriority(str, enum.Enum):
    URGENT = "urgent"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AlertStatus(str, enum.Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)

    # ─── Alert Info ───
    title = Column(String(500), nullable=False)
    message = Column(Text, nullable=False)
    priority = Column(Enum(AlertPriority), default=AlertPriority.MEDIUM, index=True)
    status = Column(Enum(AlertStatus), default=AlertStatus.NEW, index=True)

    # ─── Source ───
    trigger_rule = Column(String(200), nullable=True)
    threat_id = Column(Integer, ForeignKey("threats.id"), nullable=True)
    threat = relationship("Threat", back_populates="alerts")
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="SET NULL"), nullable=True)
    cve = relationship("CVE")

    # ─── Notification ───
    email_sent = Column(Boolean, default=False)
    acknowledged_by = Column(String(100), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)

    # ─── Timestamps ───
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Alert(id={self.id}, title='{self.title[:50]}', priority={self.priority})>"