"""
Audit log model — records every significant action taken by any user.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.dialects.postgresql import JSONB
from app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    # Who
    user_email = Column(String(255), nullable=False, index=True)
    user_role = Column(String(50), nullable=False)

    # What
    action = Column(String(100), nullable=False, index=True)   # e.g. LOGIN, CREATE_THREAT, DELETE_USER
    resource_type = Column(String(50), nullable=True)          # e.g. threat, cve, alert, user
    resource_id = Column(String(100), nullable=True)           # e.g. "42" or "CVE-2024-1234"
    details = Column(Text, nullable=True)                      # human-readable summary
    event_metadata = Column(JSONB, nullable=True)               # structured payload for programmatic queries

    # Context
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f"<AuditLog(id={self.id}, user={self.user_email}, action={self.action})>"
