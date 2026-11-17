"""
Notification Recipients — Database model for email alert recipients.

Recipients are assigned a role that determines which alerts they receive:
  - ANALYST: receives ALL threat alerts regardless of severity (their job)
  - CLIENT: receives CRITICAL/URGENT alerts only (need-to-know basis)

ADMINs build and maintain the platform — they do not receive alert emails.
Recipients are managed by ADMIN users via the /api/notifications/recipients endpoints.
"""

import enum
from datetime import datetime

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum
from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from sqlalchemy import Text

from app.database import Base


class RecipientRole(str, enum.Enum):
    ANALYST = "analyst"
    CLIENT = "client"
    NOT_CONCERNED = "not_concerned"  # Opted out — stays on list but receives no emails


class NotificationRecipient(Base):
    __tablename__ = "notification_recipients"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=False)
    company = Column(String(255), nullable=True)
    role = Column(Enum(RecipientRole), nullable=False, index=True)
    interests = Column(JSONB, nullable=True, default=list)
    inventory = Column(JSONB, nullable=True, default=list)
    vendors = Column(ARRAY(Text), nullable=True, default=list)
    regions = Column(JSONB, nullable=True, default=list)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<NotificationRecipient(email='{self.email}', role={self.role}, active={self.is_active})>"