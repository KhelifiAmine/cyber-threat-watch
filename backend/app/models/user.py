"""
User model - represents platform users with role-based access.
Three roles: ADMIN, ANALYST, CLIENT
"""

import enum
from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, Enum, Boolean

from app.database import Base


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    CLIENT = "client"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    # ─── Identity ───
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(200), nullable=False)
    hashed_password = Column(String(255), nullable=False)

    # ─── Role & Status ───
    role = Column(Enum(UserRole), default=UserRole.ANALYST, nullable=False)
    is_active = Column(Boolean, default=True)

    # ─── Timestamps ───
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<User(id={self.id}, email='{self.email}', role={self.role})>"