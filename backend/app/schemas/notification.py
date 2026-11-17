"""
Notification Schemas — Request/response models for recipient management API.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, field_validator


class RecipientCreate(BaseModel):
    # Clients are companies, not individuals: the company name is the required
    # identity. An optional contact person name may still be provided.
    email: EmailStr
    company: str
    full_name: Optional[str] = None
    role: str  # analyst, client, not_concerned
    interests: Optional[list[str]] = None

    @field_validator("role")
    @classmethod
    def validate_role(cls, v):
        allowed = ["analyst", "client", "not_concerned"]
        if v.lower() not in allowed:
            raise ValueError(f"Role must be one of: {', '.join(allowed)}")
        return v.lower()

    @field_validator("company")
    @classmethod
    def validate_company(cls, v):
        if not v or len(v.strip()) < 2:
            raise ValueError("Company name must be at least 2 characters")
        if len(v) > 255:
            raise ValueError("Company name must be under 255 characters")
        return v.strip()

    @field_validator("full_name")
    @classmethod
    def validate_name(cls, v):
        if v is None:
            return None
        v = v.strip()
        return v or None


class RecipientUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    company: Optional[str] = None
    role: Optional[str] = None
    interests: Optional[list[str]] = None
    is_active: Optional[bool] = None

    @field_validator("role")
    @classmethod
    def validate_role(cls, v):
        if v is None:
            return v
        allowed = ["analyst", "client", "not_concerned"]
        if v.lower() not in allowed:
            raise ValueError(f"Role must be one of: {', '.join(allowed)}")
        return v.lower()


class RecipientResponse(BaseModel):
    id: int
    email: str
    full_name: str
    company: Optional[str] = None
    role: str
    interests: Optional[list[str]] = None
    inventory: Optional[list[dict]] = None
    vendors: Optional[list[str]] = None
    regions: Optional[list[str]] = None
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class RecipientListResponse(BaseModel):
    recipients: list[RecipientResponse]
    total: int


class TestEmailRequest(BaseModel):
    recipient_email: EmailStr
    message: str = "This is a test email from Cyber Threat Watch notification system."
