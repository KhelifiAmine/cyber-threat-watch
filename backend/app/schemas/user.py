"""
User schemas - validation for auth and user management endpoints.
"""

from datetime import datetime
from typing import Optional

import re

from pydantic import BaseModel, EmailStr, Field, field_validator


# ─── Registration (admin creates users) ───
class UserCreate(BaseModel):
    email: str = Field(..., max_length=255)
    full_name: str = Field(..., max_length=200)
    password: str = Field(..., min_length=12, max_length=128)
    role: str = "analyst"

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        """Enforce complexity: upper, lower, digit, and symbol; block common values."""
        checks = [
            (r"[a-z]", "a lowercase letter"),
            (r"[A-Z]", "an uppercase letter"),
            (r"\d", "a digit"),
            (r"[^A-Za-z0-9]", "a special character"),
        ]
        missing = [name for pattern, name in checks if not re.search(pattern, v)]
        if missing:
            raise ValueError("Password must contain " + ", ".join(missing) + ".")
        weak = {"password", "admin123!", "analyst123!", "client123!", "changeme123!"}
        if v.lower() in weak:
            raise ValueError("Password is too common/guessable.")
        return v


# ─── Login ───
class UserLogin(BaseModel):
    email: str
    password: str


# ─── What the API returns for a user ───
class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]
    client_profile: Optional[dict] = None

    model_config = {"from_attributes": True}


# ─── JWT Token response ───
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    role: str
    full_name: str


# ─── Update user (admin) ───
class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None