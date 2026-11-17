"""
Authentication API endpoints.
POST /api/auth/register — Create new user (admin only)
POST /api/auth/login — Login and receive JWT token
GET /api/auth/me — Get current user info
"""

import os
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User, UserRole
from app.models.notification import NotificationRecipient, RecipientRole
from app.schemas.user import UserCreate, UserLogin, UserResponse, TokenResponse
from app.services.auth import (
    hash_password, verify_password,
    create_access_token, create_refresh_token,
    decode_access_token, decode_refresh_token,
)
from app.services.audit import log_action
from app.constants import USER_TO_RECIPIENT_ROLE

router = APIRouter()
security = HTTPBearer()

# ─── Login brute-force protection (Redis sliding window) ───
LOGIN_MAX_ATTEMPTS = 10          # per window, per IP
LOGIN_WINDOW_SECONDS = 300       # 5 minutes
LOGIN_LOCKOUT_SECONDS = 900      # 15 min lockout once tripped

try:
    import redis as _redis_lib
    _login_redis = _redis_lib.from_url(
        os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True
    )
except Exception:
    _login_redis = None


def _check_login_rate(request: Request) -> None:
    """Throttle repeated failed logins per client IP. Raises 429 when exceeded."""
    if _login_redis is None:
        return
    ip = (request.client.host if request.client else "unknown")
    key = f"login_fail:{ip}"
    try:
        if _login_redis.get(f"login_lock:{ip}"):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Try again later.",
            )
        count = _login_redis.get(key)
        if count is not None and int(count) >= LOGIN_MAX_ATTEMPTS:
            _login_redis.setex(f"login_lock:{ip}", LOGIN_LOCKOUT_SECONDS, "1")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Try again later.",
            )
    except HTTPException:
        raise
    except Exception:
        return  # never block auth on a Redis hiccup


def _record_login_failure(request: Request) -> None:
    if _login_redis is None:
        return
    ip = (request.client.host if request.client else "unknown")
    key = f"login_fail:{ip}"
    try:
        pipe = _login_redis.pipeline()
        pipe.incr(key)
        pipe.expire(key, LOGIN_WINDOW_SECONDS)
        pipe.execute()
    except Exception:
        pass


def _clear_login_failures(request: Request) -> None:
    if _login_redis is None:
        return
    ip = (request.client.host if request.client else "unknown")
    try:
        _login_redis.delete(f"login_fail:{ip}", f"login_lock:{ip}")
    except Exception:
        pass


# ─── Helper: Get current user from JWT token ───
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Extract and validate the user from the Authorization header.
    Used as a dependency in protected endpoints.
    """
    token = credentials.credentials
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    email = payload.get("sub")
    if email is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return user


# ─── Helper: Require specific roles ───
def require_role(*roles: UserRole):
    """
    Dependency factory that checks if the current user has one of the required roles.
    Usage: Depends(require_role(UserRole.ADMIN))
    """
    async def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role: {', '.join(r.value for r in roles)}",
            )
        return current_user
    return role_checker


# ─── POST /api/auth/register ───
@router.post("/register", response_model=UserResponse, status_code=201)
async def register(
    data: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """
    Register a new user. Only admins can create accounts.
    No open signup — this is a controlled platform.
    """
    # Check if email already exists
    existing = await db.execute(select(User).where(User.email == data.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    user = User(
        email=data.email,
        full_name=data.full_name,
        hashed_password=hash_password(data.password),
        role=data.role,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)

    # Auto-add to notification recipients based on their role
    recipient_role = USER_TO_RECIPIENT_ROLE.get(data.role, RecipientRole.ANALYST)
    existing_recipient = await db.execute(
        select(NotificationRecipient).where(NotificationRecipient.email == data.email)
    )
    if not existing_recipient.scalar_one_or_none():
        recipient = NotificationRecipient(
            email=data.email,
            full_name=data.full_name,
            role=recipient_role,
            is_active=True,
        )
        db.add(recipient)

    await log_action(
        db, current_user.email, current_user.role.value,
        "CREATE_USER", resource_type="user", resource_id=str(user.id),
        details=f"Created user {user.email} with role {user.role.value}"
    )
    return UserResponse.model_validate(user)


# ─── POST /api/auth/login ───
@router.post("/login", response_model=TokenResponse)
async def login(data: UserLogin, request: Request, db: AsyncSession = Depends(get_db)):
    """
    Login with email and password. Returns a JWT token.
    The frontend stores this token and sends it with every request.
    """
    _check_login_rate(request)  # brute-force throttle (per IP)

    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(data.password, user.hashed_password):
        _record_login_failure(request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    _clear_login_failures(request)  # successful auth resets the counter

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact your administrator.",
        )

    # Update last login timestamp
    user.last_login = datetime.utcnow()
    await log_action(db, user.email, user.role.value, "LOGIN", details=f"{user.full_name} logged in")
    await db.flush()

    # Create access + refresh tokens
    access_token = create_access_token(data={"sub": user.email, "role": user.role.value})
    refresh_token = create_refresh_token(data={"sub": user.email})

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        role=user.role.value,
        full_name=user.full_name,
    )


# ─── GET /api/auth/me ───
@router.get("/me", response_model=UserResponse)
async def get_me(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the currently logged-in user's info. CLIENT users get client_profile."""
    from app.services.client_context import get_client_recipient

    resp = UserResponse.model_validate(current_user)
    if current_user.role == UserRole.CLIENT:
        rec = await get_client_recipient(current_user, db)
        if rec:
            resp.client_profile = {
                "recipient_id": rec.id,
                "company": rec.company,
                "interests": rec.interests,
                "inventory_count": len(rec.inventory or []),
            }
    return resp

# ─── POST /api/auth/refresh ───
class RefreshRequest(BaseModel):
    refresh_token: str

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """
    Exchange a valid refresh token for a new access token + refresh token.
    Called automatically by the frontend when a 401 is received.
    """
    payload = decode_refresh_token(body.refresh_token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

    email = payload.get("sub")
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    new_access_token = create_access_token(data={"sub": user.email, "role": user.role.value})
    new_refresh_token = create_refresh_token(data={"sub": user.email})

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        role=user.role.value,
        full_name=user.full_name,
    )