"""
Cyber Threat Watch - Main Application Entry Point
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db
from app.api import api_router


async def _sync_recipient_roles():
    """Ensure notification_recipients roles match users table roles on startup."""
    try:
        from sqlalchemy import select, update
        from app.database import AsyncSessionLocal
        from app.models.user import User, UserRole
        from app.models.notification import NotificationRecipient, RecipientRole
        from app.constants import USER_TO_RECIPIENT_ROLE

        async with AsyncSessionLocal() as db:
            users = (await db.execute(select(User))).scalars().all()
            for u in users:
                expected_role = USER_TO_RECIPIENT_ROLE.get(u.role, RecipientRole.ANALYST)
                res = await db.execute(
                    select(NotificationRecipient).where(NotificationRecipient.email == u.email)
                )
                recipient = res.scalar_one_or_none()
                if recipient and recipient.role != expected_role:
                    # Never overwrite NOT_CONCERNED — that's an explicit user opt-out
                    if recipient.role == RecipientRole.NOT_CONCERNED:
                        continue
                    recipient.role = expected_role
                    print(f"[Sync] Updated {u.email} recipient role to {expected_role.value}")
            await db.commit()
    except Exception as e:
        print(f"[Sync] Recipient role sync failed (non-fatal): {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Runs on startup and shutdown."""
    print(f"[CyberShield] Starting {settings.APP_NAME}...")
    await init_db()
    await _sync_recipient_roles()
    print(f"[CyberShield] API ready at http://localhost:8000/docs")
    yield
    print(f"[CyberShield] Shutting down...")


_IS_PROD = settings.ENVIRONMENT.lower() in ("production", "prod")

# Fail fast if a placeholder/weak signing secret is used in production.
_WEAK_SECRETS = {
    "change-me-in-production",
    "your-super-secret-key-change-in-production",
    "your-secret-key", "secret", "changeme", "",
}
if _IS_PROD and settings.SECRET_KEY in _WEAK_SECRETS:
    raise RuntimeError(
        "SECRET_KEY is a known placeholder/weak value. Set a strong random secret "
        "(e.g. `python -c \"import secrets; print(secrets.token_urlsafe(64))\"`) before production."
    )

# ─── Create FastAPI Application ───
app = FastAPI(
    title="Cyber Threat Watch",
    description="Cybersecurity platform for threat monitoring and vulnerability management",
    version="0.1.0",
    lifespan=lifespan,
    # Interactive docs / schema are disabled in production to reduce recon surface.
    docs_url=None if _IS_PROD else "/docs",
    redoc_url=None if _IS_PROD else "/redoc",
    openapi_url=None if _IS_PROD else "/openapi.json",
)

# ─── CORS (allow frontend to talk to backend) ───
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


# ─── Security response headers (defense-in-depth) ───
@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if _IS_PROD:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if "server" in response.headers:
        del response.headers["server"]
    return response

# ─── Register all API routes ───
app.include_router(api_router)


# ─── Health check endpoint ───
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": "0.1.0",
        "environment": settings.ENVIRONMENT,
    }