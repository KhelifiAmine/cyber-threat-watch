from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

# Create async engine - this is the connection pool to PostgreSQL
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,  # Log SQL queries in development
    pool_size=20,
    max_overflow=10,
)

# Session factory - creates new database sessions
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# Base class for all database models
class Base(DeclarativeBase):
    pass


async def get_db():
    """
    Dependency that provides a database session to API endpoints.
    FastAPI injects this automatically:
        async def get_threats(db: AsyncSession = Depends(get_db)):
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Create all tables on startup and seed default users if missing."""
    from sqlalchemy import text

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # Idempotent schema nudges for fields added after initial table creation.
        # Safe to run on every startup — ADD COLUMN IF NOT EXISTS is a no-op when
        # the column already exists.
        for stmt in (
            "ALTER TABLE cve_enrichment_proposals ADD COLUMN IF NOT EXISTS origin VARCHAR(20) DEFAULT 'SCRAPER' NOT NULL",
            "ALTER TABLE cve_enrichment_proposals ADD COLUMN IF NOT EXISTS senior_reviewed_by VARCHAR(255)",
            "ALTER TABLE cve_enrichment_proposals ADD COLUMN IF NOT EXISTS senior_reviewed_at TIMESTAMP",
            "ALTER TABLE cve_enrichment_proposals ADD COLUMN IF NOT EXISTS senior_note TEXT",
            "ALTER TABLE cve_enrichment_proposals ADD COLUMN IF NOT EXISTS client_email_sent_at TIMESTAMP",
            "ALTER TABLE threat_enrichment_proposals ADD COLUMN IF NOT EXISTS origin VARCHAR(20) DEFAULT 'SCRAPER' NOT NULL",
            "ALTER TABLE threat_enrichment_proposals ADD COLUMN IF NOT EXISTS senior_reviewed_by VARCHAR(255)",
            "ALTER TABLE threat_enrichment_proposals ADD COLUMN IF NOT EXISTS senior_reviewed_at TIMESTAMP",
            "ALTER TABLE threat_enrichment_proposals ADD COLUMN IF NOT EXISTS senior_note TEXT",
            "ALTER TABLE threat_enrichment_proposals ADD COLUMN IF NOT EXISTS client_email_sent_at TIMESTAMP",
            "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS event_metadata JSONB",
            # Persist each run's filtered log so historical runs can replay in the UI
            "ALTER TABLE spider_runs ADD COLUMN IF NOT EXISTS log TEXT",
            "ALTER TABLE cves ADD COLUMN IF NOT EXISTS edited_by VARCHAR(255)",
            "ALTER TABLE cves ADD COLUMN IF NOT EXISTS source VARCHAR(100)",
            "ALTER TABLE threats ADD COLUMN IF NOT EXISTS edited_by VARCHAR(255)",
            "ALTER TABLE notification_recipients ADD COLUMN IF NOT EXISTS company VARCHAR(255)",
            "ALTER TABLE notification_recipients ADD COLUMN IF NOT EXISTS interests JSONB DEFAULT '[]'::jsonb",
            # Clients don't need a platform account — drop the FK that enforced user registration
            "ALTER TABLE notification_recipients DROP CONSTRAINT IF EXISTS fk_recipient_user_email",
            # Client inventory columns
            "ALTER TABLE notification_recipients ADD COLUMN IF NOT EXISTS inventory JSONB DEFAULT '[]'::jsonb",
            "ALTER TABLE notification_recipients ADD COLUMN IF NOT EXISTS vendors TEXT[] DEFAULT '{}'",
            # Client matching columns on proposals
            "ALTER TABLE cve_enrichment_proposals ADD COLUMN IF NOT EXISTS client_matches JSONB DEFAULT '[]'::jsonb",
            "ALTER TABLE threat_enrichment_proposals ADD COLUMN IF NOT EXISTS client_matches JSONB DEFAULT '[]'::jsonb",
            # Advisory sent tracking on source records
            "ALTER TABLE cves ADD COLUMN IF NOT EXISTS advisory_sent_at TIMESTAMP",
            "ALTER TABLE cves ADD COLUMN IF NOT EXISTS advisory_sent_by VARCHAR(255)",
            "ALTER TABLE threats ADD COLUMN IF NOT EXISTS advisory_sent_at TIMESTAMP",
            "ALTER TABLE threats ADD COLUMN IF NOT EXISTS advisory_sent_by VARCHAR(255)",
            # Enrichment data for news articles
            "ALTER TABLE news_articles ADD COLUMN IF NOT EXISTS enrichment_data JSONB",
            # Promote any stale REVIEWED proposals to APPROVED (senior tier removed)
            "UPDATE cve_enrichment_proposals SET status = 'APPROVED' WHERE status = 'REVIEWED'",
            "UPDATE threat_enrichment_proposals SET status = 'APPROVED' WHERE status = 'REVIEWED'",
        ):
            await conn.execute(text(stmt))

    # Seed default users if the users table is empty
    from app.models.user import User, UserRole
    from app.services.auth import hash_password
    from sqlalchemy import select, func

    async with AsyncSessionLocal() as session:
        count = (await session.execute(select(func.count(User.id)))).scalar()
        if count == 0:
            env = settings.ENVIRONMENT.lower()
            if env in ("development", "dev", "test", "local"):
                # Development-only convenience accounts with random passwords, printed once.
                # NEVER seeded outside development.
                import secrets
                dev_accounts = [
                    ("admin@example.com", "Admin", UserRole.ADMIN),
                    ("analyst@example.com", "Analyst", UserRole.ANALYST),
                    ("client@example.com", "Client", UserRole.CLIENT),
                ]
                seed_users = []
                for email, name, role in dev_accounts:
                    password = secrets.token_urlsafe(12)
                    seed_users.append(User(email=email, full_name=name, hashed_password=hash_password(password), role=role))
                    print(f"[CyberShield] Dev account {email} / {password}")
                session.add_all(seed_users)
                await session.commit()
                print("[CyberShield] Seeded 3 DEVELOPMENT users (dev only — not created in production)")
            elif settings.INITIAL_ADMIN_EMAIL and settings.INITIAL_ADMIN_PASSWORD:
                session.add(User(
                    email=settings.INITIAL_ADMIN_EMAIL,
                    full_name="Administrator",
                    hashed_password=hash_password(settings.INITIAL_ADMIN_PASSWORD),
                    role=UserRole.ADMIN,
                ))
                await session.commit()
                print(f"[CyberShield] Seeded initial admin: {settings.INITIAL_ADMIN_EMAIL}")
            else:
                print("[CyberShield] No users found and no INITIAL_ADMIN_* configured — "
                      "create the first admin with: python scripts/create_admin.py")

