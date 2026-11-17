"""
Create an administrator account (production bootstrap).

In production the application does NOT seed default credentials. Use this script
to create the first admin, then log in and manage further users via the UI/API.

Usage (inside the backend container or a configured environment):
    python scripts/create_admin.py <email> <password>

If no arguments are given, INITIAL_ADMIN_EMAIL / INITIAL_ADMIN_PASSWORD from the
environment are used.
"""
import asyncio
import sys

from sqlalchemy import select

from app.config import settings
from app.database import AsyncSessionLocal
from app.models.user import User, UserRole
from app.services.auth import hash_password


async def main() -> int:
    email = sys.argv[1] if len(sys.argv) > 1 else settings.INITIAL_ADMIN_EMAIL
    password = sys.argv[2] if len(sys.argv) > 2 else settings.INITIAL_ADMIN_PASSWORD

    if not email or not password:
        print("Usage: python scripts/create_admin.py <email> <password>")
        return 1
    if len(password) < 12:
        print("Refused: password must be at least 12 characters.")
        return 1

    async with AsyncSessionLocal() as session:
        existing = (
            await session.execute(select(User).where(User.email == email))
        ).scalar_one_or_none()
        if existing:
            print(f"User {email!r} already exists — no change.")
            return 0
        session.add(User(
            email=email,
            full_name="Administrator",
            hashed_password=hash_password(password),
            role=UserRole.ADMIN,
        ))
        await session.commit()
        print(f"Created admin account: {email}")
        return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
