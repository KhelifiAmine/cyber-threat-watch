"""
Admin API endpoints — ADMIN role only.
Manage users: list, update roles, activate/deactivate accounts.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User, UserRole
from app.models.notification import NotificationRecipient, RecipientRole
from app.schemas.user import UserResponse, UserUpdate
from app.api.auth import require_role
from app.services.audit import log_action
from app.constants import USER_TO_RECIPIENT_ROLE

router = APIRouter()


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    role: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    query = select(User)
    if role:
        query = query.where(User.role == role)
    query = query.order_by(User.created_at.desc())
    query = query.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    users = result.scalars().all()
    return [UserResponse.model_validate(u) for u in users]


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse.model_validate(user)


@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    data: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == current_user.id and data.is_active is False:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    changes = []
    if data.full_name is not None:
        changes.append(f"name→{data.full_name}")
        user.full_name = data.full_name
    if data.role is not None:
        changes.append(f"role→{data.role}")
        user.role = data.role
        # Sync notification recipient role so the user immediately appears
        # in the correct tier (client vs analyst alerts) without a re-register.
        new_rec_role = USER_TO_RECIPIENT_ROLE.get(data.role, RecipientRole.ANALYST)
        rec_result = await db.execute(
            select(NotificationRecipient).where(NotificationRecipient.email == user.email)
        )
        recipient = rec_result.scalar_one_or_none()
        if recipient:
            recipient.role = new_rec_role
        else:
            # Recipient row missing (e.g. user predates auto-sync) — create it now
            db.add(NotificationRecipient(
                email=user.email,
                full_name=user.full_name,
                role=new_rec_role,
                is_active=user.is_active,
            ))
    if data.is_active is not None:
        changes.append("activated" if data.is_active else "deactivated")
        user.is_active = data.is_active

    if changes:
        await log_action(
            db, current_user.email, current_user.role.value,
            "UPDATE_USER", resource_type="user", resource_id=str(user_id),
            details=f"Updated {user.email}: {', '.join(changes)}"
        )

    await db.flush()
    await db.refresh(user)
    return UserResponse.model_validate(user)


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    await log_action(
        db, current_user.email, current_user.role.value,
        "DELETE_USER", resource_type="user", resource_id=str(user_id),
        details=f"Deleted user {user.email} ({user.role.value})"
    )

    # Remove linked notification recipient so no orphaned records remain
    rec_result = await db.execute(
        select(NotificationRecipient).where(NotificationRecipient.email == user.email)
    )
    recipient = rec_result.scalar_one_or_none()
    if recipient:
        await db.delete(recipient)

    await db.delete(user)
    await db.flush()
