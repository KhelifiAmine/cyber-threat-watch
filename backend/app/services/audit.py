"""
Audit logging helper — call this from any endpoint to record user actions.
"""

from sqlalchemy.ext.asyncio import AsyncSession
from app.models.audit_log import AuditLog


async def log_action(
    db: AsyncSession,
    user_email: str,
    user_role: str,
    action: str,
    resource_type: str = None,
    resource_id: str = None,
    details: str = None,
    ip_address: str = None,
    event_metadata: dict = None,
):
    entry = AuditLog(
        user_email=user_email,
        user_role=user_role,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address,
        event_metadata=event_metadata,
    )
    db.add(entry)
    # No explicit flush — caller's session commit covers it
