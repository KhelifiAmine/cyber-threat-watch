"""
Client context helper — resolves the NotificationRecipient profile for CLIENT users.
"""

from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User, UserRole
from app.models.notification import NotificationRecipient


async def get_client_recipient(user: User, db: AsyncSession) -> Optional[NotificationRecipient]:
    """Look up the NotificationRecipient record for a CLIENT user by email.
    Returns None for non-CLIENT roles or if no recipient record exists."""
    if user.role != UserRole.CLIENT:
        return None
    result = await db.execute(
        select(NotificationRecipient).where(NotificationRecipient.email == user.email)
    )
    return result.scalar_one_or_none()


# Keys inside enrichment_data that reveal other tenants' data and must never be
# exposed to CLIENT users (cross-tenant leakage).
_CLIENT_REDACTED_ENRICHMENT_KEYS = {"client_matches"}

# Top-level internal review-workflow fields that CLIENT users must not see.
_CLIENT_REDACTED_TOP_KEYS = ("review_status", "has_pending_proposal", "edited_by", "flag_note")


def redact_enrichment_for_role(enrichment, role: UserRole):
    """Return a copy of an enrichment_data dict with cross-tenant fields removed
    for CLIENT users. Non-CLIENT roles (admin/analyst) see everything.

    A new dict is returned so the underlying ORM object is never mutated.
    """
    if role == UserRole.CLIENT and isinstance(enrichment, dict):
        return {k: v for k, v in enrichment.items() if k not in _CLIENT_REDACTED_ENRICHMENT_KEYS}
    return enrichment


def redact_content_item_for_role(d: dict, role: UserRole) -> dict:
    """Sanitize a serialized CVE/threat/news item (a dict) for CLIENT users:
    removes cross-tenant match data and internal review-workflow status (the
    'pending'/approved/rejected badges, editor name, flag notes). No-op for
    analysts/admins. Mutates and returns the given dict for convenience."""
    if role != UserRole.CLIENT:
        return d
    d["enrichment_data"] = redact_enrichment_for_role(d.get("enrichment_data"), role)
    for k in _CLIENT_REDACTED_TOP_KEYS:
        if k in d:
            d[k] = False if k == "has_pending_proposal" else None
    return d
