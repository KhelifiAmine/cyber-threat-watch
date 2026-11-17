"""
Shared constants used across the application.
"""

from app.models.user import UserRole
from app.models.notification import RecipientRole

# Maps user role → notification recipient role.
# Admins receive analyst-level alerts; clients receive client-level alerts.
USER_TO_RECIPIENT_ROLE = {
    UserRole.ADMIN: RecipientRole.ANALYST,
    UserRole.ANALYST: RecipientRole.ANALYST,
    UserRole.CLIENT: RecipientRole.CLIENT,
}
