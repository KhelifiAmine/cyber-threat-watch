"""
Alert API endpoints — Protected by role-based access.
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.alert import Alert, AlertStatus
from app.models.threat import Threat
from app.models.cve import CVE
from app.models.user import User, UserRole
from app.schemas.alert import AlertCreate, AlertUpdate, AlertResponse
from app.api.auth import get_current_user, require_role
from app.services.audit import log_action

router = APIRouter()


def _alert_to_response(alert: Alert) -> AlertResponse:
    """Merge alert with its linked threat/CVE enrichment data for the response."""
    base = {
        "id": alert.id,
        "title": alert.title,
        "message": alert.message,
        "priority": alert.priority.value if hasattr(alert.priority, "value") else alert.priority,
        "status": alert.status.value if hasattr(alert.status, "value") else alert.status,
        "trigger_rule": alert.trigger_rule,
        "threat_id": alert.threat_id,
        "cve_id": alert.cve_id,
        "email_sent": alert.email_sent,
        "acknowledged_by": alert.acknowledged_by,
        "acknowledged_at": alert.acknowledged_at,
        "created_at": alert.created_at,
        "updated_at": alert.updated_at,
    }

    threat = getattr(alert, "threat", None)
    cve = getattr(alert, "cve", None)

    if threat is not None:
        base["source_label"] = threat.source
        base["source_url"] = threat.source_url
        base["risk_score"] = float(threat.risk_score) if threat.risk_score is not None else None
        base["severity"] = (threat.severity.value if hasattr(threat.severity, "value") else threat.severity)
        base["description"] = threat.description
        base["enrichment_data"] = threat.enrichment_data
    elif cve is not None:
        base["source_label"] = "NVD"
        base["source_url"] = cve.source_url
        base["cve_ref"] = cve.cve_id
        base["cvss_score"] = float(cve.cvss_base_score) if cve.cvss_base_score is not None else None
        base["severity"] = (cve.cvss_severity.value if hasattr(cve.cvss_severity, "value") else cve.cvss_severity)
        base["description"] = cve.description
        base["enrichment_data"] = cve.enrichment_data

    return AlertResponse(**base)


@router.get("/")
async def list_alerts(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    priority: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """List alerts with optional filtering by status and priority."""
    query = select(Alert).options(
        selectinload(Alert.threat),
        selectinload(Alert.cve),
    )

    if status:
        query = query.where(Alert.status == status)
    if priority:
        query = query.where(Alert.priority == priority)

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    offset = (page - 1) * per_page
    query = query.order_by(desc(Alert.created_at)).offset(offset).limit(per_page)

    result = await db.execute(query)
    alerts = result.scalars().all()
    return {
        "items": [_alert_to_response(a).model_dump(mode="json") for a in alerts],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if total > 0 else 0,
    }


@router.get("/{alert_id}")
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Get a single alert by ID (with linked threat/CVE enrichment)."""
    result = await db.execute(
        select(Alert)
        .options(selectinload(Alert.threat), selectinload(Alert.cve))
        .where(Alert.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alert_to_response(alert).model_dump(mode="json")


@router.post("/", response_model=AlertResponse, status_code=201)
async def create_alert(
    data: AlertCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Create a new alert."""
    alert = Alert(**data.model_dump())
    db.add(alert)
    await db.flush()
    await db.refresh(alert)
    return AlertResponse.model_validate(alert)


@router.post("/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(
    alert_id: int,
    acknowledged_by: str = "analyst",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Mark an alert as acknowledged."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = AlertStatus.ACKNOWLEDGED
    alert.acknowledged_by = acknowledged_by
    alert.acknowledged_at = datetime.utcnow()

    await log_action(
        db, current_user.email, current_user.role.value,
        "ACKNOWLEDGE_ALERT", resource_type="alert", resource_id=str(alert_id),
        details=f"Acknowledged alert: {alert.title}"
    )
    await db.flush()
    await db.refresh(alert)
    return AlertResponse.model_validate(alert)


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: int,
    data: AlertUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Update alert status."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(alert, field, value)

    await log_action(
        db, current_user.email, current_user.role.value,
        "UPDATE_ALERT", resource_type="alert", resource_id=str(alert_id),
        details=f"Updated alert status to: {update_data.get('status', 'unknown')}"
    )
    await db.flush()
    await db.refresh(alert)
    return AlertResponse.model_validate(alert)


@router.delete("/{alert_id}", status_code=204)
async def dismiss_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """Dismiss/delete an alert."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    await log_action(
        db, current_user.email, current_user.role.value,
        "DISMISS_ALERT", resource_type="alert", resource_id=str(alert_id),
        details=f"Dismissed alert: {alert.title}"
    )
    await db.delete(alert)