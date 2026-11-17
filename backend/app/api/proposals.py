"""
Enrichment proposal API — CVE and Threat review workflow.

Flow:
  1. Scraper hits a duplicate CVE/Threat → files a proposal (PENDING).
  2. Analyst opens the ticket, reviews the diff, edits freely, and either:
       - Approves → merges selected fields into the CVE/Threat, status → APPROVED
       - Closes   → marks as REJECTED, no fields merged
  3. Independently, the analyst may send a curated advisory email to clients
     via the /send endpoint.  This is a separate action from approval and
     bypasses the NOT_CONCERNED notification preference (it is a deliberate
     human decision, not an automated alert).

Manual flagging: analysts can flag any CVE/Threat for review so it can be
curated and forwarded to clients even if no scraper duplicate was detected.
"""

from datetime import datetime
from typing import Optional, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, desc, func, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.cve import CVE
from app.models.threat import Threat
from app.models.news_article import NewsArticle, NewsStatus
from app.models.cve_enrichment_proposal import CVEEnrichmentProposal
from app.models.threat_enrichment_proposal import ThreatEnrichmentProposal
from app.models.news_enrichment_proposal import NewsEnrichmentProposal
from app.models.user import User, UserRole
from app.api.auth import get_current_user, require_role
from app.services.audit import log_action

router = APIRouter()


CVE_MERGEABLE_FIELDS = {
    "title", "description", "affected_products", "vendor",
    "cvss_base_score", "cvss_vector", "cvss_severity",
    "exploit_available", "patch_available",
    "source_url", "references", "enrichment_data",
}

THREAT_MERGEABLE_FIELDS = {
    "title", "description", "source_url",
    "severity", "threat_type", "ttp_codes",
    "regions", "risk_score", "enrichment_data",
}

NUMERIC_CVE_FIELDS = {"cvss_base_score"}
NUMERIC_THREAT_FIELDS = {"risk_score"}


def _coerce(field: str, value, numeric: set, upper_fields: set):
    if value is None or value == "":
        return None
    if field in numeric:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
    if field in upper_fields and isinstance(value, str):
        return value.strip().upper()
    return value


# ─── Serialization ───────────────────────────────────────────────────────────

def _serialize_cve_proposal(p: CVEEnrichmentProposal, current: Optional[CVE]) -> dict:
    current_fields = {}
    if current is not None:
        for f in CVE_MERGEABLE_FIELDS:
            current_fields[f] = getattr(current, f, None)
    return {
        "kind": "cve",
        "id": p.id,
        "cve_id": p.cve_id,
        "source": p.source,
        "origin": p.origin,
        "status": p.status,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "reviewed_by": p.reviewed_by,
        "reviewed_at": p.reviewed_at.isoformat() if p.reviewed_at else None,
        "flag_note": p.flag_note,  # analyst flag note
        "client_email_sent_at": p.client_email_sent_at.isoformat() if p.client_email_sent_at else None,
        "proposed_fields": p.proposed_fields or {},
        "applied_fields": p.applied_fields or {},
        "current_fields": current_fields,
        # Convenience: pass severity/score for priority sorting on ticket board
        "priority_score": current_fields.get("cvss_base_score") if current else None,
        "priority_severity": current_fields.get("cvss_severity") if current else None,
        "client_matches": p.client_matches or [],
    }


def _serialize_threat_proposal(p: ThreatEnrichmentProposal, current: Optional[Threat]) -> dict:
    current_fields = {}
    if current is not None:
        for f in THREAT_MERGEABLE_FIELDS:
            val = getattr(current, f, None)
            if hasattr(val, "value"):
                val = val.value
            current_fields[f] = val
    return {
        "kind": "threat",
        "id": p.id,
        "threat_id": p.threat_id,
        "threat_title": current.title if current else None,
        "source": p.source,
        "origin": p.origin,
        "status": p.status,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "reviewed_by": p.reviewed_by,
        "reviewed_at": p.reviewed_at.isoformat() if p.reviewed_at else None,
        "flag_note": p.flag_note,  # analyst flag note
        "client_email_sent_at": p.client_email_sent_at.isoformat() if p.client_email_sent_at else None,
        "proposed_fields": p.proposed_fields or {},
        "applied_fields": p.applied_fields or {},
        "current_fields": current_fields,
        # Convenience: pass severity/score for priority sorting on ticket board
        "priority_score": current_fields.get("risk_score") if current else None,
        "priority_severity": current_fields.get("severity") if current else None,
        "client_matches": p.client_matches or [],
    }


NEWS_MERGEABLE_FIELDS = {
    "title", "summary", "description", "sectors",
}


def _serialize_news_proposal(p: NewsEnrichmentProposal, current: Optional[NewsArticle]) -> dict:
    current_fields = {}
    if current is not None:
        for f in NEWS_MERGEABLE_FIELDS:
            current_fields[f] = getattr(current, f, None)
    return {
        "kind": "news",
        "id": p.id,
        "news_id": p.news_id,
        "news_title": current.title if current else None,
        "source": p.source,
        "origin": p.origin,
        "status": p.status,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "reviewed_by": p.reviewed_by,
        "reviewed_at": p.reviewed_at.isoformat() if p.reviewed_at else None,
        "flag_note": p.flag_note,
        "client_email_sent_at": p.client_email_sent_at.isoformat() if p.client_email_sent_at else None,
        "proposed_fields": p.proposed_fields or {},
        "applied_fields": p.applied_fields or {},
        "current_fields": current_fields,
        "priority_score": None,
        "priority_severity": None,
        "client_matches": p.client_matches or [],
    }


# ─── Request bodies ──────────────────────────────────────────────────────────

class ApplyRequest(BaseModel):
    fields: list[str]
    overrides: Optional[dict] = None


class ManualFlagRequest(BaseModel):
    cve_id: Optional[str] = None
    threat_id: Optional[int] = None
    note: Optional[str] = None


class SendRequest(BaseModel):
    recipient_ids: Optional[list[int]] = None  # None = send to all active clients


# ─── List endpoint — merges CVE + Threat proposals ───────────────────────────

@router.get("/")
async def list_proposals(
    status: str = Query("PENDING"),
    kind: Optional[Literal["cve", "threat", "news"]] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    has_matches: Optional[bool] = None,
    sort_by: Optional[str] = Query(None, description="newest|oldest|most_matches"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    items: list = []
    total = 0

    if kind in (None, "cve"):
        cve_q = select(CVEEnrichmentProposal).where(CVEEnrichmentProposal.status == status)
        cve_total = (await db.execute(select(func.count()).select_from(cve_q.subquery()))).scalar() or 0
        total += cve_total
        cve_rows = (await db.execute(
            cve_q.order_by(desc(CVEEnrichmentProposal.created_at))
        )).scalars().all()
        cve_ids = [p.cve_id for p in cve_rows]
        by_id: dict = {}
        if cve_ids:
            cres = await db.execute(select(CVE).where(CVE.cve_id.in_(cve_ids)))
            for c in cres.scalars().all():
                by_id[c.cve_id] = c
        items.extend(_serialize_cve_proposal(p, by_id.get(p.cve_id)) for p in cve_rows)

    if kind in (None, "threat"):
        t_q = select(ThreatEnrichmentProposal).where(ThreatEnrichmentProposal.status == status)
        t_total = (await db.execute(select(func.count()).select_from(t_q.subquery()))).scalar() or 0
        total += t_total
        t_rows = (await db.execute(
            t_q.order_by(desc(ThreatEnrichmentProposal.created_at))
        )).scalars().all()
        t_ids = [p.threat_id for p in t_rows]
        by_id2: dict = {}
        if t_ids:
            tres = await db.execute(select(Threat).where(Threat.id.in_(t_ids)))
            for t in tres.scalars().all():
                by_id2[t.id] = t
        items.extend(_serialize_threat_proposal(p, by_id2.get(p.threat_id)) for p in t_rows)

    if kind in (None, "news"):
        n_q = select(NewsEnrichmentProposal).where(NewsEnrichmentProposal.status == status)
        n_total = (await db.execute(select(func.count()).select_from(n_q.subquery()))).scalar() or 0
        total += n_total
        n_rows = (await db.execute(
            n_q.order_by(desc(NewsEnrichmentProposal.created_at))
        )).scalars().all()
        n_ids = [p.news_id for p in n_rows]
        by_id3: dict = {}
        if n_ids:
            nres = await db.execute(select(NewsArticle).where(NewsArticle.id.in_(n_ids)))
            for n in nres.scalars().all():
                by_id3[n.id] = n
        items.extend(_serialize_news_proposal(p, by_id3.get(p.news_id)) for p in n_rows)

    # Filter by has_matches
    if has_matches is True:
        items = [x for x in items if x.get("client_matches") and len(x["client_matches"]) > 0]
    elif has_matches is False:
        items = [x for x in items if not x.get("client_matches") or len(x["client_matches"]) == 0]

    # Sort merged list
    if sort_by == "oldest":
        items.sort(key=lambda x: x.get("created_at") or "")
    elif sort_by == "most_matches":
        items.sort(key=lambda x: len(x.get("client_matches") or []), reverse=True)
    else:
        items.sort(key=lambda x: x.get("created_at") or "", reverse=True)

    total = len(items)
    start = (page - 1) * per_page
    page_items = items[start:start + per_page]

    return {
        "items": page_items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if total > 0 else 0,
    }


# ─── Single-proposal fetch ───────────────────────────────────────────────────

async def _load_cve_proposal(db: AsyncSession, proposal_id: int):
    res = await db.execute(select(CVEEnrichmentProposal).where(CVEEnrichmentProposal.id == proposal_id))
    p = res.scalar_one_or_none()
    if not p:
        return None, None
    cres = await db.execute(select(CVE).where(CVE.cve_id == p.cve_id))
    cve = cres.scalar_one_or_none()

    return p, cve


async def _load_threat_proposal(db: AsyncSession, proposal_id: int):
    res = await db.execute(select(ThreatEnrichmentProposal).where(ThreatEnrichmentProposal.id == proposal_id))
    p = res.scalar_one_or_none()
    if not p:
        return None, None
    tres = await db.execute(select(Threat).where(Threat.id == p.threat_id))
    return p, tres.scalar_one_or_none()


@router.get("/cve/{proposal_id}")
async def get_cve_proposal(
    proposal_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    p, cve = await _load_cve_proposal(db, proposal_id)
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")
    return _serialize_cve_proposal(p, cve)


@router.get("/threat/{proposal_id}")
async def get_threat_proposal(
    proposal_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    p, threat = await _load_threat_proposal(db, proposal_id)
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")
    return _serialize_threat_proposal(p, threat)


# ─── Approve (apply fields + mark APPROVED) ──────────────────────────────────

@router.post("/cve/{proposal_id}/apply")
async def apply_cve_proposal(
    proposal_id: int,
    body: ApplyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    p, cve = await _load_cve_proposal(db, proposal_id)
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")
    if p.status != "PENDING":
        raise HTTPException(status_code=409, detail=f"Proposal already {p.status}")
    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE {p.cve_id} no longer exists")

    proposed = p.proposed_fields or {}
    overrides = body.overrides or {}
    applied: dict = {}

    for field in body.fields:
        if field not in CVE_MERGEABLE_FIELDS:
            continue
        raw = overrides.get(field, proposed.get(field))
        value = _coerce(field, raw, NUMERIC_CVE_FIELDS, {"cvss_severity"})
        if value is None:
            continue
        setattr(cve, field, value)
        applied[field] = value

    p.status = "APPROVED"
    p.reviewed_by = current_user.email
    p.reviewed_at = datetime.utcnow()
    p.applied_fields = applied

    await log_action(
        db, current_user.email, current_user.role.value,
        "APPROVE_CVE_PROPOSAL", resource_type="cve_proposal", resource_id=str(proposal_id),
        details=f"Approved proposal from {p.source} for {p.cve_id} ({len(applied)} fields merged)",
        event_metadata={
            "proposal_id": proposal_id,
            "kind": "cve",
            "cve_id": p.cve_id,
            "source": p.source,
            "origin": p.origin,
            "action": "approve",
            "fields_applied": list(applied.keys()),
            "new_status": "APPROVED",
        },
    )
    await db.flush()
    return _serialize_cve_proposal(p, cve)


@router.post("/threat/{proposal_id}/apply")
async def apply_threat_proposal(
    proposal_id: int,
    body: ApplyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    p, threat = await _load_threat_proposal(db, proposal_id)
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")
    if p.status != "PENDING":
        raise HTTPException(status_code=409, detail=f"Proposal already {p.status}")
    if not threat:
        raise HTTPException(status_code=404, detail=f"Threat {p.threat_id} no longer exists")

    proposed = p.proposed_fields or {}
    overrides = body.overrides or {}
    applied: dict = {}

    for field in body.fields:
        if field not in THREAT_MERGEABLE_FIELDS:
            continue
        raw = overrides.get(field, proposed.get(field))
        value = _coerce(field, raw, NUMERIC_THREAT_FIELDS, {"severity"})
        if value is None:
            continue
        setattr(threat, field, value)
        applied[field] = value

    p.status = "APPROVED"
    p.reviewed_by = current_user.email
    p.reviewed_at = datetime.utcnow()
    p.applied_fields = applied

    await log_action(
        db, current_user.email, current_user.role.value,
        "APPROVE_THREAT_PROPOSAL", resource_type="threat_proposal", resource_id=str(proposal_id),
        details=f"Approved proposal from {p.source} for threat {p.threat_id} ({len(applied)} fields merged)",
        event_metadata={
            "proposal_id": proposal_id,
            "kind": "threat",
            "threat_id": p.threat_id,
            "source": p.source,
            "origin": p.origin,
            "action": "approve",
            "fields_applied": list(applied.keys()),
            "new_status": "APPROVED",
        },
    )
    await db.flush()
    return _serialize_threat_proposal(p, threat)


# ─── Close (reject) ──────────────────────────────────────────────────────────

@router.post("/cve/{proposal_id}/reject")
async def reject_cve_proposal(
    proposal_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    p, cve = await _load_cve_proposal(db, proposal_id)
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")
    if p.status != "PENDING":
        raise HTTPException(status_code=409, detail=f"Proposal already {p.status}")

    p.status = "REJECTED"
    p.reviewed_by = current_user.email
    p.reviewed_at = datetime.utcnow()

    await log_action(
        db, current_user.email, current_user.role.value,
        "CLOSE_CVE_PROPOSAL", resource_type="cve_proposal", resource_id=str(proposal_id),
        details=f"Closed proposal from {p.source} for {p.cve_id}",
        event_metadata={
            "proposal_id": proposal_id,
            "kind": "cve",
            "cve_id": p.cve_id,
            "source": p.source,
            "origin": p.origin,
            "action": "close",
            "new_status": "REJECTED",
        },
    )
    await db.flush()
    return _serialize_cve_proposal(p, cve)


@router.post("/threat/{proposal_id}/reject")
async def reject_threat_proposal(
    proposal_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    p, threat = await _load_threat_proposal(db, proposal_id)
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")
    if p.status != "PENDING":
        raise HTTPException(status_code=409, detail=f"Proposal already {p.status}")

    p.status = "REJECTED"
    p.reviewed_by = current_user.email
    p.reviewed_at = datetime.utcnow()

    await log_action(
        db, current_user.email, current_user.role.value,
        "CLOSE_THREAT_PROPOSAL", resource_type="threat_proposal", resource_id=str(proposal_id),
        details=f"Closed proposal from {p.source} for threat {p.threat_id}",
        event_metadata={
            "proposal_id": proposal_id,
            "kind": "threat",
            "threat_id": p.threat_id,
            "source": p.source,
            "origin": p.origin,
            "action": "close",
            "new_status": "REJECTED",
        },
    )
    await db.flush()
    return _serialize_threat_proposal(p, threat)


# ─── Send to clients (independent of approval status) ────────────────────────

@router.post("/cve/{proposal_id}/send")
async def send_cve_advisory(
    proposal_id: int,
    body: SendRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """
    Send a curated CVE advisory email to clients.
    Bypasses NOT_CONCERNED preference — this is a deliberate analyst decision.
    Can be called on any proposal regardless of approval status.
    """
    from app.services.email_service import get_forward_recipients, send_email, render_alert_email
    from app.api.advisory import validate_advisory_fields

    p, cve = await _load_cve_proposal(db, proposal_id)
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")
    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE {p.cve_id} no longer exists")

    field_errors = validate_advisory_fields(cve, "cve", body.recipient_ids)
    if field_errors:
        raise HTTPException(status_code=422, detail=field_errors)

    recipients_data = get_forward_recipients(body.recipient_ids)
    if not recipients_data:
        raise HTTPException(status_code=400, detail="No active client recipients found")

    recipient_emails = [r["email"] for r in recipients_data]
    alert_data = {
        "alert_id": p.id,
        "alert_title": cve.title or cve.cve_id,
        "alert_message": cve.description or "",
        "priority": "HIGH",
        "status": "NEW",
        "alert_created_at": datetime.utcnow(),
        "threat_description": cve.description,
        "severity": (cve.cvss_severity or "").upper(),
        "cvss_base_score": cve.cvss_base_score,
        "cve_identifier": cve.cve_id,
        "risk_score": None,
        "source_url": cve.source_url,
        "source": "NVD",
        "threat_published_at": cve.published_at,
        "enrichment_data": cve.enrichment_data,
    }
    html = render_alert_email(alert_data)
    subject = f"Security Advisory — {cve.cve_id}"
    success = send_email(recipient_emails, subject, html)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to send email — check SMTP configuration")

    p.client_email_sent_at = datetime.utcnow()

    # Stamp the source CVE so the Sent badge appears in all views
    cve.advisory_sent_at = datetime.utcnow()
    cve.advisory_sent_by = current_user.email

    await log_action(
        db, current_user.email, current_user.role.value,
        "SEND_CVE_ADVISORY", resource_type="cve_proposal", resource_id=str(proposal_id),
        details=f"Sent CVE advisory for {cve.cve_id} to {len(recipient_emails)} recipients",
        event_metadata={
            "proposal_id": proposal_id,
            "kind": "cve",
            "cve_id": p.cve_id,
            "recipient_count": len(recipient_emails),
            "recipient_ids": body.recipient_ids,
        },
    )
    await db.flush()
    return {**_serialize_cve_proposal(p, cve), "sent_to": len(recipient_emails)}


@router.post("/threat/{proposal_id}/send")
async def send_threat_advisory(
    proposal_id: int,
    body: SendRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """
    Send a curated threat advisory email to clients.
    Bypasses NOT_CONCERNED preference — this is a deliberate analyst decision.
    """
    from app.services.email_service import get_forward_recipients, send_email, render_alert_email
    from app.api.advisory import validate_advisory_fields

    p, threat = await _load_threat_proposal(db, proposal_id)
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")
    if not threat:
        raise HTTPException(status_code=404, detail=f"Threat {p.threat_id} no longer exists")

    field_errors = validate_advisory_fields(threat, "threat", body.recipient_ids)
    if field_errors:
        raise HTTPException(status_code=422, detail=field_errors)

    recipients_data = get_forward_recipients(body.recipient_ids)
    if not recipients_data:
        raise HTTPException(status_code=400, detail="No active client recipients found")

    recipient_emails = [r["email"] for r in recipients_data]
    sev = threat.severity.value if hasattr(threat.severity, "value") else threat.severity
    alert_data = {
        "alert_id": p.id,
        "alert_title": threat.title,
        "alert_message": threat.description or "",
        "priority": "HIGH",
        "status": "NEW",
        "alert_created_at": datetime.utcnow(),
        "threat_description": threat.description,
        "severity": (sev or "").upper(),
        "cvss_base_score": None,
        "cve_identifier": None,
        "risk_score": float(threat.risk_score) if threat.risk_score is not None else None,
        "source_url": threat.source_url,
        "source": threat.source,
        "threat_published_at": threat.published_at,
        "enrichment_data": threat.enrichment_data,
    }
    html = render_alert_email(alert_data)
    subject = f"Security Advisory — {threat.title[:80]}"
    success = send_email(recipient_emails, subject, html)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to send email — check SMTP configuration")

    p.client_email_sent_at = datetime.utcnow()

    # Stamp the source Threat so the Sent badge appears in all views
    threat.advisory_sent_at = datetime.utcnow()
    threat.advisory_sent_by = current_user.email

    await log_action(
        db, current_user.email, current_user.role.value,
        "SEND_THREAT_ADVISORY", resource_type="threat_proposal", resource_id=str(proposal_id),
        details=f"Sent threat advisory for '{threat.title[:60]}' to {len(recipient_emails)} recipients",
        event_metadata={
            "proposal_id": proposal_id,
            "kind": "threat",
            "threat_id": p.threat_id,
            "recipient_count": len(recipient_emails),
            "recipient_ids": body.recipient_ids,
        },
    )
    await db.flush()
    return {**_serialize_threat_proposal(p, threat), "sent_to": len(recipient_emails)}


# ─── News proposal endpoints ────────────────────────────────────────────────

async def _load_news_proposal(db: AsyncSession, proposal_id: int):
    res = await db.execute(select(NewsEnrichmentProposal).where(NewsEnrichmentProposal.id == proposal_id))
    p = res.scalar_one_or_none()
    if not p:
        return None, None
    nres = await db.execute(select(NewsArticle).where(NewsArticle.id == p.news_id))
    return p, nres.scalar_one_or_none()


@router.get("/news/{proposal_id}")
async def get_news_proposal(
    proposal_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    p, news = await _load_news_proposal(db, proposal_id)
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")
    return _serialize_news_proposal(p, news)


@router.post("/news/{proposal_id}/apply")
async def apply_news_proposal(
    proposal_id: int,
    body: ApplyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    p, news = await _load_news_proposal(db, proposal_id)
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")
    if p.status != "PENDING":
        raise HTTPException(status_code=409, detail=f"Proposal already {p.status}")
    if not news:
        raise HTTPException(status_code=404, detail="News article no longer exists")

    proposed = p.proposed_fields or {}
    overrides = body.overrides or {}
    applied: dict = {}

    for field in body.fields:
        if field not in NEWS_MERGEABLE_FIELDS:
            continue
        value = overrides.get(field, proposed.get(field))
        if value is None:
            continue
        setattr(news, field, value)
        applied[field] = value

    p.status = "APPROVED"
    p.reviewed_by = current_user.email
    p.reviewed_at = datetime.utcnow()
    p.applied_fields = applied

    news.review_status = "APPROVED"
    news.status = NewsStatus.REVIEWED

    await log_action(
        db, current_user.email, current_user.role.value,
        "APPROVE_NEWS_PROPOSAL", resource_type="news_proposal", resource_id=str(proposal_id),
        details=f"Approved news proposal for article {p.news_id} ({len(applied)} fields merged)",
        event_metadata={"proposal_id": proposal_id, "kind": "news", "news_id": p.news_id, "fields_applied": list(applied.keys())},
    )
    await db.flush()
    return _serialize_news_proposal(p, news)


@router.post("/news/{proposal_id}/reject")
async def reject_news_proposal(
    proposal_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    p, news = await _load_news_proposal(db, proposal_id)
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")
    if p.status != "PENDING":
        raise HTTPException(status_code=409, detail=f"Proposal already {p.status}")

    p.status = "REJECTED"
    p.reviewed_by = current_user.email
    p.reviewed_at = datetime.utcnow()

    if news:
        news.review_status = "REJECTED"
        news.status = NewsStatus.DISMISSED

    await log_action(
        db, current_user.email, current_user.role.value,
        "REJECT_NEWS_PROPOSAL", resource_type="news_proposal", resource_id=str(proposal_id),
        details=f"Rejected news proposal for article {p.news_id}",
        event_metadata={"proposal_id": proposal_id, "kind": "news", "news_id": p.news_id},
    )
    await db.flush()
    return _serialize_news_proposal(p, news)


@router.post("/news/{proposal_id}/send")
async def send_news_advisory(
    proposal_id: int,
    body: SendRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    from app.services.email_service import get_forward_recipients, send_news_email

    p, news = await _load_news_proposal(db, proposal_id)
    if not p:
        raise HTTPException(status_code=404, detail="Proposal not found")
    if not news:
        raise HTTPException(status_code=404, detail="News article no longer exists")

    # Validate
    errors = []
    if not (news.title or "").strip():
        errors.append("Title is required")
    if not (news.summary or "").strip():
        errors.append("Summary is required")
    if not (news.description or "").strip() or len((news.description or "").strip()) < 20:
        errors.append("Description is required (minimum 20 characters)")
    if not (news.sectors or []):
        errors.append("At least one sector is required")
    if not body.recipient_ids:
        errors.append("At least one recipient must be selected")
    if errors:
        raise HTTPException(status_code=422, detail=errors)

    recipients_data = get_forward_recipients(body.recipient_ids)
    if not recipients_data:
        raise HTTPException(status_code=400, detail="No active client recipients found")

    recipient_emails = [r["email"] for r in recipients_data]
    pub = news.published_at or datetime.utcnow()
    news_id_str = f"NEWS-{pub.strftime('%y%m%d')}-{news.id:04d}"

    success = send_news_email(
        to_emails=recipient_emails,
        news_id=news_id_str,
        title=news.title,
        summary=news.summary or "",
        description=news.description or "",
        sectors=news.sectors or [],
        source=news.source,
        published_date=news.published_at.strftime("%d %B %Y") if news.published_at else "",
        enrichment_data=news.enrichment_data,
    )
    if not success:
        raise HTTPException(status_code=500, detail="Failed to send email")

    p.client_email_sent_at = now
    news.advisory_sent_at = now
    news.advisory_sent_by = current_user.email

    await log_action(
        db, current_user.email, current_user.role.value,
        "SEND_NEWS_ADVISORY", resource_type="news_proposal", resource_id=str(proposal_id),
        details=f"Sent news advisory '{news.title[:60]}' to {len(recipient_emails)} recipients",
        event_metadata={"proposal_id": proposal_id, "kind": "news", "news_id": p.news_id, "recipient_count": len(recipient_emails)},
    )
    await db.flush()
    return {**_serialize_news_proposal(p, news), "sent_to": len(recipient_emails)}


# ─── Client recipients list (for send modal) ─────────────────────────────────

@router.get("/clients")
async def list_client_recipients(
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """All active non-analyst recipients available for forwarded advisories."""
    from app.services.email_service import get_all_client_recipients_for_ui
    return get_all_client_recipients_for_ui()


# ─── Manual flagging ─────────────────────────────────────────────────────────

@router.post("/flag")
async def manual_flag(
    body: ManualFlagRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    if not body.cve_id and not body.threat_id:
        raise HTTPException(status_code=400, detail="Provide cve_id or threat_id")
    if body.cve_id and body.threat_id:
        raise HTTPException(status_code=400, detail="Provide exactly one of cve_id/threat_id")

    if body.cve_id:
        cres = await db.execute(select(CVE).where(CVE.cve_id == body.cve_id))
        cve = cres.scalar_one_or_none()
        if not cve:
            raise HTTPException(status_code=404, detail="CVE not found")

        existing = await db.execute(
            select(CVEEnrichmentProposal).where(
                CVEEnrichmentProposal.cve_id == body.cve_id,
                CVEEnrichmentProposal.status == "PENDING",
            )
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="CVE is already in review")

        p = CVEEnrichmentProposal(
            cve_id=body.cve_id,
            source=f"manual:{current_user.email}",
            origin="MANUAL",
            proposed_fields={},
            status="PENDING",
            flag_note=body.note,
        )
        db.add(p)
        await db.flush()
        await log_action(
            db, current_user.email, current_user.role.value,
            "MANUAL_FLAG_CVE", resource_type="cve", resource_id=body.cve_id,
            details=body.note or "Flagged for review",
            event_metadata={
                "proposal_id": p.id,
                "kind": "cve",
                "cve_id": body.cve_id,
                "origin": "MANUAL",
                "action": "flag",
                "flag_note": body.note,
            },
        )
        return _serialize_cve_proposal(p, cve)

    tres = await db.execute(select(Threat).where(Threat.id == body.threat_id))
    threat = tres.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    existing = await db.execute(
        select(ThreatEnrichmentProposal).where(
            ThreatEnrichmentProposal.threat_id == body.threat_id,
            ThreatEnrichmentProposal.status == "PENDING",
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Threat is already in review")

    p = ThreatEnrichmentProposal(
        threat_id=body.threat_id,
        source=f"manual:{current_user.email}",
        origin="MANUAL",
        proposed_fields={},
        status="PENDING",
        flag_note=body.note,
    )
    db.add(p)
    await db.flush()
    await log_action(
        db, current_user.email, current_user.role.value,
        "MANUAL_FLAG_THREAT", resource_type="threat", resource_id=str(body.threat_id),
        details=body.note or "Flagged for review",
        event_metadata={
            "proposal_id": p.id,
            "kind": "threat",
            "threat_id": body.threat_id,
            "origin": "MANUAL",
            "action": "flag",
            "flag_note": body.note,
        },
    )
    return _serialize_threat_proposal(p, threat)


# ─── Flag-status lookup — for list-page badges ───────────────────────────────

@router.get("/flags/cves")
async def cve_flags(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Returns {cve_id: status} for CVEs that currently have a PENDING proposal."""
    result = await db.execute(
        select(CVEEnrichmentProposal.cve_id, CVEEnrichmentProposal.status)
        .where(CVEEnrichmentProposal.status == "PENDING")
    )
    return {cve_id: status for cve_id, status in result.all()}


@router.get("/flags/threats")
async def threat_flags(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    result = await db.execute(
        select(ThreatEnrichmentProposal.threat_id, ThreatEnrichmentProposal.status)
        .where(ThreatEnrichmentProposal.status == "PENDING")
    )
    return {str(tid): status for tid, status in result.all()}
