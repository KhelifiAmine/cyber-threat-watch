"""
Threat API endpoints — Protected by role-based access.
ANALYST and ADMIN can create/edit/delete.
All authenticated users can read.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, desc, asc, or_, cast, String
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.threat import Threat, SeverityLevel, ThreatStatus
from app.models.threat_enrichment_proposal import ThreatEnrichmentProposal
from app.models.user import User, UserRole
from app.schemas.threat import ThreatCreate, ThreatUpdate, ThreatResponse, ThreatListResponse
from app.api.auth import get_current_user, require_role
from app.services.audit import log_action

router = APIRouter()


@router.get("/sources")
async def get_threat_sources(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return distinct Threat source values for the filter dropdown."""
    from sqlalchemy import distinct
    result = await db.execute(
        select(distinct(Threat.source)).where(Threat.source.isnot(None), Threat.source != "")
    )
    return sorted([r for r in result.scalars().all() if r])


@router.get("/filter-options")
async def threat_filter_options(
    source: Optional[str] = None,
    severity: Optional[str] = None,
    region: Optional[str] = None,
    status: Optional[str] = None,
    sent: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return available filter options with counts, scoped by current filters."""
    from sqlalchemy import distinct

    def _apply_common(q, skip_field=None):
        if source and skip_field != "source":
            q = q.where(Threat.source == source)
        if severity and skip_field != "severity":
            q = q.where(Threat.severity == severity)
        if region and skip_field != "region":
            q = q.where(Threat.regions.ilike(f"%{region}%"))
        if status and skip_field != "status":
            q = q.where(Threat.status == status)
        if sent is True:
            q = q.where(Threat.advisory_sent_at.isnot(None))
        elif sent is False:
            q = q.where(Threat.advisory_sent_at.is_(None))
        return q

    # Sources
    src_q = _apply_common(
        select(Threat.source, func.count(Threat.id)).group_by(Threat.source).where(Threat.source.isnot(None)),
        skip_field="source",
    )
    src_rows = (await db.execute(src_q)).all()

    # Severities
    sev_q = _apply_common(
        select(Threat.severity, func.count(Threat.id)).group_by(Threat.severity).where(Threat.severity.isnot(None)),
        skip_field="severity",
    )
    sev_rows = (await db.execute(sev_q)).all()

    # Regions
    reg_q = _apply_common(
        select(Threat.regions, func.count(Threat.id)).group_by(Threat.regions).where(Threat.regions.isnot(None)),
        skip_field="region",
    )
    reg_rows = (await db.execute(reg_q)).all()

    # Statuses
    stat_q = _apply_common(
        select(Threat.status, func.count(Threat.id)).group_by(Threat.status).where(Threat.status.isnot(None)),
        skip_field="status",
    )
    stat_rows = (await db.execute(stat_q)).all()

    return {
        "sources": [{"value": r[0], "count": r[1]} for r in src_rows if r[0]],
        "severities": [{"value": r[0].value if hasattr(r[0], "value") else str(r[0]), "count": r[1]} for r in sev_rows if r[0]],
        "regions": [{"value": r[0], "count": r[1]} for r in reg_rows if r[0]],
        "statuses": [{"value": r[0].value if hasattr(r[0], "value") else str(r[0]), "count": r[1]} for r in stat_rows if r[0]],
    }


@router.get("/")
async def list_threats(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    source: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    region: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "created_at",
    review_status: Optional[str] = Query(None, description="none|approved|rejected"),
    sent: Optional[bool] = None,
    mena_only: Optional[bool] = None,
    min_risk: Optional[float] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List threats with filtering, search, and pagination.

    Threats with a non-terminal proposal (PENDING/REVIEWED) are hidden —
    they live in the review queue. Returned threats carry `review_status`.

    CLIENT users see only threats matching their profile (via client_matches).
    """
    query = select(Threat)

    # CLIENT auto-filter: real-time matching by regions + product inventory
    if current_user.role == UserRole.CLIENT:
        from app.services.client_context import get_client_recipient
        from app.api.dashboard import _build_inventory_sets, _match_inventory_against_cve
        rec = await get_client_recipient(current_user, db)
        if not rec:
            return {"items": [], "total": 0, "page": page, "per_page": per_page, "pages": 0}
        client_regions = {r.strip().lower() for r in (rec.regions or [])}
        inv_products, inv_vendors = _build_inventory_sets(rec.inventory or [])
        # Match threats by region overlap OR product inventory
        all_rows = (await db.execute(
            select(Threat.id, Threat.regions, Threat.enrichment_data)
        )).all()
        matching_ids = []
        for tid, regions_str, enrichment in all_rows:
            # Region match
            threat_regions = {r.strip().lower() for r in (regions_str or "").split(",") if r.strip()}
            if client_regions and threat_regions & client_regions:
                matching_ids.append(tid)
                continue
            # Product match via enrichment affected_products
            if inv_products and _match_inventory_against_cve(inv_products, inv_vendors, enrichment, None):
                matching_ids.append(tid)
        if not matching_ids:
            return {"items": [], "total": 0, "page": page, "per_page": per_page, "pages": 0}
        query = query.where(Threat.id.in_(matching_ids))

    if source:
        query = query.where(Threat.source == source)
    if severity:
        query = query.where(Threat.severity == severity)
    if region:
        query = query.where(Threat.regions.ilike(f"%{region}%"))
    if status:
        query = query.where(Threat.status == status)
    if search:
        term = f"%{search.strip()}%"
        query = query.where(or_(
            Threat.title.ilike(term),
            Threat.description.ilike(term),
            Threat.threat_type.ilike(term),
            Threat.regions.ilike(term),
            cast(Threat.enrichment_data, String).ilike(term),
        ))

    if sent is True:
        query = query.where(Threat.advisory_sent_at.isnot(None))
    elif sent is False:
        query = query.where(Threat.advisory_sent_at.is_(None))

    if mena_only is True:
        query = query.where(Threat.is_mena_relevant.is_(True))

    if min_risk is not None:
        query = query.where(Threat.risk_score >= min_risk)

    # Hide threats currently in review (PENDING only — REVIEWED removed)
    in_review_subq = select(ThreatEnrichmentProposal.threat_id).where(
        ThreatEnrichmentProposal.status == "PENDING"
    )
    query = query.where(~Threat.id.in_(in_review_subq))

    approved_subq = select(ThreatEnrichmentProposal.threat_id).where(
        ThreatEnrichmentProposal.status == "APPROVED"
    )
    rejected_subq = select(ThreatEnrichmentProposal.threat_id).where(
        ThreatEnrichmentProposal.status == "REJECTED"
    )
    if review_status == "approved":
        query = query.where(Threat.id.in_(approved_subq))
    elif review_status == "rejected":
        query = query.where(
            Threat.id.in_(rejected_subq),
            ~Threat.id.in_(approved_subq),
        )
    elif review_status == "none":
        query = query.where(
            ~Threat.id.in_(approved_subq),
            ~Threat.id.in_(rejected_subq),
        )

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    if sort_by == "risk_score" or sort_by == "risk_desc":
        query = query.order_by(desc(Threat.risk_score))
    elif sort_by == "severity":
        query = query.order_by(desc(Threat.severity))
    elif sort_by == "oldest":
        query = query.order_by(asc(Threat.created_at))
    else:
        query = query.order_by(desc(Threat.created_at))

    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page)

    result = await db.execute(query)
    threats = result.scalars().all()

    # Attach latest terminal proposal status
    threat_ids = [t.id for t in threats]
    status_map: dict = {}
    if threat_ids:
        prop_rows = (await db.execute(
            select(ThreatEnrichmentProposal)
            .where(
                ThreatEnrichmentProposal.threat_id.in_(threat_ids),
                ThreatEnrichmentProposal.status.in_(["APPROVED", "REJECTED"]),
            )
            .order_by(desc(ThreatEnrichmentProposal.reviewed_at))
        )).scalars().all()
        for p in prop_rows:
            if p.threat_id not in status_map:
                status_map[p.threat_id] = p.status

    from app.services.client_context import redact_content_item_for_role
    items = []
    for t in threats:
        d = ThreatResponse.model_validate(t).model_dump(mode="json")
        d["review_status"] = status_map.get(t.id)
        d["edited_by"] = t.edited_by
        # Strip cross-tenant match data + internal review status for CLIENT users.
        items.append(redact_content_item_for_role(d, current_user.role))

    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if total > 0 else 0,
    }


@router.get("/{threat_id}", response_model=ThreatResponse)
async def get_threat(
    threat_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single threat by ID."""
    result = await db.execute(select(Threat).where(Threat.id == threat_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    from app.services.client_context import redact_enrichment_for_role
    resp = ThreatResponse.model_validate(threat)
    if current_user.role == UserRole.CLIENT:
        if hasattr(resp, "review_status"):
            resp.review_status = None
        if hasattr(resp, "edited_by"):
            resp.edited_by = None
    resp.enrichment_data = redact_enrichment_for_role(resp.enrichment_data, current_user.role)
    return resp


@router.post("/", response_model=ThreatResponse, status_code=201)
async def create_threat(
    data: ThreatCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Create a new threat entry."""
    threat = Threat(**data.model_dump())
    db.add(threat)
    await db.flush()
    await db.refresh(threat)
    return ThreatResponse.model_validate(threat)


@router.patch("/{threat_id}", response_model=ThreatResponse)
async def update_threat(
    threat_id: int,
    data: ThreatUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Update an existing threat."""
    result = await db.execute(select(Threat).where(Threat.id == threat_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(threat, field, value)

    threat.edited_by = current_user.full_name or current_user.email

    await log_action(
        db, current_user.email, current_user.role.value,
        "EDIT_THREAT", resource_type="threat", resource_id=str(threat_id),
        details=f"Directly edited threat {threat_id}: {', '.join(update_data.keys())}",
        event_metadata={"fields_changed": list(update_data.keys()), "threat_id": threat_id},
    )
    await db.flush()
    await db.refresh(threat)
    resp = ThreatResponse.model_validate(threat)
    resp.edited_by = threat.edited_by
    return resp


@router.delete("/{threat_id}", status_code=204)
async def delete_threat(
    threat_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """Delete a threat."""
    result = await db.execute(select(Threat).where(Threat.id == threat_id))
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    await db.delete(threat)