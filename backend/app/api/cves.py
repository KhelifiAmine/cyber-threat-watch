"""
CVE API endpoints — Protected by role-based access.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, desc, asc, or_, cast, String
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.cve import CVE
from app.models.cve_enrichment_proposal import CVEEnrichmentProposal
from app.models.user import User, UserRole
from app.schemas.cve import CVECreate, CVEUpdate, CVEResponse
from app.api.auth import get_current_user, require_role
from app.services.audit import log_action

router = APIRouter()


@router.get("/sources")
async def get_cve_sources(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return distinct CVE source values for the filter dropdown."""
    from sqlalchemy import distinct
    result = await db.execute(
        select(distinct(CVE.source)).where(CVE.source.isnot(None), CVE.source != "")
    )
    return sorted([r for r in result.scalars().all() if r])


@router.get("/filter-options")
async def cve_filter_options(
    source: Optional[str] = None,
    severity: Optional[str] = None,
    exploit_available: Optional[str] = None,
    sent: Optional[bool] = None,
    review_status: Optional[str] = Query(None, description="none|approved|rejected"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return available filter options with counts, scoped by current filters."""
    from sqlalchemy import distinct

    def _apply_common(q, skip_field=None):
        if source and skip_field != "source":
            q = q.where(CVE.source == source)
        if severity and skip_field != "severity":
            q = q.where(CVE.cvss_severity == severity.upper())
        if exploit_available and skip_field != "exploit":
            q = q.where(CVE.exploit_available == exploit_available)
        if sent is True:
            q = q.where(CVE.advisory_sent_at.isnot(None))
        elif sent is False:
            q = q.where(CVE.advisory_sent_at.is_(None))
        return q

    src_q = _apply_common(
        select(CVE.source, func.count(CVE.id)).group_by(CVE.source).where(CVE.source.isnot(None), CVE.source != ""),
        skip_field="source",
    )
    src_rows = (await db.execute(src_q)).all()

    sev_q = _apply_common(
        select(CVE.cvss_severity, func.count(CVE.id)).group_by(CVE.cvss_severity).where(CVE.cvss_severity.isnot(None)),
        skip_field="severity",
    )
    sev_rows = (await db.execute(sev_q)).all()

    exp_q = _apply_common(
        select(CVE.exploit_available, func.count(CVE.id)).group_by(CVE.exploit_available).where(CVE.exploit_available.isnot(None)),
        skip_field="exploit",
    )
    exp_rows = (await db.execute(exp_q)).all()

    return {
        "sources": [{"value": r[0], "count": r[1]} for r in src_rows if r[0]],
        "severities": [{"value": r[0], "count": r[1]} for r in sev_rows if r[0]],
        "exploit_values": [{"value": r[0], "count": r[1]} for r in exp_rows if r[0]],
    }


@router.get("/")
async def list_cves(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    source: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    exploit_available: Optional[str] = None,
    min_cvss: Optional[float] = None,
    review_status: Optional[str] = Query(None, description="none|approved|rejected"),
    sent: Optional[bool] = None,
    sort_by: Optional[str] = Query(None, description="newest|oldest|risk_desc|cvss_desc"),
    has_exploit: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List CVEs with filtering and pagination.

    CVEs with a non-terminal proposal (PENDING or REVIEWED) are hidden — they
    live in the review queue until the proposal is approved or rejected.
    Each returned CVE is decorated with `review_status` reflecting the most
    recent terminal proposal (APPROVED/REJECTED) if any.

    CLIENT users see only CVEs matching their inventory (via client_matches).
    """
    query = select(CVE)

    # CLIENT auto-filter: real-time matching against client inventory
    _client_cve_ids = None
    if current_user.role == UserRole.CLIENT:
        from app.services.client_context import get_client_recipient
        from app.api.dashboard import _build_inventory_sets, _match_inventory_against_cve
        rec = await get_client_recipient(current_user, db)
        if not rec or not (rec.inventory or []):
            return {"items": [], "total": 0, "page": page, "per_page": per_page, "pages": 0}
        inv_products, inv_vendors = _build_inventory_sets(rec.inventory)
        # Fetch all CVE enrichment data and match in Python
        all_rows = (await db.execute(
            select(CVE.id, CVE.enrichment_data, CVE.vendor)
        )).all()
        matching_ids = []
        for cve_id, enrichment, vendor in all_rows:
            if _match_inventory_against_cve(inv_products, inv_vendors, enrichment, vendor):
                matching_ids.append(cve_id)
        if not matching_ids:
            return {"items": [], "total": 0, "page": page, "per_page": per_page, "pages": 0}
        _client_cve_ids = matching_ids
        query = query.where(CVE.id.in_(matching_ids))

    if source:
        query = query.where(CVE.source == source)
    if severity:
        query = query.where(CVE.cvss_severity == severity.upper())
    if search:
        term = f"%{search.strip()}%"
        query = query.where(or_(
            CVE.cve_id.ilike(term),
            CVE.title.ilike(term),
            CVE.description.ilike(term),
            CVE.affected_products.ilike(term),
            CVE.vendor.ilike(term),
            func.cast(CVE.enrichment_data["affected_products"].astext, String).ilike(term),
        ))
    if exploit_available:
        query = query.where(CVE.exploit_available == exploit_available)
    if min_cvss is not None:
        query = query.where(CVE.cvss_base_score >= min_cvss)

    # Subquery for pending proposals — used for badge display, NOT for hiding CVEs
    in_review_subq = select(CVEEnrichmentProposal.cve_id).where(
        CVEEnrichmentProposal.status == "PENDING"
    )

    approved_subq = select(CVEEnrichmentProposal.cve_id).where(
        CVEEnrichmentProposal.status == "APPROVED"
    )
    rejected_subq = select(CVEEnrichmentProposal.cve_id).where(
        CVEEnrichmentProposal.status == "REJECTED"
    )

    if sent is True:
        query = query.where(CVE.advisory_sent_at.isnot(None))
    elif sent is False:
        query = query.where(CVE.advisory_sent_at.is_(None))

    if has_exploit is True:
        query = query.where(CVE.exploit_available == "yes")

    if review_status == "approved":
        query = query.where(CVE.cve_id.in_(approved_subq))
    elif review_status == "rejected":
        query = query.where(
            CVE.cve_id.in_(rejected_subq),
            ~CVE.cve_id.in_(approved_subq),
        )
    elif review_status == "none":
        query = query.where(
            ~CVE.cve_id.in_(approved_subq),
            ~CVE.cve_id.in_(rejected_subq),
        )

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    offset = (page - 1) * per_page
    order_clauses = {
        "newest": [desc(CVE.created_at)],
        "oldest": [asc(CVE.created_at)],
        "cvss_desc": [desc(CVE.cvss_base_score).nullslast(), desc(CVE.created_at)],
    }
    paged_query = query.order_by(*order_clauses.get(sort_by, [desc(CVE.created_at), desc(CVE.cvss_base_score)])).offset(offset).limit(per_page)

    result = await db.execute(paged_query)
    cves = result.scalars().all()

    # Attach latest terminal proposal status + pending flag for badge display
    cve_ids = [c.cve_id for c in cves]
    status_map: dict = {}
    pending_set: set = set()
    if cve_ids:
        prop_rows = (await db.execute(
            select(CVEEnrichmentProposal)
            .where(
                CVEEnrichmentProposal.cve_id.in_(cve_ids),
                CVEEnrichmentProposal.status.in_(["APPROVED", "REJECTED", "PENDING"]),
            )
            .order_by(desc(CVEEnrichmentProposal.reviewed_at))
        )).scalars().all()
        for p in prop_rows:
            if p.status == "PENDING":
                pending_set.add(p.cve_id)
            elif p.cve_id not in status_map:
                status_map[p.cve_id] = p.status

    from app.services.client_context import redact_content_item_for_role
    items = []
    for c in cves:
        d = CVEResponse.model_validate(c).model_dump(mode="json")
        d["review_status"] = status_map.get(c.cve_id)
        d["has_pending_proposal"] = c.cve_id in pending_set
        d["edited_by"] = c.edited_by
        # Strip cross-tenant match data + internal review status for CLIENT users.
        items.append(redact_content_item_for_role(d, current_user.role))

    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if total > 0 else 0,
    }


@router.get("/{cve_id}", response_model=CVEResponse)
async def get_cve(
    cve_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single CVE by its CVE ID (e.g., CVE-2024-12345)."""
    result = await db.execute(select(CVE).where(CVE.cve_id == cve_id))
    cve = result.scalar_one_or_none()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")

    latest = await db.execute(
        select(CVEEnrichmentProposal.status)
        .where(
            CVEEnrichmentProposal.cve_id == cve_id,
            CVEEnrichmentProposal.status.in_(["APPROVED", "REJECTED"]),
        )
        .order_by(CVEEnrichmentProposal.created_at.desc())
        .limit(1)
    )
    review_status = latest.scalar_one_or_none()
    resp = CVEResponse.model_validate(cve)
    resp.review_status = review_status
    from app.services.client_context import redact_enrichment_for_role
    if current_user.role == UserRole.CLIENT:
        resp.review_status = None
        if hasattr(resp, "edited_by"):
            resp.edited_by = None
    resp.enrichment_data = redact_enrichment_for_role(resp.enrichment_data, current_user.role)
    return resp


@router.post("/", response_model=CVEResponse, status_code=201)
async def create_cve(
    data: CVECreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Create a new CVE entry."""
    existing = await db.execute(select(CVE).where(CVE.cve_id == data.cve_id))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"CVE {data.cve_id} already exists")

    cve = CVE(**data.model_dump())
    db.add(cve)
    await db.flush()
    await db.refresh(cve)
    return CVEResponse.model_validate(cve)


@router.patch("/{cve_id}", response_model=CVEResponse)
async def update_cve(
    cve_id: str,
    data: CVEUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Update a CVE entry."""
    result = await db.execute(select(CVE).where(CVE.cve_id == cve_id))
    cve = result.scalar_one_or_none()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")

    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(cve, field, value)

    cve.edited_by = current_user.full_name or current_user.email

    await log_action(
        db, current_user.email, current_user.role.value,
        "EDIT_CVE", resource_type="cve", resource_id=cve_id,
        details=f"Directly edited CVE {cve_id}: {', '.join(update_data.keys())}",
        event_metadata={"fields_changed": list(update_data.keys()), "cve_id": cve_id},
    )
    await db.flush()
    await db.refresh(cve)
    resp = CVEResponse.model_validate(cve)
    resp.edited_by = cve.edited_by
    return resp


@router.delete("/{cve_id}", status_code=204)
async def delete_cve(
    cve_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """Delete a CVE entry. Admin only."""
    result = await db.execute(select(CVE).where(CVE.cve_id == cve_id))
    cve = result.scalar_one_or_none()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")

    # Delete related proposals
    await db.execute(
        select(CVEEnrichmentProposal).where(CVEEnrichmentProposal.cve_id == cve_id)
    )
    from sqlalchemy import delete as sql_delete
    await db.execute(sql_delete(CVEEnrichmentProposal).where(CVEEnrichmentProposal.cve_id == cve_id))

    await log_action(
        db, current_user.email, current_user.role.value,
        "DELETE_CVE", resource_type="cve", resource_id=cve_id,
        details=f"Deleted CVE {cve_id}",
    )
    await db.delete(cve)
    await db.flush()