"""
News API endpoints — CRUD, flag for review, direct send.
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, desc, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.news_article import NewsArticle, NewsStatus
from app.models.news_enrichment_proposal import NewsEnrichmentProposal
from app.models.user import User, UserRole
from app.schemas.news import NewsArticleUpdate, NewsArticleResponse
from app.api.auth import get_current_user, require_role
from app.services.audit import log_action

router = APIRouter()


@router.get("/")
async def list_news(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    source: Optional[str] = None,
    sector: Optional[str] = None,
    status: Optional[str] = None,
    sent: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "newest",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List news articles with filtering and pagination.

    CLIENT users see only news matching their profile (via client_matches).
    """
    query = select(NewsArticle)

    # CLIENT auto-filter: match news by client sectors (interests) and regions
    if current_user.role == UserRole.CLIENT:
        from app.services.client_context import get_client_recipient
        rec = await get_client_recipient(current_user, db)
        if not rec:
            return {"items": [], "total": 0, "page": page, "per_page": per_page, "pages": 0}
        client_sectors = {s.strip().lower() for s in (rec.interests or [])}
        client_regions = {r.strip().lower() for r in (rec.regions or [])}
        if not client_sectors and not client_regions:
            return {"items": [], "total": 0, "page": page, "per_page": per_page, "pages": 0}
        # Match news by sector overlap OR region overlap
        all_rows = (await db.execute(
            select(NewsArticle.id, NewsArticle.sectors, NewsArticle.enrichment_data)
        )).all()
        matching_ids = []
        for nid, sectors, enrichment in all_rows:
            news_sectors = {s.strip().lower() for s in (sectors or [])}
            if client_sectors and news_sectors & client_sectors:
                matching_ids.append(nid)
                continue
            news_regions = {r.strip().lower() for r in ((enrichment or {}).get("affected_regions", []))}
            if client_regions and news_regions & client_regions:
                matching_ids.append(nid)
        if not matching_ids:
            return {"items": [], "total": 0, "page": page, "per_page": per_page, "pages": 0}
        query = query.where(NewsArticle.id.in_(matching_ids))

    if source:
        query = query.where(NewsArticle.source == source)
    if sector:
        # Check if sector is in the JSONB array
        query = query.where(NewsArticle.sectors.contains([sector]))
    if status:
        query = query.where(NewsArticle.status == status)
    else:
        # By default, hide FLAGGED articles — they live in the Review Queue
        query = query.where(NewsArticle.status != NewsStatus.FLAGGED)
    if sent == "true":
        query = query.where(NewsArticle.advisory_sent_at.isnot(None))
    elif sent == "false":
        query = query.where(NewsArticle.advisory_sent_at.is_(None))
    if search:
        term = f"%{search.strip()}%"
        query = query.where(or_(
            NewsArticle.title.ilike(term),
            NewsArticle.summary.ilike(term),
            NewsArticle.description.ilike(term),
        ))

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    if sort_by == "oldest":
        query = query.order_by(NewsArticle.published_at.asc().nullslast())
    else:
        query = query.order_by(desc(NewsArticle.published_at).nullslast(), desc(NewsArticle.created_at))

    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page)

    result = await db.execute(query)
    articles = result.scalars().all()

    from app.services.client_context import redact_content_item_for_role
    items = []
    for a in articles:
        d = NewsArticleResponse.model_validate(a).model_dump(mode="json")
        # Strip cross-tenant match data + internal review status for CLIENT users.
        items.append(redact_content_item_for_role(d, current_user.role))

    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if total > 0 else 0,
    }


@router.get("/{news_id}", response_model=NewsArticleResponse)
async def get_news(
    news_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(NewsArticle).where(NewsArticle.id == news_id))
    article = result.scalar_one_or_none()
    if not article:
        raise HTTPException(status_code=404, detail="News article not found")
    from app.services.client_context import redact_enrichment_for_role
    resp = NewsArticleResponse.model_validate(article)
    if current_user.role == UserRole.CLIENT:
        if hasattr(resp, "review_status"):
            resp.review_status = None
        if hasattr(resp, "edited_by"):
            resp.edited_by = None
    resp.enrichment_data = redact_enrichment_for_role(resp.enrichment_data, current_user.role)
    return resp


@router.patch("/{news_id}", response_model=NewsArticleResponse)
async def update_news(
    news_id: int,
    data: NewsArticleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    result = await db.execute(select(NewsArticle).where(NewsArticle.id == news_id))
    article = result.scalar_one_or_none()
    if not article:
        raise HTTPException(status_code=404, detail="News article not found")

    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(article, field, value)

    article.edited_by = current_user.full_name or current_user.email
    article.updated_at = datetime.utcnow()

    await log_action(
        db, current_user.email, current_user.role.value,
        "EDIT_NEWS", resource_type="news", resource_id=str(news_id),
        details=f"Edited news article {news_id}: {', '.join(update_data.keys())}",
        event_metadata={"fields_changed": list(update_data.keys()), "news_id": news_id},
    )
    await db.flush()
    await db.refresh(article)
    return NewsArticleResponse.model_validate(article)


@router.delete("/{news_id}", status_code=204)
async def delete_news(
    news_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    result = await db.execute(select(NewsArticle).where(NewsArticle.id == news_id))
    article = result.scalar_one_or_none()
    if not article:
        raise HTTPException(status_code=404, detail="News article not found")
    await db.delete(article)


class FlagRequest(BaseModel):
    note: Optional[str] = None


@router.post("/{news_id}/flag")
async def flag_news(
    news_id: int,
    body: FlagRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Flag a news article for review — creates a NewsEnrichmentProposal."""
    result = await db.execute(select(NewsArticle).where(NewsArticle.id == news_id))
    article = result.scalar_one_or_none()
    if not article:
        raise HTTPException(status_code=404, detail="News article not found")

    # Check for existing pending proposal
    existing = await db.execute(
        select(NewsEnrichmentProposal).where(
            NewsEnrichmentProposal.news_id == news_id,
            NewsEnrichmentProposal.status == "PENDING",
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="News article is already in review")

    article.status = NewsStatus.FLAGGED
    article.review_status = "PENDING"

    proposal = NewsEnrichmentProposal(
        news_id=news_id,
        source=f"manual:{current_user.email}",
        origin="MANUAL",
        proposed_fields={},
        status="PENDING",
        flag_note=body.note,
        created_at=datetime.utcnow(),
    )
    db.add(proposal)

    await log_action(
        db, current_user.email, current_user.role.value,
        "FLAG_NEWS", resource_type="news", resource_id=str(news_id),
        details=body.note or "Flagged for review",
        event_metadata={"news_id": news_id, "flag_note": body.note},
    )
    await db.flush()
    return {"status": "flagged", "proposal_id": proposal.id}


class NewsSendRequest(BaseModel):
    recipient_ids: Optional[list[int]] = None


@router.post("/{news_id}/send")
async def send_news_direct(
    news_id: int,
    body: NewsSendRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Send a news advisory directly from a news article."""
    from app.services.email_service import get_forward_recipients, send_news_email

    result = await db.execute(select(NewsArticle).where(NewsArticle.id == news_id))
    article = result.scalar_one_or_none()
    if not article:
        raise HTTPException(status_code=404, detail="News article not found")

    # Validate mandatory fields
    errors = []
    if not (article.title or "").strip():
        errors.append("Title is required")
    if not (article.summary or "").strip():
        errors.append("Summary is required")
    if not (article.description or "").strip() or len((article.description or "").strip()) < 20:
        errors.append("Description is required (minimum 20 characters)")
    if not (article.sectors or []):
        errors.append("At least one sector is required")
    if not body.recipient_ids:
        errors.append("At least one recipient must be selected")
    if errors:
        raise HTTPException(status_code=422, detail=errors)

    recipients_data = get_forward_recipients(body.recipient_ids)
    if not recipients_data:
        raise HTTPException(status_code=400, detail="No active client recipients found")

    recipient_emails = [r["email"] for r in recipients_data]

    # Generate news ID — use published_at so the date reflects the article, not the send time
    pub = article.published_at or datetime.utcnow()
    news_id_str = f"NEWS-{pub.strftime('%y%m%d')}-{article.id:04d}"

    success = send_news_email(
        to_emails=recipient_emails,
        news_id=news_id_str,
        title=article.title,
        summary=article.summary or "",
        description=article.description or "",
        sectors=article.sectors or [],
        source=article.source,
        published_date=article.published_at.strftime("%d %B %Y") if article.published_at else "",
        enrichment_data=article.enrichment_data,
    )
    if not success:
        raise HTTPException(status_code=500, detail="Failed to send email — check SMTP configuration")

    article.advisory_sent_at = now
    article.advisory_sent_by = current_user.email
    article.status = NewsStatus.REVIEWED

    await log_action(
        db, current_user.email, current_user.role.value,
        "SEND_NEWS_ADVISORY", resource_type="news", resource_id=str(news_id),
        details=f"Sent news advisory for '{article.title[:60]}' to {len(recipient_emails)} recipients",
        event_metadata={
            "news_id": news_id,
            "news_id_str": news_id_str,
            "recipient_count": len(recipient_emails),
        },
    )
    await db.flush()
    return {"sent_to": len(recipient_emails), "news_id": news_id_str}
