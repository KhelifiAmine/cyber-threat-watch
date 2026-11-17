"""
Dashboard API endpoints — accessible by all authenticated users.
"""

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, cast, String
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.threat import Threat, SeverityLevel, ThreatStatus
from app.models.cve import CVE
from app.models.alert import Alert, AlertStatus
from app.models.user import User, UserRole
from app.models.notification import NotificationRecipient, RecipientRole
from app.models.news_article import NewsArticle
from app.api.auth import get_current_user, require_role

router = APIRouter()


# ─── Shared helper: fuzzy product matching ───────────────────

def _product_match(inv_product: str, cve_product: str) -> bool:
    """Check if an inventory product matches a CVE product name.

    Exact match always works. Substring matching only allowed when the shorter
    string is at least 4 characters — prevents false positives like "ise" matching
    "on-premise" or "os" matching "cisco", while allowing "rhel" or "esxi".
    """
    if inv_product == cve_product:
        return True
    shorter = min(len(inv_product), len(cve_product))
    if shorter < 4:
        return False
    return inv_product in cve_product or cve_product in inv_product


def _match_inventory_against_cve(inv_products: set, inv_vendors: set,
                                  enrichment, vendor: str | None) -> str | None:
    """Check if a CVE matches a client's inventory. Returns matched product name or None.

    Matching logic:
      1. If CVE has enrichment affected_products → match against client product families.
         If enrichment exists but no product matched, do NOT fall back to vendor — the CVE
         affects a different product from the same vendor (e.g. Microsoft Office vs Windows Server).
      2. Vendor-only fallback ONLY when CVE has no enrichment at all (un-enriched CVEs where
         vendor is all we have to go on).
    """
    has_enrichment_products = bool(
        enrichment and (enrichment.get("affected_products") or [])
    )
    if has_enrichment_products and inv_products:
        for prod in enrichment["affected_products"]:
            # Try product_family first (clean name), then name, then product_raw
            pname = (
                (prod.get("product_family") or "").strip().lower()
                or (prod.get("name") or "").strip().lower()
                or (prod.get("product_raw") or "").strip().lower()
            )
            if pname and any(_product_match(ip, pname) for ip in inv_products):
                return (prod.get("product_family") or prod.get("name") or prod.get("product_raw", "")).strip()
    # No product-level match — either enrichment listed different products, or
    # CVE has no enrichment at all. Either way, vendor-only is too noisy
    # (e.g. "Microsoft" matches 63 unrelated CVEs). Skip it.
    return None


def _build_inventory_sets(inventory: list) -> tuple[set, set]:
    """Extract lowercase product-family and vendor sets from a client's inventory.

    Uses product_family (e.g. "FortiGate") for matching — this is the right
    granularity: specific enough to avoid noise, broad enough to catch related CVEs.
    """
    products = set()
    vendors = set()
    for item in (inventory or []):
        # product_family is the clean product-line name (e.g. "FortiGate", "FortiWeb")
        pf = (item.get("product_family") or "").strip().lower()
        pr = (item.get("product_raw") or "").strip().lower()
        v = (item.get("vendor") or "").strip().lower()
        if pf:
            products.add(pf)
        elif pr:
            products.add(pr)
        if v:
            vendors.add(v)
    return products, vendors


@router.get("/summary")
async def dashboard_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    total_threats = (await db.execute(select(func.count(Threat.id)))).scalar() or 0
    active_threats = (
        await db.execute(
            select(func.count(Threat.id)).where(Threat.status == ThreatStatus.ACTIVE)
        )
    ).scalar() or 0
    total_cves = (await db.execute(select(func.count(CVE.id)))).scalar() or 0
    open_alerts = (
        await db.execute(
            select(func.count(Alert.id)).where(Alert.status == AlertStatus.NEW)
        )
    ).scalar() or 0

    # Severity breakdown combines threats (enum) + CVEs (varchar) so the
    # pie chart reflects the whole inventory, not just the ~185 threat rows.
    threat_sev_rows = (await db.execute(
        select(Threat.severity, func.count(Threat.id)).group_by(Threat.severity)
    )).all()
    cve_sev_rows = (await db.execute(
        select(CVE.cvss_severity, func.count(CVE.id)).group_by(CVE.cvss_severity)
    )).all()

    def _norm_sev(v):
        if v is None:
            return None
        s = v.value if hasattr(v, "value") else str(v)
        return s.strip().upper()

    severity_breakdown: dict = {}
    for sev, count in list(threat_sev_rows) + list(cve_sev_rows):
        key = _norm_sev(sev)
        if key:
            severity_breakdown[key] = severity_breakdown.get(key, 0) + (count or 0)

    yesterday = datetime.utcnow() - timedelta(hours=24)
    recent_count = (
        await db.execute(
            select(func.count(Threat.id)).where(Threat.created_at >= yesterday)
        )
    ).scalar() or 0

    new_cves_24h = (
        await db.execute(
            select(func.count(CVE.id)).where(CVE.created_at >= yesterday)
        )
    ).scalar() or 0

    avg_risk = (
        await db.execute(select(func.avg(Threat.risk_score)))
    ).scalar() or 0.0

    # Top critical CVEs from the last 30 days, highest score first, newest
    # as a tiebreak so the list rotates with fresh data instead of being
    # permanently pinned to old 9.9/10 CVEs.
    critical_cutoff = datetime.utcnow() - timedelta(days=30)
    critical_cves_query = (
        select(CVE)
        .where(CVE.cvss_base_score >= 9.0)
        .where(CVE.created_at >= critical_cutoff)
        .order_by(CVE.cvss_base_score.desc(), CVE.created_at.desc())
        .limit(5)
    )
    critical_cves_result = await db.execute(critical_cves_query)
    critical_cves = [
        {"cve_id": c.cve_id, "score": c.cvss_base_score, "title": c.title}
        for c in critical_cves_result.scalars().all()
    ]

    return {
        "overview": {
            "total_threats": total_threats,
            "active_threats": active_threats,
            "total_cves": total_cves,
            "open_alerts": open_alerts,
            "threats_last_24h": recent_count,
            "new_cves_24h": new_cves_24h,
            "avg_risk_score": round(avg_risk, 1),
        },
        "severity_breakdown": {
            "critical": severity_breakdown.get("CRITICAL", 0),
            "high": severity_breakdown.get("HIGH", 0),
            "medium": severity_breakdown.get("MEDIUM", 0),
            "low": severity_breakdown.get("LOW", 0),
            "info": severity_breakdown.get("INFO", 0),
        },
        "critical_cves": critical_cves,
    }


@router.get("/trends")
async def dashboard_trends(
    days: int = 7,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    trends = []
    for i in range(days - 1, -1, -1):
        date = datetime.utcnow() - timedelta(days=i)
        start = date.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)

        threats_count = (
            await db.execute(
                select(func.count(Threat.id)).where(
                    Threat.created_at >= start,
                    Threat.created_at < end,
                )
            )
        ).scalar() or 0

        cves_count = (
            await db.execute(
                select(func.count(CVE.id)).where(
                    CVE.created_at >= start,
                    CVE.created_at < end,
                )
            )
        ).scalar() or 0

        trends.append({
            "date": start.strftime("%Y-%m-%d"),
            "count": threats_count,
            "cves": cves_count,
        })

    return {"days": days, "trends": trends}


@router.get("/top-products")
async def dashboard_top_products(
    days: int = Query(30, ge=1, le=365),
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Top mentioned vendors/products across CVEs and threats in the last N days."""
    from collections import Counter

    cutoff = datetime.utcnow() - timedelta(days=days)
    counter: Counter = Counter()

    # CVEs
    cve_rows = (await db.execute(
        select(CVE.enrichment_data).where(
            CVE.created_at >= cutoff,
            CVE.enrichment_data.isnot(None),
        )
    )).scalars().all()

    for enrichment in cve_rows:
        if not enrichment:
            continue
        for product in (enrichment.get("affected_products") or []):
            name = product.get("name", "").strip()
            if name:
                counter[name] += 1

    # Fallback: also count from CVE.vendor and CVE.affected_products text fields
    cve_text_rows = (await db.execute(
        select(CVE.vendor, CVE.affected_products).where(
            CVE.created_at >= cutoff,
        )
    )).all()

    for vendor, products_text in cve_text_rows:
        if vendor and vendor.strip():
            counter[vendor.strip()] += 1
        if products_text and products_text.strip():
            for p in products_text.split(","):
                p = p.strip()
                if p and len(p) > 2:
                    counter[p] += 1

    # Threats
    threat_rows = (await db.execute(
        select(Threat.enrichment_data).where(
            Threat.created_at >= cutoff,
            Threat.enrichment_data.isnot(None),
        )
    )).scalars().all()

    for enrichment in threat_rows:
        if not enrichment:
            continue
        for product in (enrichment.get("affected_products") or []):
            name = product.get("name", "").strip()
            if name:
                counter[name] += 1

    top = [{"name": name, "count": count} for name, count in counter.most_common(limit)]
    return top


@router.get("/sectors")
async def dashboard_sectors(
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Sector distribution derived from enrichment data and descriptions."""
    from collections import Counter
    from app.services.sector_classifier import infer_sectors

    cutoff = datetime.utcnow() - timedelta(days=days)
    counter: Counter = Counter()

    # Threats
    threat_rows = (await db.execute(
        select(Threat.description, Threat.enrichment_data).where(
            Threat.created_at >= cutoff,
        )
    )).all()

    for desc, enrichment in threat_rows:
        text = (desc or "")
        products = []
        if enrichment:
            for p in (enrichment.get("affected_products") or []):
                products.append(p.get("name", ""))
        sectors = infer_sectors(text, products)
        for s in sectors:
            counter[s] += 1

    # CVEs
    cve_rows = (await db.execute(
        select(CVE.description, CVE.enrichment_data).where(
            CVE.created_at >= cutoff,
        )
    )).all()

    for desc, enrichment in cve_rows:
        text = (desc or "")
        products = []
        if enrichment:
            for p in (enrichment.get("affected_products") or []):
                products.append(p.get("name", ""))
        sectors = infer_sectors(text, products)
        for s in sectors:
            counter[s] += 1

    return [{"sector": sector, "count": count} for sector, count in counter.most_common()]


@router.get("/client-coverage")
async def dashboard_client_coverage(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Client coverage stats: total, reached, sector breakdown, top clients."""
    # Total active clients — use the users table as source of truth
    # (notification_recipients roles can be out of sync)
    total_clients = (await db.execute(
        select(func.count(User.id)).where(
            User.role == UserRole.CLIENT,
            User.is_active.is_(True),
        )
    )).scalar() or 0

    # Clients reached = unique clients in sent proposals
    # Count CVEs + Threats with advisory_sent_at set
    cves_sent = (await db.execute(
        select(func.count(CVE.id)).where(CVE.advisory_sent_at.isnot(None))
    )).scalar() or 0

    threats_sent = (await db.execute(
        select(func.count(Threat.id)).where(Threat.advisory_sent_at.isnot(None))
    )).scalar() or 0

    advisories_sent = cves_sent + threats_sent

    # Client sectors from interests
    from collections import Counter
    clients_result = (await db.execute(
        select(NotificationRecipient.interests).where(
            NotificationRecipient.role == RecipientRole.CLIENT,
            NotificationRecipient.is_active.is_(True),
        )
    )).scalars().all()

    sector_counter: Counter = Counter()
    for interests in clients_result:
        if interests:
            for i in interests:
                sector_counter[i] += 1

    by_sector = [{"sector": s, "count": c} for s, c in sector_counter.most_common()]

    return {
        "total_clients": total_clients,
        "advisories_sent": advisories_sent,
        "by_sector": by_sector,
    }


@router.get("/client-status-board")
async def dashboard_client_status_board(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Per-client status: products, open CVEs, unsent count, last advisory, status."""

    # All CLIENT users joined to their notification_recipient records
    client_users = (await db.execute(
        select(User).where(User.role == UserRole.CLIENT, User.is_active.is_(True))
    )).scalars().all()

    # Map email → recipient for inventory lookup
    client_emails = [u.email for u in client_users]
    recipients = {}
    if client_emails:
        recs = (await db.execute(
            select(NotificationRecipient).where(NotificationRecipient.email.in_(client_emails))
        )).scalars().all()
        recipients = {r.email: r for r in recs}

    # Pre-fetch all CVEs (we need to match against each client's inventory)
    all_cves = (await db.execute(
        select(CVE.id, CVE.enrichment_data, CVE.vendor, CVE.advisory_sent_at)
    )).all()

    results = []
    for user in client_users:
        rec = recipients.get(user.email)
        inventory = rec.inventory if rec else []
        sector = (rec.interests[0] if rec and rec.interests else "")
        products_count = len(inventory or [])

        inv_products, inv_vendors = _build_inventory_sets(inventory)

        open_cves = 0
        unsent_cves = 0
        last_advisory_at = None

        if inv_products or inv_vendors:
            for cve_id, enrichment, vendor, sent_at in all_cves:
                match = _match_inventory_against_cve(inv_products, inv_vendors, enrichment, vendor)
                if match:
                    open_cves += 1
                    if sent_at is None:
                        unsent_cves += 1
                    if sent_at and (last_advisory_at is None or sent_at > last_advisory_at):
                        last_advisory_at = sent_at

        # Status: overdue (unsent > 48h or no advisory in 7d while open CVEs exist),
        # needs_attention (unsent exist), current (nothing pending)
        now = datetime.utcnow()
        status = "current"
        if unsent_cves > 0:
            status = "needs_attention"
            days_since_advisory = (now - last_advisory_at).days if last_advisory_at else 999
            if days_since_advisory >= 7 or unsent_cves >= 3:
                status = "overdue"
        elif open_cves > 0 and last_advisory_at:
            days_since = (now - last_advisory_at).days
            if days_since >= 7:
                status = "overdue"

        results.append({
            "id": rec.id if rec else None,
            "user_id": user.id,
            "name": user.full_name or user.email,
            "email": user.email,
            "sector": sector,
            "products_count": products_count,
            "open_cves": open_cves,
            "unsent_cves": unsent_cves,
            "last_advisory_at": last_advisory_at.isoformat() if last_advisory_at else None,
            "status": status,
        })

    # Sort: overdue first, then needs_attention, then current
    order = {"overdue": 0, "needs_attention": 1, "current": 2}
    results.sort(key=lambda x: (order.get(x["status"], 9), -x["unsent_cves"]))
    return results


@router.get("/client-detail/{recipient_id}")
async def dashboard_client_detail(
    recipient_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Full client detail for inline dashboard expansion."""
    from fastapi import HTTPException

    rec = (await db.execute(
        select(NotificationRecipient).where(NotificationRecipient.id == recipient_id)
    )).scalar_one_or_none()
    if not rec:
        raise HTTPException(status_code=404, detail="Client not found")

    inventory = rec.inventory or []
    inv_products, inv_vendors = _build_inventory_sets(inventory)

    # ── Product inventory with per-product CVE counts ──
    all_cves = (await db.execute(
        select(CVE.id, CVE.cve_id, CVE.title, CVE.cvss_base_score,
               CVE.cvss_severity, CVE.enrichment_data, CVE.vendor,
               CVE.advisory_sent_at, CVE.advisory_sent_by, CVE.created_at,
               CVE.source)
    )).all()

    product_cve_counts: dict[str, int] = {}
    cve_exposure = []

    for row in all_cves:
        (db_id, cve_id, title, cvss, severity, enrichment, vendor,
         sent_at, sent_by, created_at, source) = row
        matched_product = _match_inventory_against_cve(inv_products, inv_vendors, enrichment, vendor)
        if matched_product:
            product_cve_counts[matched_product.lower()] = product_cve_counts.get(matched_product.lower(), 0) + 1
            cve_exposure.append({
                "cve_id": cve_id,
                "title": title or "",
                "cvss": cvss,
                "severity": severity or "",
                "product": matched_product,
                "sent_at": sent_at.isoformat() if sent_at else None,
                "sent_by": sent_by or "",
                "created_at": created_at.isoformat() if created_at else None,
                "source": source or "",
                "age_hours": int((datetime.utcnow() - created_at).total_seconds() / 3600) if created_at else 0,
            })

    # Sort CVEs: unsent first, then by CVSS desc
    cve_exposure.sort(key=lambda x: (0 if x["sent_at"] is None else 1, -(x["cvss"] or 0)))

    # Build product inventory display — group by product_family to reduce noise
    family_cve_map: dict[str, dict] = {}
    for item in inventory:
        pf = (item.get("product_family") or "").strip()
        pr = (item.get("product_raw") or "").strip()
        v = (item.get("vendor") or "").strip()
        label = pf or pr or v
        key = label.lower()
        lookup = key  # matches how _build_inventory_sets builds inv_products
        cve_count = product_cve_counts.get(lookup, 0)
        # If no product-level match, check vendor-level
        if cve_count == 0 and v:
            cve_count = product_cve_counts.get(v.lower(), 0)
        if key not in family_cve_map:
            family_cve_map[key] = {
                "product": label,
                "vendor": v,
                "cve_count": cve_count,
            }
        # Keep the higher CVE count (vendor-level counts may overlap)
        elif cve_count > family_cve_map[key]["cve_count"]:
            family_cve_map[key]["cve_count"] = cve_count

    product_inventory = sorted(family_cve_map.values(), key=lambda x: -x["cve_count"])

    # ── Threat exposure (match by client regions) ──
    sector = rec.interests[0] if rec.interests else None
    client_regions = {r.strip().lower() for r in (rec.regions or []) if r.strip()}
    threat_exposure = []
    threats = (await db.execute(
        select(Threat.id, Threat.title, Threat.risk_score, Threat.severity,
               Threat.advisory_sent_at, Threat.created_at, Threat.regions)
        .where(Threat.risk_score >= 50)
        .order_by(Threat.risk_score.desc())
        .limit(100)
    )).all()

    for tid, title, risk, sev, sent_at, created_at, regions in threats:
        # Filter: only threats whose regions overlap with client's regions
        if client_regions:
            threat_regions = {r.strip().lower() for r in (regions or "").split(",") if r.strip()}
            if not (threat_regions & client_regions):
                continue
        threat_exposure.append({
            "id": tid,
            "title": title or "",
            "risk_score": risk,
            "severity": sev.value if hasattr(sev, "value") else str(sev),
            "sent_at": sent_at.isoformat() if sent_at else None,
            "created_at": created_at.isoformat() if created_at else None,
            "regions": regions or "Global",
        })
    threat_exposure = threat_exposure[:20]

    # ── Advisory history ──
    advisory_history = []
    for cve in cve_exposure:
        if cve["sent_at"]:
            advisory_history.append({
                "kind": "CVE",
                "identifier": cve["cve_id"],
                "title": cve["title"],
                "sent_at": cve["sent_at"],
                "sent_by": cve["sent_by"],
            })
    advisory_history.sort(key=lambda x: x["sent_at"] or "", reverse=True)

    return {
        "client": {
            "name": rec.full_name,
            "email": rec.email,
            "company": rec.company or "",
            "sector": sector or "",
            "products_count": len(inventory),
        },
        "product_inventory": product_inventory,
        "cve_exposure": cve_exposure,
        "threat_exposure": threat_exposure,
        "advisory_history": advisory_history,
        "stats": {
            "total_cves": len(cve_exposure),
            "total_products": len(inventory),
            "advisories_received": len(advisory_history),
        },
    }


@router.get("/my-exposure")
async def dashboard_my_exposure(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Client-facing endpoint: returns the caller's own exposure data.
    Resolves the NotificationRecipient from the JWT email — no ID needed."""
    from fastapi import HTTPException
    from app.services.client_context import get_client_recipient

    if current_user.role != UserRole.CLIENT:
        raise HTTPException(status_code=403, detail="This endpoint is for CLIENT users only")

    rec = await get_client_recipient(current_user, db)
    if not rec:
        raise HTTPException(status_code=404, detail="No client profile found for your account")

    return await dashboard_client_detail(rec.id, db, current_user)


@router.get("/unsent-backlog")
async def dashboard_unsent_backlog(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Count of high-risk items with no advisory sent."""
    unsent_cves = (await db.execute(
        select(func.count(CVE.id)).where(
            CVE.advisory_sent_at.is_(None),
            CVE.cvss_base_score >= 7.0,
        )
    )).scalar() or 0

    unsent_threats = (await db.execute(
        select(func.count(Threat.id)).where(
            Threat.advisory_sent_at.is_(None),
            Threat.risk_score >= 70,
        )
    )).scalar() or 0

    # Oldest unsent
    oldest_cve = (await db.execute(
        select(func.min(CVE.created_at)).where(
            CVE.advisory_sent_at.is_(None),
            CVE.cvss_base_score >= 7.0,
        )
    )).scalar()

    oldest_threat = (await db.execute(
        select(func.min(Threat.created_at)).where(
            Threat.advisory_sent_at.is_(None),
            Threat.risk_score >= 70,
        )
    )).scalar()

    oldest = None
    if oldest_cve and oldest_threat:
        oldest = min(oldest_cve, oldest_threat).isoformat()
    elif oldest_cve:
        oldest = oldest_cve.isoformat()
    elif oldest_threat:
        oldest = oldest_threat.isoformat()

    return {
        "unsent_cves": unsent_cves,
        "unsent_threats": unsent_threats,
        "oldest_unsent_date": oldest,
    }


@router.get("/client-exposure")
async def dashboard_client_exposure(
    days: int = Query(30, ge=1, le=365),
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Top clients by CVE exposure — matches client inventories against recent CVEs."""
    cutoff = datetime.utcnow() - timedelta(days=days)

    clients = (await db.execute(
        select(NotificationRecipient).where(
            NotificationRecipient.role == RecipientRole.CLIENT,
            NotificationRecipient.is_active.is_(True),
        )
    )).scalars().all()

    cve_rows = (await db.execute(
        select(CVE.enrichment_data, CVE.vendor).where(CVE.created_at >= cutoff)
    )).all()

    client_results = []
    for client in clients:
        inventory = client.inventory or []
        if not inventory:
            continue

        inv_products, inv_vendors = _build_inventory_sets(inventory)
        matching_cves = 0
        product_hits: dict[str, int] = {}

        for enrichment, vendor in cve_rows:
            matched_product = _match_inventory_against_cve(inv_products, inv_vendors, enrichment, vendor)
            if matched_product:
                matching_cves += 1
                product_hits[matched_product] = product_hits.get(matched_product, 0) + 1

        if matching_cves > 0:
            top_products = sorted(product_hits.items(), key=lambda x: -x[1])[:3]
            client_results.append({
                "client_name": client.full_name,
                "company": client.company or "",
                "sector": (client.interests[0] if client.interests else ""),
                "matching_cve_count": matching_cves,
                "top_products": [{"name": n, "cve_count": c} for n, c in top_products],
            })

    client_results.sort(key=lambda x: -x["matching_cve_count"])
    return client_results[:limit]


@router.get("/regional-landscape")
async def dashboard_regional_landscape(
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Regional threat distribution."""
    from collections import Counter, defaultdict

    cutoff = datetime.utcnow() - timedelta(days=days)

    threat_rows = (await db.execute(
        select(Threat.regions, Threat.risk_score, Threat.severity).where(
            Threat.created_at >= cutoff,
        )
    )).all()

    region_data = defaultdict(lambda: {"threat_count": 0, "news_count": 0, "total_risk": 0.0, "severities": Counter()})

    for regions_str, risk_score, severity in threat_rows:
        # A threat can have multiple comma-separated regions
        regions = [r.strip() for r in (regions_str or "Global").split(",") if r.strip()]
        for region in regions:
            rd = region_data[region]
            rd["threat_count"] += 1
            rd["total_risk"] += (risk_score or 0)
            if severity:
                rd["severities"][severity.value if hasattr(severity, "value") else str(severity).upper()] += 1

    # Also count news articles by affected_regions
    news_rows = (await db.execute(
        select(NewsArticle.enrichment_data).where(
            NewsArticle.created_at >= cutoff,
            NewsArticle.enrichment_data.isnot(None),
        )
    )).all()
    for (enrichment,) in news_rows:
        for r in (enrichment or {}).get("affected_regions", []):
            if isinstance(r, str) and r.strip():
                region_data[r.strip()]["news_count"] += 1

    result = []
    for region, data in region_data.items():
        result.append({
            "region": region,
            "threat_count": data["threat_count"],
            "news_count": data["news_count"],
            "avg_risk_score": round(data["total_risk"] / data["threat_count"], 1) if data["threat_count"] else 0,
            "severity_breakdown": dict(data["severities"]),
        })

    result.sort(key=lambda x: -(x["threat_count"] + x["news_count"]))
    return result


@router.get("/attention-items")
async def dashboard_attention_items(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Items needing analyst attention: unsent high-risk, pending review, spider failures."""
    from app.models.cve_enrichment_proposal import CVEEnrichmentProposal
    from app.models.threat_enrichment_proposal import ThreatEnrichmentProposal
    from app.models.news_enrichment_proposal import NewsEnrichmentProposal
    from app.models.spider_run import SpiderRun

    # Top 5 unsent high-risk CVEs
    unsent_cves = (await db.execute(
        select(CVE.cve_id, CVE.title, CVE.cvss_base_score, CVE.created_at)
        .where(CVE.advisory_sent_at.is_(None), CVE.cvss_base_score >= 7.0)
        .order_by(CVE.cvss_base_score.desc().nullslast(), CVE.created_at.asc())
        .limit(5)
    )).all()

    # Top 5 unsent high-risk threats
    unsent_threats = (await db.execute(
        select(Threat.id, Threat.title, Threat.risk_score, Threat.created_at)
        .where(Threat.advisory_sent_at.is_(None), Threat.risk_score >= 70)
        .order_by(Threat.risk_score.desc(), Threat.created_at.asc())
        .limit(5)
    )).all()

    # Pending review count — include all 3 proposal types to match the proposals API
    pending_cve = (await db.execute(
        select(func.count(CVEEnrichmentProposal.id)).where(CVEEnrichmentProposal.status == "PENDING")
    )).scalar() or 0
    pending_threat = (await db.execute(
        select(func.count(ThreatEnrichmentProposal.id)).where(ThreatEnrichmentProposal.status == "PENDING")
    )).scalar() or 0
    pending_news = (await db.execute(
        select(func.count(NewsEnrichmentProposal.id)).where(NewsEnrichmentProposal.status == "PENDING")
    )).scalar() or 0

    # Failed spiders in last 24h
    day_ago = datetime.utcnow() - timedelta(hours=24)
    failed_spiders = (await db.execute(
        select(SpiderRun.spider_name, SpiderRun.error_message, SpiderRun.finished_at)
        .where(SpiderRun.status == "FAILURE", SpiderRun.finished_at >= day_ago)
        .order_by(SpiderRun.finished_at.desc())
    )).all()

    # Oldest unsent age
    oldest_cve_time = (await db.execute(
        select(func.min(CVE.created_at)).where(CVE.advisory_sent_at.is_(None), CVE.cvss_base_score >= 7.0)
    )).scalar()
    oldest_threat_time = (await db.execute(
        select(func.min(Threat.created_at)).where(Threat.advisory_sent_at.is_(None), Threat.risk_score >= 70)
    )).scalar()

    oldest_time = None
    if oldest_cve_time and oldest_threat_time:
        oldest_time = min(oldest_cve_time, oldest_threat_time)
    elif oldest_cve_time:
        oldest_time = oldest_cve_time
    elif oldest_threat_time:
        oldest_time = oldest_threat_time

    oldest_age_hours = 0
    if oldest_time:
        oldest_age_hours = int((datetime.utcnow() - oldest_time).total_seconds() / 3600)

    # Pre-compute affected clients for the unsent CVEs (bounded to top 5+5)
    clients = (await db.execute(
        select(NotificationRecipient).where(
            NotificationRecipient.role == RecipientRole.CLIENT,
            NotificationRecipient.is_active.is_(True),
        )
    )).scalars().all()

    # Build per-client inventory sets once
    client_inventories = []
    for client in clients:
        inv = client.inventory or []
        if not inv:
            continue
        prods, vends = _build_inventory_sets(inv)
        client_inventories.append((client.full_name, prods, vends))

    def _find_affected_clients(enrichment, vendor):
        affected = []
        for name, prods, vends in client_inventories:
            if _match_inventory_against_cve(prods, vends, enrichment, vendor):
                affected.append(name)
        return affected

    # Fetch enrichment data for unsent CVEs to match clients
    unsent_cve_ids = [c[0] for c in unsent_cves]
    cve_enrichments = {}
    if unsent_cve_ids:
        enr_rows = (await db.execute(
            select(CVE.cve_id, CVE.enrichment_data, CVE.vendor)
            .where(CVE.cve_id.in_(unsent_cve_ids))
        )).all()
        for cid, enr, vnd in enr_rows:
            cve_enrichments[cid] = (enr, vnd)

    unsent_cves_out = []
    for c in unsent_cves:
        cve_id = c[0]
        enr, vnd = cve_enrichments.get(cve_id, (None, None))
        unsent_cves_out.append({
            "cve_id": cve_id,
            "title": c[1],
            "cvss": c[2],
            "created_at": c[3].isoformat() if c[3] else None,
            "affected_clients": _find_affected_clients(enr, vnd),
        })

    return {
        "unsent_cves": unsent_cves_out,
        "unsent_threats": [
            {"id": t[0], "title": t[1], "risk_score": t[2], "created_at": t[3].isoformat() if t[3] else None}
            for t in unsent_threats
        ],
        "pending_review_count": pending_cve + pending_threat + pending_news,
        "failed_spiders": [
            {"name": f[0], "last_error": (f[1] or "")[:200], "failed_at": f[2].isoformat() if f[2] else None}
            for f in failed_spiders
        ],
        "oldest_unsent_age_hours": oldest_age_hours,
    }


@router.get("/spider-analytics")
async def dashboard_spider_analytics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Per-spider performance analytics: success rate, avg items, client match count."""
    from app.models.spider_run import SpiderRun
    from sqlalchemy import distinct

    # Get all distinct spider names
    spider_names = (await db.execute(
        select(distinct(SpiderRun.spider_name))
    )).scalars().all()

    results = []
    for spider in spider_names:
        # Last 7 runs
        runs = (await db.execute(
            select(SpiderRun.status, SpiderRun.items_scraped, SpiderRun.items_new, SpiderRun.started_at)
            .where(SpiderRun.spider_name == spider)
            .order_by(SpiderRun.started_at.desc().nullslast())
            .limit(7)
        )).all()

        if not runs:
            continue

        total_runs = len(runs)
        successful = sum(1 for r in runs if r[0] == "SUCCESS")
        success_rate = round(successful / total_runs * 100) if total_runs else 0
        avg_items = round(sum(r[1] or 0 for r in runs) / total_runs) if total_runs else 0

        # Count CVEs/Threats from this spider that matched clients
        client_matched = 0
        cve_matches = (await db.execute(
            select(func.count(CVE.id)).where(
                CVE.source == spider,
                CVE.enrichment_data.isnot(None),
                cast(CVE.enrichment_data["client_matches"].astext, String) != "[]",
                cast(CVE.enrichment_data["client_matches"].astext, String) != "null",
            )
        )).scalar() or 0

        threat_matches = (await db.execute(
            select(func.count(Threat.id)).where(
                Threat.source == spider,
                Threat.enrichment_data.isnot(None),
                cast(Threat.enrichment_data["client_matches"].astext, String) != "[]",
                cast(Threat.enrichment_data["client_matches"].astext, String) != "null",
            )
        )).scalar() or 0

        client_matched = cve_matches + threat_matches

        results.append({
            "spider": spider,
            "success_rate_pct": success_rate,
            "avg_items_per_run": avg_items,
            "client_matched_count": client_matched,
            "runs": [
                {
                    "date": r[3].isoformat() if r[3] else None,
                    "items": r[1] or 0,
                    "status": r[0],
                }
                for r in reversed(runs)  # chronological order for sparklines
            ],
        })

    results.sort(key=lambda x: -x["client_matched_count"])
    return results


@router.post("/report-data")
async def generate_report_data(
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Generate all report data in one call based on selected modules."""
    from collections import Counter, defaultdict
    from app.models.notification import NotificationRecipient, RecipientRole
    from app.models.spider_run import SpiderRun

    days = body.get("days", 30)
    modules = set(body.get("modules", []))
    cutoff = datetime.utcnow() - timedelta(days=days)
    result = {}

    # ── Executive Summary ──
    if "overview" in modules:
        total_threats = (await db.execute(select(func.count(Threat.id)))).scalar() or 0
        active_threats = (await db.execute(
            select(func.count(Threat.id)).where(Threat.status == ThreatStatus.ACTIVE)
        )).scalar() or 0
        total_cves = (await db.execute(select(func.count(CVE.id)))).scalar() or 0
        open_alerts = (await db.execute(
            select(func.count(Alert.id)).where(Alert.status == AlertStatus.NEW)
        )).scalar() or 0
        yesterday = datetime.utcnow() - timedelta(hours=24)
        threats_24h = (await db.execute(
            select(func.count(Threat.id)).where(Threat.created_at >= yesterday)
        )).scalar() or 0
        cves_24h = (await db.execute(
            select(func.count(CVE.id)).where(CVE.created_at >= yesterday)
        )).scalar() or 0
        avg_risk = (await db.execute(select(func.avg(Threat.risk_score)))).scalar() or 0.0

        result["overview"] = {
            "total_threats": total_threats, "active_threats": active_threats,
            "total_cves": total_cves, "open_alerts": open_alerts,
            "threats_last_24h": threats_24h, "new_cves_24h": cves_24h,
            "avg_risk_score": round(avg_risk, 1),
        }

    # ── Severity Breakdown ──
    if "severity" in modules:
        threat_sev = (await db.execute(
            select(Threat.severity, func.count(Threat.id))
            .where(Threat.created_at >= cutoff)
            .group_by(Threat.severity)
        )).all()
        cve_sev = (await db.execute(
            select(CVE.cvss_severity, func.count(CVE.id))
            .where(CVE.created_at >= cutoff)
            .group_by(CVE.cvss_severity)
        )).all()

        sev_map: dict = {}
        for sev, count in list(threat_sev) + list(cve_sev):
            key = (sev.value if hasattr(sev, "value") else str(sev)).strip().upper() if sev else None
            if key:
                sev_map[key] = sev_map.get(key, 0) + (count or 0)

        result["severity"] = {
            "critical": sev_map.get("CRITICAL", 0), "high": sev_map.get("HIGH", 0),
            "medium": sev_map.get("MEDIUM", 0), "low": sev_map.get("LOW", 0),
            "info": sev_map.get("INFO", 0),
        }

    # ── Top Products ──
    if "products" in modules:
        counter: Counter = Counter()
        cve_rows = (await db.execute(
            select(CVE.enrichment_data, CVE.vendor, CVE.affected_products)
            .where(CVE.created_at >= cutoff)
        )).all()
        for enrichment, vendor, products_text in cve_rows:
            if enrichment:
                for p in (enrichment.get("affected_products") or []):
                    name = (p.get("name") or "").strip()
                    if name:
                        counter[name] += 1
            if vendor and vendor.strip():
                counter[vendor.strip()] += 1
            if products_text and products_text.strip():
                for p in products_text.split(","):
                    p = p.strip()
                    if p and len(p) > 2:
                        counter[p] += 1

        result["products"] = [{"name": n, "count": c} for n, c in counter.most_common(15)]

    # ── Sectors ──
    if "sectors" in modules:
        from app.services.sector_classifier import infer_sectors
        sector_counter: Counter = Counter()
        rows = (await db.execute(
            select(Threat.description, Threat.enrichment_data).where(Threat.created_at >= cutoff)
        )).all()
        for desc, enrichment in rows:
            products = [p.get("name", "") for p in (enrichment or {}).get("affected_products", [])]
            for s in infer_sectors(desc or "", products):
                sector_counter[s] += 1
        cve_rows2 = (await db.execute(
            select(CVE.description, CVE.enrichment_data).where(CVE.created_at >= cutoff)
        )).all()
        for desc, enrichment in cve_rows2:
            products = [p.get("name", "") for p in (enrichment or {}).get("affected_products", [])]
            for s in infer_sectors(desc or "", products):
                sector_counter[s] += 1

        result["sectors"] = [{"sector": s, "count": c} for s, c in sector_counter.most_common()]

    # ── Regional Landscape (Threats + News) ──
    if "regions" in modules:
        region_data = defaultdict(lambda: {"threat_count": 0, "news_count": 0, "total_risk": 0.0, "severities": Counter()})
        threat_rows = (await db.execute(
            select(Threat.regions, Threat.risk_score, Threat.severity).where(Threat.created_at >= cutoff)
        )).all()
        for regions_str, risk_score, severity in threat_rows:
            regions = [r.strip() for r in (regions_str or "Global").split(",") if r.strip()]
            for region in regions:
                rd = region_data[region]
                rd["threat_count"] += 1
                rd["total_risk"] += (risk_score or 0)
                if severity:
                    rd["severities"][severity.value if hasattr(severity, "value") else str(severity).upper()] += 1

        # News regions
        news_reg = (await db.execute(
            select(NewsArticle.enrichment_data).where(
                NewsArticle.created_at >= cutoff,
                NewsArticle.enrichment_data.isnot(None),
            )
        )).all()
        for (enrichment,) in news_reg:
            for r in (enrichment or {}).get("affected_regions", []):
                if isinstance(r, str) and r.strip():
                    region_data[r.strip()]["news_count"] += 1

        result["regions"] = sorted([
            {
                "region": region, "threat_count": data["threat_count"],
                "news_count": data["news_count"],
                "avg_risk_score": round(data["total_risk"] / data["threat_count"], 1) if data["threat_count"] else 0,
                "severity_breakdown": dict(data["severities"]),
            }
            for region, data in region_data.items()
        ], key=lambda x: -(x["threat_count"] + x["news_count"]))

    # ── Client Exposure ──
    if "exposure" in modules:
        clients = (await db.execute(
            select(NotificationRecipient).where(
                NotificationRecipient.role == RecipientRole.CLIENT,
                NotificationRecipient.is_active.is_(True),
            )
        )).scalars().all()

        cve_rows3 = (await db.execute(
            select(CVE.cve_id, CVE.title, CVE.enrichment_data, CVE.vendor, CVE.affected_products)
            .where(CVE.created_at >= cutoff)
        )).all()

        client_results = []
        for client in clients:
            inventory = client.inventory or []
            if not inventory:
                continue
            inv_products = {(item.get("product") or "").strip().lower() for item in inventory if (item.get("product") or "").strip()}
            inv_vendors = {(item.get("vendor") or "").strip().lower() for item in inventory if (item.get("vendor") or "").strip()}
            matching = 0
            for _, _, enrichment, vendor, _ in cve_rows3:
                if enrichment:
                    for prod in (enrichment.get("affected_products") or []):
                        pname = (prod.get("name") or "").strip().lower()
                        if pname and (pname in inv_products or any(ip in pname or pname in ip for ip in inv_products)):
                            matching += 1
                            break
                    else:
                        if vendor and vendor.strip().lower() in inv_vendors:
                            matching += 1
                elif vendor and vendor.strip().lower() in inv_vendors:
                    matching += 1

            if matching > 0:
                client_results.append({
                    "client_name": client.full_name, "company": client.company or "",
                    "matching_cve_count": matching,
                })

        client_results.sort(key=lambda x: -x["matching_cve_count"])
        result["exposure"] = client_results[:10]

    # ── Advisory History ──
    if "advisories" in modules:
        sent_cves = (await db.execute(
            select(CVE.cve_id, CVE.title, CVE.advisory_sent_at, CVE.advisory_sent_by)
            .where(CVE.advisory_sent_at.isnot(None), CVE.advisory_sent_at >= cutoff)
            .order_by(CVE.advisory_sent_at.desc())
        )).all()

        sent_threats = (await db.execute(
            select(Threat.id, Threat.title, Threat.advisory_sent_at, Threat.advisory_sent_by)
            .where(Threat.advisory_sent_at.isnot(None), Threat.advisory_sent_at >= cutoff)
            .order_by(Threat.advisory_sent_at.desc())
        )).all()

        advisory_list = []
        for cve_id, title, sent_at, sent_by in sent_cves:
            advisory_list.append({
                "kind": "CVE", "identifier": cve_id, "title": title or "",
                "sent_at": sent_at.isoformat() if sent_at else None,
                "sent_by": sent_by or "",
            })
        for tid, title, sent_at, sent_by in sent_threats:
            advisory_list.append({
                "kind": "Threat", "identifier": str(tid), "title": title or "",
                "sent_at": sent_at.isoformat() if sent_at else None,
                "sent_by": sent_by or "",
            })
        advisory_list.sort(key=lambda x: x["sent_at"] or "", reverse=True)
        result["advisories"] = advisory_list

    # ── Spider Performance ──
    if "spiders" in modules:
        from sqlalchemy import distinct as dist
        spider_names = (await db.execute(select(dist(SpiderRun.spider_name)))).scalars().all()
        spider_list = []
        for spider in spider_names:
            runs = (await db.execute(
                select(SpiderRun.status, SpiderRun.items_scraped, SpiderRun.started_at)
                .where(SpiderRun.spider_name == spider)
                .order_by(SpiderRun.started_at.desc().nullslast())
                .limit(7)
            )).all()
            if not runs:
                continue
            total = len(runs)
            ok = sum(1 for r in runs if r[0] == "SUCCESS")
            avg = round(sum(r[1] or 0 for r in runs) / total) if total else 0
            spider_list.append({
                "spider": spider, "success_rate_pct": round(ok / total * 100) if total else 0,
                "avg_items_per_run": avg, "total_runs": total,
            })
        result["spiders"] = spider_list

    # ── Critical CVEs ──
    if "cves" in modules:
        crit = (await db.execute(
            select(CVE.cve_id, CVE.title, CVE.cvss_base_score)
            .where(CVE.cvss_base_score >= 9.0, CVE.created_at >= cutoff)
            .order_by(CVE.cvss_base_score.desc(), CVE.created_at.desc())
            .limit(10)
        )).all()
        result["cves"] = [{"cve_id": c[0], "title": c[1] or "", "score": c[2]} for c in crit]

    result["generated_at"] = datetime.utcnow().isoformat()
    result["days"] = days
    result["analyst"] = current_user.full_name or current_user.email

    return result