"""
Reports API — Generate report data and export PDF.
"""

import asyncio
import base64
import os
from datetime import datetime, timedelta
from io import BytesIO

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.threat import Threat, SeverityLevel, ThreatStatus
from app.models.cve import CVE
from app.models.alert import Alert, AlertStatus
from app.models.user import User, UserRole
from app.models.notification import NotificationRecipient, RecipientRole
from app.models.news_article import NewsArticle
from app.api.auth import get_current_user, require_role
from app.api.dashboard import _build_inventory_sets, _match_inventory_against_cve

router = APIRouter()

# Limit concurrent Playwright PDF renders
_pdf_semaphore = asyncio.Semaphore(2)


@router.post("/generate-data")
async def generate_report_data(
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Generate report data for either general or client report."""
    from collections import Counter, defaultdict
    from app.models.spider_run import SpiderRun

    report_type = body.get("report_type", "general")  # "general" or "client"
    days = body.get("days", 30)
    modules = set(body.get("modules", []))
    client_id = body.get("client_id")
    cutoff = datetime.utcnow() - timedelta(days=days)
    result = {"report_type": report_type}

    # ── Executive Summary / Overview ──
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

        # News stats
        total_news = (await db.execute(
            select(func.count(NewsArticle.id)).where(NewsArticle.created_at >= cutoff)
        )).scalar() or 0

        result["overview"] = {
            "total_threats": total_threats, "active_threats": active_threats,
            "total_cves": total_cves, "open_alerts": open_alerts,
            "threats_last_24h": threats_24h, "new_cves_24h": cves_24h,
            "avg_risk_score": round(avg_risk, 1),
            "total_news": total_news,
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

        # Also count news by sector
        news_rows = (await db.execute(
            select(NewsArticle.sectors).where(NewsArticle.created_at >= cutoff)
        )).all()
        for (sectors,) in news_rows:
            if isinstance(sectors, list):
                for s in sectors:
                    if s:
                        sector_counter[s] += 1

        result["sectors"] = [{"sector": s, "count": c} for s, c in sector_counter.most_common()]

    # ── Regional Landscape (Threats + News) ──
    if "regions" in modules:
        region_data = defaultdict(lambda: {"threat_count": 0, "news_count": 0, "total_risk": 0.0, "severities": Counter()})

        # Threats
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

        # News
        news_enrichment = (await db.execute(
            select(NewsArticle.enrichment_data).where(
                NewsArticle.created_at >= cutoff,
                NewsArticle.enrichment_data.isnot(None),
            )
        )).all()
        for (enrichment,) in news_enrichment:
            for r in (enrichment or {}).get("affected_regions", []):
                if isinstance(r, str) and r.strip():
                    region_data[r.strip()]["news_count"] += 1

        result["regions"] = sorted([
            {
                "region": region,
                "threat_count": data["threat_count"],
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
            inv_products, inv_vendors = _build_inventory_sets(inventory)
            matching = 0
            for _, _, enrichment, vendor, _ in cve_rows3:
                if _match_inventory_against_cve(inv_products, inv_vendors, enrichment, vendor):
                    matching += 1

            if matching > 0:
                client_results.append({
                    "client_name": client.full_name, "company": client.company or "",
                    "matching_cve_count": matching,
                    "regions": client.regions or [],
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
        # News advisories
        sent_news = (await db.execute(
            select(NewsArticle.id, NewsArticle.title, NewsArticle.advisory_sent_at, NewsArticle.advisory_sent_by)
            .where(NewsArticle.advisory_sent_at.isnot(None), NewsArticle.advisory_sent_at >= cutoff)
            .order_by(NewsArticle.advisory_sent_at.desc())
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
        for nid, title, sent_at, sent_by in sent_news:
            advisory_list.append({
                "kind": "News", "identifier": str(nid), "title": title or "",
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
            select(CVE.cve_id, CVE.title, CVE.cvss_base_score, CVE.cvss_severity, CVE.vendor)
            .where(CVE.cvss_base_score >= 9.0, CVE.created_at >= cutoff)
            .order_by(CVE.cvss_base_score.desc(), CVE.created_at.desc())
            .limit(10)
        )).all()
        result["cves"] = [
            {"cve_id": c[0], "title": c[1] or "", "score": c[2], "severity": c[3] or "", "vendor": c[4] or ""}
            for c in crit
        ]

    # ── Client-specific data (for client reports) ──
    if report_type == "client" and client_id:
        rec = (await db.execute(
            select(NotificationRecipient).where(NotificationRecipient.id == int(client_id))
        )).scalar_one_or_none()
        if not rec:
            raise HTTPException(status_code=404, detail="Client not found")

        inventory = rec.inventory or []
        inv_products, inv_vendors = _build_inventory_sets(inventory)

        # CVE exposure for this client
        all_cves = (await db.execute(
            select(CVE.cve_id, CVE.title, CVE.cvss_base_score, CVE.cvss_severity,
                   CVE.enrichment_data, CVE.vendor, CVE.created_at, CVE.source)
            .where(CVE.created_at >= cutoff)
        )).all()

        cve_exposure = []
        product_counter: Counter = Counter()
        for cve_id, title, cvss, severity, enrichment, vendor, created_at, source in all_cves:
            matched = _match_inventory_against_cve(inv_products, inv_vendors, enrichment, vendor)
            if matched:
                product_counter[matched] += 1
                cve_exposure.append({
                    "cve_id": cve_id, "title": title or "",
                    "cvss": cvss, "severity": severity or "",
                    "product": matched,
                    "created_at": created_at.isoformat() if created_at else None,
                    "source": source or "",
                })
        cve_exposure.sort(key=lambda x: -(x["cvss"] or 0))

        # Regional exposure — cross-reference client regions with news/threat regions
        client_regions = rec.regions or []
        regional_exposure = []
        if client_regions and "regions" in result:
            for reg_data in result["regions"]:
                if reg_data["region"] in client_regions:
                    regional_exposure.append(reg_data)

        result["client_data"] = {
            "client": {
                # Clients are companies: the company name is the identity.
                "name": rec.company or rec.full_name,
                "email": rec.email,
                "company": rec.company or rec.full_name or "",
                "sector": rec.interests[0] if rec.interests else "",
                "regions": client_regions,
                "products_count": len(inventory),
            },
            "cve_exposure": cve_exposure,
            "products_by_cve": [{"name": n, "count": c} for n, c in product_counter.most_common(10)],
            "regional_exposure": regional_exposure,
            "stats": {
                "total_cves": len(cve_exposure),
                "total_products": len(inventory),
            },
        }

    result["generated_at"] = datetime.utcnow().isoformat()
    result["days"] = days
    result["analyst"] = current_user.full_name or current_user.email

    return result


@router.post("/export-pdf")
async def export_pdf(
    body: dict,
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """Render edited report data as a branded PDF via Playwright."""
    from jinja2 import FileSystemLoader
    from jinja2.sandbox import SandboxedEnvironment

    template_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "templates"
    )
    jinja_env = SandboxedEnvironment(
        loader=FileSystemLoader(template_dir),
        autoescape=True,
    )
    # Load Logo as base64 for embedding in PDF
    logo_path = os.path.join(template_dir, "logo.png")
    logo_b64 = ""
    if os.path.exists(logo_path):
        with open(logo_path, "rb") as f:
            logo_b64 = base64.b64encode(f.read()).decode()

    template = jinja_env.get_template("report_pdf.html")
    html = template.render(
        report=body,
        year=datetime.utcnow().year,
        logo_b64=logo_b64,
    )

    async with _pdf_semaphore:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.set_content(html, wait_until="networkidle")
            pdf_bytes = await page.pdf(
                format="A4",
                margin={"top": "20mm", "bottom": "20mm", "left": "15mm", "right": "15mm"},
                print_background=True,
            )
            await browser.close()

    report_type = body.get("report_type", "general")
    filename = f"CTW_{report_type.title()}_Report_{datetime.utcnow().strftime('%Y%m%d')}.pdf"

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
