"""
Scraper API — Manual triggers, run history, live log streaming, and schedule info.
"""
import os
import asyncio
from datetime import datetime, timezone
from typing import Optional

import redis as redis_lib
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_serializer
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import require_role
from app.models.user import User, UserRole
from app.models.spider_run import SpiderRun
from app.database import get_db
from app.services.audit import log_action

router = APIRouter()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Vendor spiders — scheduled via Celery Beat
SCHEDULE_INFO = {
    "fortiguard": {"interval_seconds": 21600, "label": "Every 6 hours"},
    "cisco":      {"interval_seconds": 21600, "label": "Every 6 hours"},
    "microsoft":  {"interval_seconds": 43200, "label": "Every 12 hours"},
}

# News spiders — scheduled every 2 hours via Celery Beat
NEWS_SCHEDULE_INFO = {
    "bleepingcomputer": {"interval_seconds": 7200, "label": "Every 2 hours"},
    "thehackernews":    {"interval_seconds": 7200, "label": "Every 2 hours"},
    "darkreading":      {"interval_seconds": 7200, "label": "Every 2 hours"},
    "securityweek":     {"interval_seconds": 7200, "label": "Every 2 hours"},
}

# General spiders — manual only, no schedule
GENERAL_SPIDERS = ["nvd", "github", "certfr", "certeu"]


# ─── Schemas ──────────────────────────────────────────────

class ScrapeResponse(BaseModel):
    message: str
    task_id: str
    spider: str

class ScrapeAllResponse(BaseModel):
    message: str
    tasks: list

class SpiderRunResponse(BaseModel):
    id: int
    spider_name: str
    task_id: str
    status: str
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    items_scraped: int
    items_new: int
    items_duplicate: int
    items_dropped_nlp: int
    items_dropped_clean: int
    alerts_created: int
    triggered_by: str
    error_message: Optional[str]

    model_config = {"from_attributes": True}

    @field_serializer("started_at", "finished_at")
    def serialize_datetime(self, value: Optional[datetime]) -> Optional[str]:
        """Always emit timestamps as UTC ISO-8601 with a Z suffix so browsers
        never mis-parse them as local time."""
        if value is None:
            return None
        if value.tzinfo is None:
            # Naive datetime from PostgreSQL TIMESTAMP WITHOUT TIME ZONE —
            # the backend always writes UTC, so just tag it.
            return value.isoformat() + "Z"
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# ─── Manual Trigger ───────────────────────────────────────

@router.post("/run/{spider_name}", response_model=ScrapeResponse)
async def run_spider(
    spider_name: str,
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    from app.tasks.scraping_tasks import (
        scrape_nvd, scrape_github, scrape_certfr, scrape_certeu,
        scrape_fortiguard, scrape_cisco, scrape_microsoft,
        scrape_bleepingcomputer, scrape_thehackernews,
        scrape_darkreading, scrape_securityweek,
    )
    spider_map = {
        "nvd": scrape_nvd, "github": scrape_github,
        "certfr": scrape_certfr, "certeu": scrape_certeu,
        "fortiguard": scrape_fortiguard, "cisco": scrape_cisco,
        "microsoft": scrape_microsoft,
        "bleepingcomputer": scrape_bleepingcomputer,
        "thehackernews": scrape_thehackernews,
        "darkreading": scrape_darkreading,
        "securityweek": scrape_securityweek,
    }
    if spider_name not in spider_map:
        raise HTTPException(status_code=400, detail=f"Unknown spider: {spider_name}. Available: {list(spider_map.keys())}")

    task = spider_map[spider_name].apply_async(
        kwargs={"triggered_by": current_user.email}
    )

    await log_action(
        db, current_user.email, current_user.role.value,
        "RUN_SPIDER", resource_type="scraper", resource_id=spider_name,
        details=f"Manually triggered spider: {spider_name} (task: {task.id})"
    )

    return ScrapeResponse(message=f"Spider '{spider_name}' triggered", task_id=str(task.id), spider=spider_name)


@router.post("/run", response_model=ScrapeAllResponse)
async def run_all_spiders(
    group: str = Query("general", regex="^(general|vendor|news)$"),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    from app.tasks.scraping_tasks import run_all_general_sequentially, run_all_vendor_sequentially, run_all_news_sequentially

    if group == "vendor":
        t = run_all_vendor_sequentially.apply_async(
            kwargs={"triggered_by": current_user.email}
        )
        label = "vendor"
    elif group == "news":
        t = run_all_news_sequentially.apply_async(
            kwargs={"triggered_by": current_user.email}
        )
        label = "news"
    else:
        t = run_all_general_sequentially.apply_async(
            kwargs={"triggered_by": current_user.email}
        )
        label = "general"

    await log_action(
        db, current_user.email, current_user.role.value,
        "RUN_ALL_SPIDERS", resource_type="scraper",
        details=f"Triggered sequential run of {label} spiders (coordinator task: {t.id})"
    )

    return ScrapeAllResponse(
        message=f"All {label} spiders queued for sequential execution (one at a time)",
        tasks=[{"spider": f"all-{label}", "task_id": str(t.id)}]
    )


# ─── Run History ──────────────────────────────────────────

@router.get("/runs", response_model=list[SpiderRunResponse])
async def list_runs(
    spider: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    query = select(SpiderRun).order_by(desc(SpiderRun.started_at)).limit(limit)
    if spider:
        query = query.where(SpiderRun.spider_name == spider)
    result = await db.execute(query)
    runs = result.scalars().all()
    return [SpiderRunResponse.model_validate(r) for r in runs]


# ─── Live Log Stream (SSE) ────────────────────────────────

@router.get("/logs/{task_id}")
async def stream_logs(
    task_id: str,
    since: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    """
    Server-Sent Events stream of log lines for a spider run.

    Live runs stream from the Redis buffer (spider_log:{task_id}). When that
    buffer has expired (logs are kept ~6h) or the run predates it, the persisted
    SpiderRun.log is replayed instead — so clicking an already-finished run always
    shows its output rather than hanging on "Waiting for output...".
    """
    r = redis_lib.from_url(REDIS_URL, decode_responses=True)
    key = f"spider_log:{task_id}"

    # Resolve run state once, while the DB session is open.
    row = (
        await db.execute(
            select(SpiderRun.status, SpiderRun.log).where(SpiderRun.task_id == task_id)
        )
    ).first()
    status = row[0] if row else None
    persisted = row[1] if row else None
    finished = status in ("SUCCESS", "EMPTY", "FAILURE")

    async def generate():
        # Finished run with no live buffer → replay the persisted log, then stop.
        if finished and not r.exists(key):
            if persisted:
                for line in persisted.split("\n"):
                    yield f"data: {line}\n\n"
            else:
                yield "data: [No stored output for this run — live logs are kept for ~6h after a run.]\n\n"
            yield "data: __DONE__\n\n"
            return

        # Live (or just-triggered) run → stream the Redis buffer.
        index = since
        missing = 0
        while True:
            lines = r.lrange(key, index, -1)
            for line in lines:
                index += 1
                if line == "__DONE__":
                    yield "data: __DONE__\n\n"
                    return
                yield f"data: {line}\n\n"
            if not lines:
                if r.exists(key):
                    missing = 0
                else:
                    # Buffer absent: stop immediately if the run is already finished,
                    # otherwise allow a short grace period for the worker to start it.
                    missing += 1
                    if finished or missing > 20:
                        yield "data: __DONE__\n\n"
                        return
            await asyncio.sleep(1)

    return StreamingResponse(generate(), media_type="text/event-stream",
                              headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─── Schedule Info ────────────────────────────────────────

@router.get("/schedule")
async def get_schedule(
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns vendor spiders, news spiders (with schedule countdown), and general spiders (manual only).
    Each scheduled spider also reports its enabled state and auto-reactivation TTL.
    """
    from app.tasks.scraping_tasks import is_spider_enabled, get_spider_disabled_ttl
    now = datetime.now(timezone.utc)

    async def get_last_run(spider_name):
        q = (
            select(SpiderRun)
            .where(SpiderRun.spider_name == spider_name)
            .where(SpiderRun.status.in_(["SUCCESS", "EMPTY", "FAILURE"]))
            .order_by(desc(SpiderRun.finished_at))
            .limit(1)
        )
        result = await db.execute(q)
        return result.scalar_one_or_none()

    def build_scheduled_entry(spider_name, info, last_run):
        interval = info["interval_seconds"]
        if last_run and last_run.finished_at:
            last_finished = last_run.finished_at.replace(tzinfo=timezone.utc) if last_run.finished_at.tzinfo is None else last_run.finished_at
            elapsed = int((now - last_finished).total_seconds())
            seconds_until_next = max(0, interval - elapsed)
            last_run_at = last_finished.isoformat()
            last_status = last_run.status
        else:
            seconds_until_next = 0
            last_run_at = None
            last_status = "never"

        enabled = is_spider_enabled(spider_name)
        disabled_ttl = get_spider_disabled_ttl(spider_name) if not enabled else None

        return {
            "spider": spider_name,
            "interval_label": info["label"],
            "interval_seconds": interval,
            "last_run_at": last_run_at,
            "last_status": last_status,
            "seconds_until_next": seconds_until_next,
            "enabled": enabled,
            "disabled_ttl_seconds": disabled_ttl,
        }

    # Vendor spiders — scheduled
    vendor_spiders = []
    for spider_name, info in SCHEDULE_INFO.items():
        last_run = await get_last_run(spider_name)
        vendor_spiders.append(build_scheduled_entry(spider_name, info, last_run))

    # News spiders — scheduled
    news_spiders = []
    for spider_name, info in NEWS_SCHEDULE_INFO.items():
        last_run = await get_last_run(spider_name)
        news_spiders.append(build_scheduled_entry(spider_name, info, last_run))

    # General spiders — manual only
    general_spiders = []
    for spider_name in GENERAL_SPIDERS:
        last_run = await get_last_run(spider_name)
        if last_run and last_run.finished_at:
            last_finished = last_run.finished_at.replace(tzinfo=timezone.utc) if last_run.finished_at.tzinfo is None else last_run.finished_at
            last_run_at = last_finished.isoformat()
            last_status = last_run.status
        else:
            last_run_at = None
            last_status = "never"
        general_spiders.append({
            "spider": spider_name,
            "last_run_at": last_run_at,
            "last_status": last_status,
        })

    return {
        "vendor_spiders": vendor_spiders,
        "news_spiders": news_spiders,
        "general_spiders": general_spiders,
    }


# ─── Task Status ─────────────────────────────────────────

@router.get("/status/{task_id}")
async def get_task_status(
    task_id: str,
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    from app.tasks.celery_app import celery_app
    result = celery_app.AsyncResult(task_id)
    return {"task_id": task_id, "status": result.status, "result": result.result if result.ready() else None}


# ─── Schedule Toggle (Admin only) ────────────────────────

@router.get("/schedule/enabled")
async def get_schedule_enabled(
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    from app.tasks.scraping_tasks import is_schedule_enabled
    return {"schedule_enabled": is_schedule_enabled()}


@router.post("/schedule/enabled")
async def set_schedule_enabled(
    body: dict,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    from app.tasks.scraping_tasks import set_schedule_enabled
    enabled = bool(body.get("enabled", True))
    set_schedule_enabled(enabled)
    await log_action(
        db, current_user.email, current_user.role.value,
        "TOGGLE_SCHEDULE", resource_type="scraper",
        details=f"Schedule {'enabled' if enabled else 'disabled'} by {current_user.email}"
    )
    return {"schedule_enabled": enabled}


# ─── Per-Spider Toggle ────────────────────────────────────

ALL_SCHEDULED_SPIDERS = list(SCHEDULE_INFO.keys()) + list(NEWS_SCHEDULE_INFO.keys())


@router.get("/schedule/spider/{spider_name}/enabled")
async def get_spider_enabled(
    spider_name: str,
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    if spider_name not in ALL_SCHEDULED_SPIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown scheduled spider: {spider_name}")
    from app.tasks.scraping_tasks import is_spider_enabled, get_spider_disabled_ttl
    enabled = is_spider_enabled(spider_name)
    return {
        "spider": spider_name,
        "enabled": enabled,
        "disabled_ttl_seconds": get_spider_disabled_ttl(spider_name) if not enabled else None,
    }


@router.post("/schedule/spider/{spider_name}/enabled")
async def set_spider_enabled(
    spider_name: str,
    body: dict,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    if spider_name not in ALL_SCHEDULED_SPIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown scheduled spider: {spider_name}")
    from app.tasks.scraping_tasks import enable_spider, disable_spider, is_spider_enabled, get_spider_disabled_ttl
    enabled = bool(body.get("enabled", True))
    if enabled:
        enable_spider(spider_name)
    else:
        disable_spider(spider_name)
    await log_action(
        db, current_user.email, current_user.role.value,
        "TOGGLE_SPIDER", resource_type="scraper", resource_id=spider_name,
        details=f"Spider {spider_name} {'enabled' if enabled else 'paused (12h auto-reactivation)'} by {current_user.email}"
    )
    return {
        "spider": spider_name,
        "enabled": is_spider_enabled(spider_name),
        "disabled_ttl_seconds": get_spider_disabled_ttl(spider_name) if not enabled else None,
    }
