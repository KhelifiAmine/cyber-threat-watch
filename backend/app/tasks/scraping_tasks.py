"""
Scraping Tasks — Celery tasks that trigger Scrapy spiders.
Each run is tracked in the spider_runs table and logs are streamed to Redis.
"""

import os
import re
import logging
import subprocess
from datetime import datetime, timezone

import redis as redis_lib
import psycopg2
from celery.signals import worker_ready

from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://cybershield:CHANGE_ME@postgres:5432/cybershield",
).replace("postgresql+asyncpg://", "postgresql://")


@worker_ready.connect
def warmup_ollama(sender=None, **kwargs):
    """
    On worker startup, send a tiny request to Ollama to ensure the phi3.5 model
    is loaded into memory before any spider/enrichment task needs it.
    """
    import urllib.request
    import json as _json

    ollama_url = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
    body = _json.dumps({
        "model": "phi3.5",
        "messages": [{"role": "user", "content": "ping"}],
        "stream": False,
        "options": {"num_predict": 1, "num_ctx": 4096},
    }).encode()
    req = urllib.request.Request(
        ollama_url + "/api/chat",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            r.read()
        logger.info("[Startup] Ollama phi3.5 model warmed up successfully")
    except Exception as e:
        logger.warning(f"[Startup] Could not warm up Ollama phi3.5: {e}")


@worker_ready.connect
def cleanup_stale_runs(sender=None, **kwargs):
    """
    On worker startup, any spider run still marked RUNNING or PENDING is by
    definition orphaned — the worker that was executing it is gone. Mark them
    all as FAILURE so the UI stops showing ghost "running" rows.
    """
    try:
        conn = psycopg2.connect(DATABASE_URL)
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE spider_runs
                SET status = 'FAILURE',
                    finished_at = COALESCE(finished_at, NOW()),
                    error_message = 'Worker restarted — task abandoned mid-run'
                WHERE status IN ('RUNNING', 'PENDING')
                """
            )
            affected = cur.rowcount
        conn.commit()
        conn.close()
        if affected:
            logger.warning(f"[Startup] Cleaned up {affected} stale spider run(s)")
    except Exception as e:
        logger.error(f"[Startup] Failed to clean up stale runs: {e}")

LOG_TTL = 3600 * 6   # Keep logs in Redis for 6 hours


# ─── Redis helpers ───────────────────────────────────────

def get_redis():
    return redis_lib.from_url(REDIS_URL, decode_responses=True)


def push_log(r, task_id: str, line: str):
    key = f"spider_log:{task_id}"
    r.rpush(key, line)
    r.expire(key, LOG_TTL)


# ─── DB helpers (sync psycopg2 — Celery is synchronous) ──

def db_create_run(task_id, spider_name, triggered_by="schedule"):
    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO spider_runs
                    (task_id, spider_name, status, started_at, triggered_by,
                     items_scraped, items_new, items_duplicate,
                     items_dropped_nlp, items_dropped_clean, alerts_created)
                VALUES (%s, %s, 'RUNNING', %s, %s, 0, 0, 0, 0, 0, 0)
                ON CONFLICT (task_id) DO UPDATE SET status = 'RUNNING', started_at = %s
                """,
                (task_id, spider_name, datetime.now(timezone.utc), triggered_by,
                 datetime.now(timezone.utc)),
            )
        conn.commit()
    finally:
        conn.close()


def db_finish_run(task_id, status, counts, error_message=None, log_text=None):
    conn = psycopg2.connect(DATABASE_URL)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE spider_runs SET
                    status = %s,
                    finished_at = %s,
                    items_scraped = %s,
                    items_new = %s,
                    items_duplicate = %s,
                    items_dropped_nlp = %s,
                    items_dropped_clean = %s,
                    alerts_created = %s,
                    error_message = %s,
                    log = COALESCE(%s, log)
                WHERE task_id = %s
                """,
                (
                    status,
                    datetime.now(timezone.utc),
                    counts.get("scraped", 0),
                    counts.get("new", 0),
                    counts.get("duplicate", 0),
                    counts.get("dropped_nlp", 0),
                    counts.get("dropped_clean", 0),
                    counts.get("alerts", 0),
                    error_message,
                    log_text,
                    task_id,
                ),
            )
        conn.commit()
    finally:
        conn.close()


def _collect_log(r, task_id) -> str | None:
    """Read the filtered live-log buffer from Redis so it can be persisted on the run."""
    try:
        lines = [ln for ln in r.lrange(f"spider_log:{task_id}", 0, -1) if ln != "__DONE__"]
        return "\n".join(lines) if lines else None
    except Exception:
        return None


# ─── Parse Scrapy output into structured counts ───────────

def parse_counts(stdout: str, stderr: str) -> dict:
    """Extract item counts from Scrapy log output."""
    counts = {"scraped": 0, "new": 0, "duplicate": 0, "dropped_nlp": 0, "dropped_clean": 0, "alerts": 0, "pipeline_errors": 0}

    text = stdout + stderr

    # Scrapy stats dict format: 'item_scraped_count': 40
    m = re.search(r"item_scraped_count'\s*:\s*(\d+)", text)
    if m:
        counts["scraped"] = int(m.group(1))

    # DatabasePipeline logs "[Stored] CVE ...", "[Stored] Threat: ...", "[NEWS STORED] ..."
    counts["new"] = len(re.findall(r"\[Stored\]|\[NEWS STORED\]", text))

    # DatabasePipeline close_spider logs "X stored, Y skipped"
    m = re.search(r"(\d+) stored,\s*(\d+) skipped", text)
    if m:
        counts["duplicate"] = int(m.group(2))

    counts["dropped_nlp"] = len(re.findall(r"\[NLP\] DROPPED", text))
    counts["dropped_clean"] = len(re.findall(r"No valid title", text))

    # DatabasePipeline logs "[Alert Created] PRIORITY: title"
    counts["alerts"] = len(re.findall(r"\[Alert Created\]", text))

    # Count pipeline-level errors (not per-item NLP drops — those are normal)
    counts["pipeline_errors"] = len(re.findall(r"\[DatabasePipeline\] Error storing", text))

    return counts


def determine_status(returncode: int, counts: dict, full_output: str) -> tuple[str, str | None]:
    """
    Determine the real run status beyond just the process return code.
    Scrapy exits 0 even when spiders encounter serious errors mid-run.
    Returns (status, error_message).

    Three possible outcomes:
      SUCCESS — ran, found items, enriched, and stored them
      EMPTY   — ran cleanly, source had nothing new (0 items is expected)
      FAILURE — any stage broke: process error, timeout, parse error, or
                items scraped but nothing stored
    """
    if returncode != 0:
        return "FAILURE", f"Exit code {returncode}"

    # Phi3.5 / Ollama was unreachable
    if "phi3.5 isn't reachable" in full_output.lower():
        return "FAILURE", "Phi3.5 isn't reachable — start Ollama and retry"

    # Pipeline errors mean items went through Scrapy but failed to store.
    if counts["pipeline_errors"] > 0:
        return "FAILURE", (
            f"Pipeline errors: {counts['pipeline_errors']} item(s) failed to store. "
            f"Check live log for details."
        )

    # Spider produced items (passed NLP) but stored none — DB-level failure.
    if counts["scraped"] > 0 and counts["new"] == 0 and counts["duplicate"] == 0:
        return "FAILURE", (
            f"Spider produced {counts['scraped']} item(s) through pipelines but stored 0. "
            f"Possible database error — check live log."
        )

    # Source had nothing new — clean run with no items. Different from failure.
    if counts["scraped"] == 0 and counts["new"] == 0 and counts["duplicate"] == 0 and counts["pipeline_errors"] == 0:
        return "EMPTY", None

    return "SUCCESS", None


# ─── Filter & format log lines for the UI ─────────────────

INTERESTING_PATTERNS = [
    (r"\[Enrichment\].*OFFLINE", "OLLAMA ERR"),
    (r"\[Enrichment\].*FAILED",  "ENRICH ERR"),
    (r"\[Enrichment\].*phi3.5",  "ENRICH    "),
    (r"ollama_offline",          "OLLAMA ERR"),
    (r"\[NLP\] VERIFIED",       "✓ VERIFIED"),
    (r"\[NLP\] DROPPED",        "✗ DROPPED "),
    (r"\[NLP\] LOW-CONF",       "~ LOW-CONF"),
    (r"\[NLPPipeline\]",        "NLP INIT  "),
    (r"\[Stored\]",              "DB        "),
    (r"\[DatabasePipeline\]",    "DB        "),
    (r"\[Alert Created\]",       "ALERT     "),
    (r"\[NEWS STORED\]",         "NEWS      "),
    (r"\[NEWS\]",                "NEWS      "),
    (r"\[NEWS Matching\]",       "MATCH     "),
    (r"CERT-EU:",                "CERT-EU   "),
    (r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \[.+\] ERROR:", "ERROR     "),
    (r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \[.+\] WARNING:", "WARNING   "),
    (r"item_scraped_count",      "STATS     "),
    (r"item_dropped_count",      "STATS     "),
    (r"Spider opened",           "INFO      "),
    (r"Spider closed",           "INFO      "),
    (r"\[NLP\] NLP model ready",  "NLP READY "),
    (r"\[NLP\] NLP server not ready", "NLP LOAD  "),
    (r"\[NLP\] Waiting for NLP",  "NLP LOAD  "),
    (r"\[NLP\] Loading.*step",    "NLP LOAD  "),
    (r"\[NLP\] TTPXHunter model loaded", "NLP READY "),
    (r"\[NLP\].*news spider.*skipping", "NLP SKIP  "),
]

def is_interesting(line: str) -> bool:
    for pattern, _ in INTERESTING_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    return False

def format_line(line: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    line = line.strip()
    for pattern, label in INTERESTING_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return f"[{ts}] [{label.strip()}] {line}"
    return f"[{ts}] {line}"


# ─── Schedule enable / disable ────────────────────────────

SCHEDULE_ENABLED_KEY = "scraper:schedule_enabled"

def is_schedule_enabled() -> bool:
    """Returns True unless an admin has explicitly disabled the schedule."""
    try:
        r = get_redis()
        val = r.get(SCHEDULE_ENABLED_KEY)
        return val != "0"
    except Exception:
        return True  # safe default

def set_schedule_enabled(enabled: bool):
    r = get_redis()
    r.set(SCHEDULE_ENABLED_KEY, "1" if enabled else "0")


# ─── Per-spider enable / disable ──────────────────────────

SPIDER_DISABLED_KEY = "scraper:spider_disabled:{}"


def disable_spider(spider_name: str):
    """
    Pause a specific spider's scheduled runs.
    Auto-reactivates after 12 hours via Redis TTL — the log history will show
    FAILURE if it keeps failing after reactivation.
    """
    r = get_redis()
    r.set(SPIDER_DISABLED_KEY.format(spider_name), "1", ex=43200)  # 12 hours


def enable_spider(spider_name: str):
    """Re-enable a specific spider immediately (clears the disabled key)."""
    r = get_redis()
    r.delete(SPIDER_DISABLED_KEY.format(spider_name))


def is_spider_enabled(spider_name: str) -> bool:
    """Returns True if the spider is enabled (key absent = enabled)."""
    try:
        r = get_redis()
        return not r.exists(SPIDER_DISABLED_KEY.format(spider_name))
    except Exception:
        return True  # safe default: allow runs if Redis is unavailable


def get_spider_disabled_ttl(spider_name: str) -> int | None:
    """Returns seconds remaining until auto-reactivation, or None if spider is enabled."""
    try:
        r = get_redis()
        ttl = r.ttl(SPIDER_DISABLED_KEY.format(spider_name))
        return ttl if ttl > 0 else None
    except Exception:
        return None


# ─── Re-enrich empty summaries ───────────────────────────

_NEWS_SPIDER_SET = {"bleepingcomputer", "thehackernews", "darkreading", "securityweek"}
_CVE_SPIDER_SET = {"nvd", "github", "cisco", "fortiguard", "microsoft"}
_THREAT_SPIDER_SET = {"certeu", "certfr", "exploitdb"}


def _re_enrich_empty_summaries(spider_name, r, task_id, run_started):
    """
    After a spider finishes, check for articles with empty summaries
    from this run and retry LLM enrichment one by one.
    Runs before the spider is marked as done, so the next spider waits.
    """
    import json as _json

    if spider_name in _NEWS_SPIDER_SET:
        table = "news_articles"
    elif spider_name in _CVE_SPIDER_SET:
        table = "cves"
    elif spider_name in _THREAT_SPIDER_SET:
        table = "threats"
    else:
        return 0

    conn = psycopg2.connect(DATABASE_URL)
    fixed = 0
    try:
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT id, title, description, source
                FROM {table}
                WHERE created_at >= %s
                  AND (enrichment_data->>'summary' IS NULL
                       OR LENGTH(enrichment_data->>'summary') < 20)
            """, (run_started,))
            rows = cur.fetchall()

        if not rows:
            return 0

        ts = lambda: datetime.now(timezone.utc).strftime("%H:%M:%S")
        push_log(r, task_id, f"[{ts()}] [RE-ENRICH] {len(rows)} item(s) with empty summaries — retrying")

        from app.services.enrichment import enrich

        for item_id, title, description, source in rows:
            try:
                result = enrich(title, description or "", source)
                new_summary = result.get("summary", "")

                if len(new_summary) >= 20:
                    patch = {"summary": new_summary}
                    with conn.cursor() as cur:
                        cur.execute(f"""
                            UPDATE {table}
                            SET enrichment_data = enrichment_data || %s::jsonb
                            WHERE id = %s
                        """, (_json.dumps(patch), item_id))
                    conn.commit()
                    fixed += 1
                    push_log(r, task_id,
                             f"[{ts()}] [RE-ENRICH] Fixed: {title[:60]} (summary_len={len(new_summary)})")
                else:
                    push_log(r, task_id,
                             f"[{ts()}] [RE-ENRICH] Still empty: {title[:60]}")
            except Exception as e:
                push_log(r, task_id, f"[{ts()}] [RE-ENRICH] Error on '{title[:40]}': {e}")

    finally:
        conn.close()

    if fixed:
        push_log(r, task_id, f"[{ts()}] [RE-ENRICH] Done — fixed {fixed}/{len(rows)} summaries")
    return fixed


# ─── Core runner ──────────────────────────────────────────

def run_spider(spider_name, task_id=None, triggered_by="schedule", **kwargs):
    r = get_redis()
    tid = task_id or f"manual-{spider_name}-{int(datetime.now().timestamp())}"
    run_started = datetime.now(timezone.utc)

    db_create_run(tid, spider_name, triggered_by)
    push_log(r, tid, f"[{run_started.strftime('%H:%M:%S')}] [SCRAPER  ] Starting spider: {spider_name}")

    cmd = ["python", "-m", "scrapy", "crawl", spider_name, "-s", "LOG_LEVEL=INFO"]
    for key, value in kwargs.items():
        cmd.extend(["-a", f"{key}={value}"])

    try:
        process = subprocess.Popen(
            cmd,
            cwd="/app",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env={**os.environ, "SCRAPY_SETTINGS_MODULE": "scraper.settings",
                 "SPIDER_TASK_ID": tid},
        )

        stdout_lines = []
        for line in process.stdout:
            stdout_lines.append(line)
            if is_interesting(line):
                push_log(r, tid, format_line(line))

        process.wait(timeout=600)

        full_output = "".join(stdout_lines)
        counts = parse_counts(full_output, "")

        status, error = determine_status(process.returncode, counts, full_output)

        # Re-enrich any items with empty summaries before closing this spider
        if status == "SUCCESS" and counts.get("new", 0) > 0:
            _re_enrich_empty_summaries(spider_name, r, tid, run_started)

        summary = (
            f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] [DONE     ] "
            f"Spider {spider_name} finished — "
            f"scraped: {counts['scraped']}, new: {counts['new']}, "
            f"duplicates: {counts['duplicate']}, "
            f"dropped (NLP): {counts['dropped_nlp']}, "
            f"alerts: {counts['alerts']}"
        )
        push_log(r, tid, summary)
        push_log(r, tid, "__DONE__")

        db_finish_run(tid, status, counts, error, log_text=_collect_log(r, tid))
        logger.info(f"[Scraper] {spider_name} {status}: {counts}")
        return {"spider": spider_name, "task_id": tid, "status": status, "counts": counts}

    except subprocess.TimeoutExpired:
        push_log(r, tid, f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] [ERROR    ] Spider timed out after 600 seconds")
        push_log(r, tid, "__DONE__")
        db_finish_run(tid, "FAILURE", {}, "Timeout after 600s", log_text=_collect_log(r, tid))
        return {"spider": spider_name, "error": "timeout"}

    except Exception as e:
        push_log(r, tid, f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] [ERROR    ] {str(e)}")
        push_log(r, tid, "__DONE__")
        db_finish_run(tid, "FAILURE", {}, str(e), log_text=_collect_log(r, tid))
        return {"spider": spider_name, "error": str(e)}


# ═══════════════════════════════════════════════
# Spider Tasks
# ═══════════════════════════════════════════════

def _schedule_guard(spider_name, triggered_by):
    """Return True if this run should be skipped (schedule disabled or spider paused)."""
    if triggered_by == "schedule" and not is_schedule_enabled():
        logger.info(f"[Scraper] Schedule disabled — skipping {spider_name}")
        return True
    if triggered_by == "schedule" and not is_spider_enabled(spider_name):
        logger.info(f"[Scraper] Spider {spider_name} is paused — skipping (auto-reactivates in {get_spider_disabled_ttl(spider_name)}s)")
        return True
    return False


@celery_app.task(name="app.tasks.scraping_tasks.scrape_nvd", bind=True)
def scrape_nvd(self, days_back=1, triggered_by="schedule"):
    if _schedule_guard("nvd", triggered_by): return {"spider": "nvd", "status": "skipped"}
    return run_spider("nvd", task_id=self.request.id, triggered_by=triggered_by, days_back=days_back)

@celery_app.task(name="app.tasks.scraping_tasks.scrape_github", bind=True)
def scrape_github(self, days_back=1, triggered_by="schedule"):
    if _schedule_guard("github", triggered_by): return {"spider": "github", "status": "skipped"}
    return run_spider("github", task_id=self.request.id, triggered_by=triggered_by, days_back=days_back)

@celery_app.task(name="app.tasks.scraping_tasks.scrape_certfr", bind=True)
def scrape_certfr(self, days_back=1, triggered_by="schedule"):
    if _schedule_guard("certfr", triggered_by): return {"spider": "certfr", "status": "skipped"}
    return run_spider("certfr", task_id=self.request.id, triggered_by=triggered_by, days_back=days_back)

@celery_app.task(name="app.tasks.scraping_tasks.scrape_certeu", bind=True)
def scrape_certeu(self, days_back=1, triggered_by="schedule"):
    if _schedule_guard("certeu", triggered_by): return {"spider": "certeu", "status": "skipped"}
    return run_spider("certeu", task_id=self.request.id, triggered_by=triggered_by, days_back=days_back)


_SCRAPER_QUEUE_LOCK = "scraper:queue_lock"
_SCRAPER_QUEUE_TTL = 1800  # 30 min max — auto-expires if worker dies mid-run


def _run_group_sequentially(self, spider_order, group_label, triggered_by="manual"):
    """
    Run a list of spiders one after another in a fixed order.
    Each spider gets its own spider_runs row and Redis log stream.
    Only one group can run at a time — concurrent attempts are skipped.
    """
    import uuid

    # If schedule is globally disabled, skip the entire group
    if triggered_by == "schedule" and not is_schedule_enabled():
        logger.info(f"[Scraper] Schedule disabled — skipping {group_label}")
        return []

    r = get_redis()

    # Acquire global scraper queue lock — only one group runs at a time
    acquired = r.set(_SCRAPER_QUEUE_LOCK, self.request.id, nx=True, ex=_SCRAPER_QUEUE_TTL)
    if not acquired:
        holder = r.get(_SCRAPER_QUEUE_LOCK)
        logger.info(f"[Scraper] {group_label} skipped — another group is already running (task {holder})")
        return []

    try:
        return _run_group_inner(self, r, spider_order, group_label, triggered_by)
    finally:
        # Release lock only if we still own it
        if r.get(_SCRAPER_QUEUE_LOCK) == self.request.id:
            r.delete(_SCRAPER_QUEUE_LOCK)


def _run_group_inner(self, r, spider_order, group_label, triggered_by):
    import uuid

    coordinator_key = f"spider_log:{self.request.id}"
    ts = lambda: datetime.now(timezone.utc).strftime("%H:%M:%S")

    r.rpush(coordinator_key, f"[{ts()}] [RUN ALL  ] {group_label} — {len(spider_order)} spiders queued")
    r.expire(coordinator_key, LOG_TTL)

    results = []
    for i, (spider_name, kwargs) in enumerate(spider_order, 1):
        # Skip individually disabled spiders
        if triggered_by == "schedule" and not is_spider_enabled(spider_name):
            r.rpush(coordinator_key, f"[{ts()}] [RUN ALL  ] ({i}/{len(spider_order)}) {spider_name} — paused, skipping")
            r.expire(coordinator_key, LOG_TTL)
            results.append({"spider": spider_name, "status": "skipped"})
            continue

        sub_id = str(uuid.uuid4())
        r.rpush(coordinator_key, f"[{ts()}] [RUN ALL  ] ({i}/{len(spider_order)}) Starting {spider_name}...")
        r.expire(coordinator_key, LOG_TTL)

        result = run_spider(spider_name, task_id=sub_id, triggered_by=triggered_by, **kwargs)
        results.append(result)

        status = result.get("status", "?")
        counts = result.get("counts", {})
        r.rpush(coordinator_key, (
            f"[{ts()}] [RUN ALL  ] ({i}/{len(spider_order)}) {spider_name} done — "
            f"status: {status}, new: {counts.get('new', 0)}, alerts: {counts.get('alerts', 0)}"
        ))
        r.expire(coordinator_key, LOG_TTL)

    r.rpush(coordinator_key, f"[{ts()}] [RUN ALL  ] All spiders complete.")
    r.rpush(coordinator_key, "__DONE__")
    r.expire(coordinator_key, LOG_TTL)

    return results


@celery_app.task(name="app.tasks.scraping_tasks.run_all_general_sequentially", bind=True)
def run_all_general_sequentially(self, triggered_by="manual"):
    """Run all general (manual-only) spiders sequentially."""
    SPIDER_ORDER = [
        ("nvd",    {"days_back": 1}),
        ("github", {"days_back": 1}),
        ("certfr", {"days_back": 1}),
        ("certeu", {"days_back": 1}),
    ]
    return _run_group_sequentially(self, SPIDER_ORDER, "General spiders sequential run", triggered_by)


@celery_app.task(name="app.tasks.scraping_tasks.run_all_vendor_sequentially", bind=True)
def run_all_vendor_sequentially(self, triggered_by="manual"):
    """Run all vendor (scheduled) spiders sequentially."""
    SPIDER_ORDER = [
        ("fortiguard", {}),
        ("cisco",      {}),
        ("microsoft",  {}),
    ]
    return _run_group_sequentially(self, SPIDER_ORDER, "Vendor spiders sequential run", triggered_by)


# ─── Vendor Spider Tasks ─────────────────────────────────

@celery_app.task(name="app.tasks.scraping_tasks.scrape_fortiguard", bind=True)
def scrape_fortiguard(self, triggered_by="schedule"):
    if _schedule_guard("fortiguard", triggered_by): return {"spider": "fortiguard", "status": "skipped"}
    return run_spider("fortiguard", task_id=self.request.id, triggered_by=triggered_by)

@celery_app.task(name="app.tasks.scraping_tasks.scrape_cisco", bind=True)
def scrape_cisco(self, triggered_by="schedule"):
    if _schedule_guard("cisco", triggered_by): return {"spider": "cisco", "status": "skipped"}
    return run_spider("cisco", task_id=self.request.id, triggered_by=triggered_by)

@celery_app.task(name="app.tasks.scraping_tasks.scrape_microsoft", bind=True)
def scrape_microsoft(self, triggered_by="schedule"):
    if _schedule_guard("microsoft", triggered_by): return {"spider": "microsoft", "status": "skipped"}
    return run_spider("microsoft", task_id=self.request.id, triggered_by=triggered_by)


# ─── News Spider Tasks ───────────────────────────────────

@celery_app.task(name="app.tasks.scraping_tasks.scrape_bleepingcomputer", bind=True)
def scrape_bleepingcomputer(self, triggered_by="schedule"):
    if _schedule_guard("bleepingcomputer", triggered_by): return {"spider": "bleepingcomputer", "status": "skipped"}
    return run_spider("bleepingcomputer", task_id=self.request.id, triggered_by=triggered_by)

@celery_app.task(name="app.tasks.scraping_tasks.scrape_thehackernews", bind=True)
def scrape_thehackernews(self, triggered_by="schedule"):
    if _schedule_guard("thehackernews", triggered_by): return {"spider": "thehackernews", "status": "skipped"}
    return run_spider("thehackernews", task_id=self.request.id, triggered_by=triggered_by)

@celery_app.task(name="app.tasks.scraping_tasks.scrape_darkreading", bind=True)
def scrape_darkreading(self, triggered_by="schedule"):
    if _schedule_guard("darkreading", triggered_by): return {"spider": "darkreading", "status": "skipped"}
    return run_spider("darkreading", task_id=self.request.id, triggered_by=triggered_by)

@celery_app.task(name="app.tasks.scraping_tasks.scrape_securityweek", bind=True)
def scrape_securityweek(self, triggered_by="schedule"):
    if _schedule_guard("securityweek", triggered_by): return {"spider": "securityweek", "status": "skipped"}
    return run_spider("securityweek", task_id=self.request.id, triggered_by=triggered_by)

@celery_app.task(name="app.tasks.scraping_tasks.run_all_news_sequentially", bind=True)
def run_all_news_sequentially(self, triggered_by="manual"):
    SPIDER_ORDER = [
        ("bleepingcomputer", {}),
        ("thehackernews", {}),
        ("darkreading", {}),
        ("securityweek", {}),
    ]
    return _run_group_sequentially(self, SPIDER_ORDER, "News spiders sequential run", triggered_by)


# ═══════════════════════════════════════════════
# Email Notification Tasks
# ═══════════════════════════════════════════════

@celery_app.task(
    name="app.tasks.scraping_tasks.send_alert_email",
    bind=True,
    max_retries=2,
    default_retry_delay=60,
)
def send_alert_email(self, alert_id):
    from app.services.email_service import (
        get_alert_with_threat, get_recipients_for_priority,
        render_alert_email, send_email, mark_alert_email_sent, sanitize_header,
    )
    logger.info(f"[Email] Processing alert {alert_id}")
    try:
        alert_data = get_alert_with_threat(alert_id)
        if not alert_data:
            return {"alert_id": alert_id, "status": "not_found"}
        if alert_data.get("email_sent"):
            return {"alert_id": alert_id, "status": "already_sent"}
        priority = str(alert_data.get("priority", "medium"))
        recipients = get_recipients_for_priority(priority)
        if not recipients:
            return {"alert_id": alert_id, "status": "no_recipients"}
        html_body = render_alert_email(alert_data)
        alert_title = str(alert_data.get("alert_title", "New Alert"))
        subject = sanitize_header(f"[Cyber Threat Watch] [{priority.upper()}] {alert_title}")
        success = send_email(recipients, subject, html_body)
        if success:
            mark_alert_email_sent(alert_id)
            return {"alert_id": alert_id, "status": "sent", "recipients": len(recipients)}
        else:
            raise self.retry(exc=Exception("SMTP send failed"))
    except self.MaxRetriesExceededError:
        return {"alert_id": alert_id, "status": "failed_max_retries"}
    except Exception as e:
        try:
            raise self.retry(exc=e)
        except self.MaxRetriesExceededError:
            return {"alert_id": alert_id, "status": "failed", "error": str(e)}
