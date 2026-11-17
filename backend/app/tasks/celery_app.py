import os
from celery import Celery
from celery.schedules import crontab

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "cybershield",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["app.tasks.scraping_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
)

celery_app.conf.beat_schedule = {
    # Vendor spiders — sequential queue, every 6 hours
    "vendors-sequential": {
        "task": "app.tasks.scraping_tasks.run_all_vendor_sequentially",
        "schedule": crontab(minute=0, hour="*/6"),
        "kwargs": {"triggered_by": "schedule"},
    },
    # News spiders — sequential queue, every 2 hours
    "news-sequential": {
        "task": "app.tasks.scraping_tasks.run_all_news_sequentially",
        "schedule": crontab(minute=30, hour="*/2"),
        "kwargs": {"triggered_by": "schedule"},
    },
}