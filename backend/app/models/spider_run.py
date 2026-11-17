"""
SpiderRun model — tracks each scraper execution with metadata and result counts.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Float
from app.database import Base


class SpiderRun(Base):
    __tablename__ = "spider_runs"

    id = Column(Integer, primary_key=True, index=True)
    spider_name = Column(String(50), nullable=False, index=True)
    task_id = Column(String(100), nullable=False, unique=True, index=True)
    status = Column(String(20), default="PENDING")   # PENDING, RUNNING, SUCCESS, EMPTY, FAILURE

    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    # Result counts
    items_scraped = Column(Integer, default=0)
    items_new = Column(Integer, default=0)
    items_duplicate = Column(Integer, default=0)
    items_dropped_nlp = Column(Integer, default=0)
    items_dropped_clean = Column(Integer, default=0)
    alerts_created = Column(Integer, default=0)

    # Triggered by
    triggered_by = Column(String(100), default="schedule")  # schedule or user email

    error_message = Column(Text, nullable=True)

    # Persisted, UI-filtered log of the run (replayed when the live Redis buffer has expired)
    log = Column(Text, nullable=True)

    def __repr__(self):
        return f"<SpiderRun(id={self.id}, spider={self.spider_name}, status={self.status})>"
