from fastapi import APIRouter

from app.api.threats import router as threats_router
from app.api.cves import router as cves_router
from app.api.alerts import router as alerts_router
from app.api.dashboard import router as dashboard_router
from app.api.auth import router as auth_router
from app.api.admin import router as admin_router
from app.api.audit_log import router as audit_log_router
from app.api.scraper import router as scraper_router
from app.api.notifications import router as notifications_router
from app.api.proposals import router as proposals_router
from app.api.advisory import router as advisory_router
from app.api.news import router as news_router
from app.api.reports import router as reports_router

api_router = APIRouter(prefix="/api")

api_router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
api_router.include_router(admin_router, prefix="/admin", tags=["Admin"])
api_router.include_router(audit_log_router, prefix="/admin", tags=["Audit Log"])
api_router.include_router(threats_router, prefix="/threats", tags=["Threats"])
api_router.include_router(cves_router, prefix="/cves", tags=["CVEs"])
api_router.include_router(alerts_router, prefix="/alerts", tags=["Alerts"])
api_router.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(scraper_router, prefix="/scraper", tags=["Scraper"])
api_router.include_router(notifications_router, prefix="/notifications", tags=["Notifications"])
api_router.include_router(proposals_router, prefix="/proposals", tags=["Proposals"])
api_router.include_router(advisory_router, prefix="/advisory", tags=["Advisory"])
api_router.include_router(news_router, prefix="/news", tags=["News"])
api_router.include_router(reports_router, prefix="/reports", tags=["Reports"])