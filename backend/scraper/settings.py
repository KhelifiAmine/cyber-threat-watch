"""
Scrapy Settings — Controls how the scraper behaves.
We set polite crawling defaults so we don't get banned.
"""

BOT_NAME = "cybershield_scraper"

SPIDER_MODULES = ["scraper.spiders"]
NEWSPIDER_MODULE = "scraper.spiders"

# ─── Polite Crawling ───
# Don't hammer servers — be a good citizen
ROBOTSTXT_OBEY = True
CONCURRENT_REQUESTS = 4
DOWNLOAD_DELAY = 1.5
CONCURRENT_REQUESTS_PER_DOMAIN = 2

# ─── User Agent ───
USER_AGENT = "CyberThreatWatch/1.0 (Threat Intelligence Research)"

# ─── Pipelines ───
# Order matters: clean first, then score, then store
ITEM_PIPELINES = {
    "scraper.pipelines.CleaningPipeline": 100,
    "scraper.pipelines.NLPPipeline": 200,
    "scraper.pipelines.RiskScoringPipeline": 300,
    "scraper.pipelines.EnrichmentPipeline": 350,
    "scraper.pipelines.DatabasePipeline": 400,
}

# ─── Playwright (for JS-heavy sites) ───
TWISTED_REACTOR = "twisted.internet.asyncioreactor.AsyncioSelectorReactor"
DOWNLOAD_HANDLERS = {
    "http": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
    "https": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
}
PLAYWRIGHT_LAUNCH_OPTIONS = {"headless": True}
PLAYWRIGHT_MAX_PAGES_PER_CONTEXT = 4
PLAYWRIGHT_DEFAULT_NAVIGATION_TIMEOUT = 60000  # 60s for slow pages (DarkReading)

# ─── Logging ───
LOG_LEVEL = "INFO"

# ─── Timeouts ───
DOWNLOAD_TIMEOUT = 60

# ─── Retry ───
RETRY_TIMES = 3
RETRY_HTTP_CODES = [500, 502, 503, 504, 408, 429]