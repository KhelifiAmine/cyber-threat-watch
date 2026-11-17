"""
DarkReading Spider — Scrapes cybersecurity news via RSS.
Source: https://www.darkreading.com/rss.xml

Two-step: RSS feed (plain HTTP) → follow each article link via Playwright → extract full article body.
"""

import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import scrapy

from scraper.items import NewsItem
from scraper.utils import extract_structured_text


class DarkReadingSpider(scrapy.Spider):
    name = "darkreading"
    allowed_domains = ["www.darkreading.com", "darkreading.com"]
    start_urls = ["https://www.darkreading.com/rss.xml"]

    custom_settings = {
        "DOWNLOAD_DELAY": 2,
        "CONCURRENT_REQUESTS_PER_DOMAIN": 1,
        "ROBOTSTXT_OBEY": False,
        "USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "ITEM_PIPELINES": {
            "scraper.pipelines.CleaningPipeline": 100,
            "scraper.pipelines.NLPPipeline": 200,
            "scraper.pipelines.EnrichmentPipeline": 400,
            "scraper.pipelines.DatabasePipeline": 500,
        },
    }

    def parse(self, response):
        items = response.xpath("//item")
        self.logger.info(f"[DarkReading] Found {len(items)} articles in feed")

        for entry in items[:20]:
            title = entry.xpath("title/text()").get("").strip()
            link = entry.xpath("link/text()").get("").strip()
            desc_raw = entry.xpath("description/text()").get("").strip()
            pub_date = entry.xpath("pubDate/text()").get("")

            if not title or not link:
                continue

            # Skip non-article pages (events, webinars, etc.)
            if "/events/" in link or "/webinar/" in link or "/sponsored/" in link:
                self.logger.debug(f"[DarkReading] Skipping non-article: {link}")
                continue

            rss_description = re.sub(r"<[^>]+>", "", desc_raw).strip()

            published_at = None
            if pub_date:
                try:
                    published_at = parsedate_to_datetime(pub_date)
                except Exception:
                    published_at = datetime.now(timezone.utc)

            yield scrapy.Request(
                link,
                callback=self.parse_article,
                meta={
                    "playwright": True,
                    "playwright_include_page": False,
                    "playwright_page_goto_kwargs": {"wait_until": "domcontentloaded"},
                },
                cb_kwargs={
                    "title": title,
                    "rss_description": rss_description,
                    "published_at": published_at or datetime.now(timezone.utc),
                },
            )

    # Boilerplate markers — truncate at first match
    _BOILERPLATE_MARKERS = [
        "How Organizations Are Managing",
        "How Enterprises Are",
        "Inside RSAC",
        "Ditch the Data Center",
        "AI-Powered Credential Security",
        "AI-Powered Cybersecurity for",
        "How Security Teams should",
        "What is the Right Role",
        "Your Guide to Securing",
        "Keep up with the latest",
        "About the Author",
    ]

    # Author bio / role lines at the end
    _AUTHOR_ROLES = [
        "Senior News Director", "Contributing Writer", "Staff Writer",
        "Editor-in-Chief", "Managing Editor", "News Director",
        "Senior Editor", "Contributing Editor",
    ]

    # Leading date line (e.g. "May 20, 2026" or "January 5, 2025")
    _LEADING_DATE_RE = re.compile(
        r"^\s*(?:January|February|March|April|May|June|July|August|September|October|November|December)"
        r"\s+\d{1,2},?\s+\d{4}\s*$",
        re.MULTILINE,
    )

    def _clean_article_body(self, body: str) -> str:
        """Strip leading/trailing boilerplate from DarkReading article body."""
        # Remove leading date lines
        body = self._LEADING_DATE_RE.sub("", body).strip()
        # Remove inline "Related:" lines
        body = re.sub(r"^Related:.*$", "", body, flags=re.MULTILINE)

        # Truncate at trailing boilerplate
        cut_pos = len(body)
        for marker in self._BOILERPLATE_MARKERS:
            pos = body.find(marker)
            if pos != -1 and pos < cut_pos:
                cut_pos = pos
        body = body[:cut_pos].strip()

        # Strip author bio at the end (name + role line + bio paragraph)
        lines = body.rstrip().splitlines()
        while lines:
            last = lines[-1].strip()
            if not last:
                lines.pop()
                continue
            if any(role in last for role in self._AUTHOR_ROLES):
                lines.pop()
                # Also remove the author name line above
                if lines and len(lines[-1].strip().split()) <= 4:
                    lines.pop()
                continue
            # Remove trailing bio paragraph (long line after author name was removed)
            break
        body = "\n".join(lines).strip()

        return body

    def parse_article(self, response, title, rss_description, published_at):
        """Extract full article body from the Playwright-rendered page."""
        body = ""

        # DarkReading uses ArticleBase-Body for article content
        for selector in ("div.ArticleBase-Body", "div.article-content", "div.ContentModule", "article"):
            section = response.css(selector)
            if section:
                body = extract_structured_text(section[0])
                if body:
                    break

        if body:
            body = self._clean_article_body(body)

        description = body if len(body) > len(rss_description) else rss_description

        self.logger.info(
            f"[DarkReading] Article '{title[:50]}' — {len(description)} chars"
        )

        yield NewsItem(
            title=title,
            summary="",
            description=description,
            url=response.url,
            source="DarkReading",
            published_at=published_at,
        )
