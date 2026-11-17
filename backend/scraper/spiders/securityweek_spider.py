"""
SecurityWeek Spider — Scrapes cybersecurity news via RSS.
Source: https://www.securityweek.com/feed/

Two-step: RSS feed via plain HTTP → follow each article link via Playwright (Cloudflare-protected) → extract full article body.
"""

import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import scrapy

from scraper.items import NewsItem
from scraper.utils import extract_structured_text


class SecurityWeekSpider(scrapy.Spider):
    name = "securityweek"
    allowed_domains = ["www.securityweek.com", "securityweek.com"]
    start_urls = ["https://www.securityweek.com/feed/"]

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
        self.logger.info(f"[SecurityWeek] Found {len(items)} articles in feed")

        for entry in items[:20]:
            title = entry.xpath("title/text()").get("").strip()
            link = entry.xpath("link/text()").get("").strip()
            desc_raw = entry.xpath("description/text()").get("").strip()
            pub_date = entry.xpath("pubDate/text()").get("")

            # SecurityWeek (WordPress) may include full content in content:encoded
            content_encoded = entry.xpath(
                "*[local-name()='encoded']/text()",
            ).get("").strip()

            if not title or not link:
                continue

            rss_description = re.sub(r"<[^>]+>", "", desc_raw).strip()
            full_content = re.sub(r"<[^>]+>", "", content_encoded).strip() if content_encoded else ""

            published_at = None
            if pub_date:
                try:
                    published_at = parsedate_to_datetime(pub_date)
                except Exception:
                    published_at = datetime.now(timezone.utc)

            # If content:encoded has substantially more text, use it directly
            if len(full_content) > len(rss_description) * 2:
                full_content = self._clean_article_body(full_content)
                self.logger.info(
                    f"[SecurityWeek] Article '{title[:50]}' — {len(full_content)} chars from RSS content:encoded"
                )
                yield NewsItem(
                    title=title,
                    summary="",
                    description=full_content,
                    url=link,
                    source="SecurityWeek",
                    published_at=published_at or datetime.now(timezone.utc),
                )
            else:
                # Follow the link with Playwright to get the full article
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

    # Boilerplate markers — truncate article body at the first match
    _BOILERPLATE_MARKERS = [
        "Related :", "Related:",
        "More from SecurityWeek",
        "Latest News",
        "Trending",
        "Daily Briefing Newsletter",
        "People on the Move",
        "Expert Insights",
        "Virtual Event",
        "Webinar Today:",
    ]

    # Leading noise patterns — lines that appear before the real article
    _LEADING_NOISE_RE = re.compile(
        r"^(?:\s*[-–—]*\s*(?:Flipboard|Reddit|Whatsapp|Email|By)\s*)+$",
        re.MULTILINE,
    )
    # WordPress category headers that appear as the first line (e.g. "Cybersecurity Funding")
    _CATEGORY_HEADERS = [
        "Cybersecurity Funding", "Application Security", "Artificial Intelligence",
        "Malware & Threats", "Endpoint Security", "ICS/OT", "Supply Chain Security",
        "Threat Intelligence", "Vulnerabilities", "Cloud Security", "Data Protection",
    ]

    def _clean_article_body(self, body: str) -> str:
        """Strip leading/trailing boilerplate from article body."""
        # --- Strip leading junk ---
        # Remove social share buttons and "By" lines
        body = self._LEADING_NOISE_RE.sub("", body)
        # Remove category header if it's the first line
        lines = body.strip().splitlines()
        while lines and lines[0].strip() in self._CATEGORY_HEADERS:
            lines.pop(0)
        body = "\n".join(lines).strip()

        # --- Truncate at trailing boilerplate ---
        cut_pos = len(body)
        for marker in self._BOILERPLATE_MARKERS:
            pos = body.find(marker)
            if pos != -1 and pos < cut_pos:
                cut_pos = pos
        body = body[:cut_pos].strip()

        # Final cleanup — any remaining social share fragments
        body = re.sub(
            r"[\s\-]*(?:Flipboard|Reddit|Whatsapp|Email)[\s\-]*(?:Flipboard|Reddit|Whatsapp|Email[\s\-]*)*",
            "", body,
        ).strip()
        return body

    def parse_article(self, response, title, rss_description, published_at):
        """Extract full article body from the Playwright-rendered page."""
        body = ""

        # SecurityWeek (WordPress) article body
        for selector in ("div.entry-content", "article"):
            section = response.css(selector)
            if section:
                body = extract_structured_text(section[0])
                if body:
                    break

        if body:
            body = self._clean_article_body(body)

        description = body if len(body) > len(rss_description) else rss_description

        self.logger.info(
            f"[SecurityWeek] Article '{title[:50]}' — {len(description)} chars"
        )

        yield NewsItem(
            title=title,
            summary="",
            description=description,
            url=response.url,
            source="SecurityWeek",
            published_at=published_at,
        )
