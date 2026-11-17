"""
BleepingComputer Spider — Scrapes cybersecurity news via RSS.
Source: https://www.bleepingcomputer.com/feed/

Two-step: RSS feed → follow each article link → extract full article body.
"""

import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import scrapy

from scraper.items import NewsItem
from scraper.utils import extract_structured_text


class BleepingComputerSpider(scrapy.Spider):
    name = "bleepingcomputer"
    allowed_domains = ["www.bleepingcomputer.com", "bleepingcomputer.com"]
    start_urls = ["https://www.bleepingcomputer.com/feed/"]

    custom_settings = {
        "DOWNLOAD_DELAY": 1.5,
        "CONCURRENT_REQUESTS_PER_DOMAIN": 1,
        "ITEM_PIPELINES": {
            "scraper.pipelines.CleaningPipeline": 100,
            "scraper.pipelines.NLPPipeline": 200,
            "scraper.pipelines.EnrichmentPipeline": 400,
            "scraper.pipelines.DatabasePipeline": 500,
        },
    }

    def parse(self, response):
        items = response.xpath("//item")
        self.logger.info(f"[BleepingComputer] Found {len(items)} articles in feed")

        for entry in items[:20]:
            title = entry.xpath("title/text()").get("").strip()
            link = entry.xpath("link/text()").get("").strip()
            desc_raw = entry.xpath("description/text()").get("").strip()
            pub_date = entry.xpath("pubDate/text()").get("")

            if not title or not link:
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
                cb_kwargs={
                    "title": title,
                    "rss_description": rss_description,
                    "published_at": published_at or datetime.now(timezone.utc),
                },
            )

    # Leading metadata: "- May 20, 2026\n- 10:02 AM\n- 0" (date, time, comment count)
    _LEADING_META_RE = re.compile(
        r"^(?:\s*-\s*(?:January|February|March|April|May|June|July|August|September|October|November|December)"
        r"\s+\d{1,2},?\s+\d{4}\s*\n)"
        r"(?:\s*-\s*\d{1,2}:\d{2}\s*(?:AM|PM)\s*\n)"
        r"(?:\s*-\s*\d+\s*\n)",
        re.IGNORECASE,
    )

    # Trailing "Related Articles" headlines
    _RELATED_MARKERS = [
        "Related Articles:",
        "Not a member yet?",
        "Sponsored and written by",
    ]

    def _clean_article_body(self, body: str) -> str:
        """Strip leading metadata and trailing junk from BleepingComputer articles."""
        # Strip leading date/time/comment-count block
        body = self._LEADING_META_RE.sub("", body).strip()

        # Truncate at related articles / sponsored content
        cut_pos = len(body)
        for marker in self._RELATED_MARKERS:
            pos = body.find(marker)
            if pos != -1 and pos < cut_pos:
                cut_pos = pos
        body = body[:cut_pos].strip()

        # Strip trailing related article headlines (short lines at the end)
        lines = body.rstrip().splitlines()
        while lines:
            last = lines[-1].strip()
            if not last:
                lines.pop()
                continue
            # Related headlines are typically short (under 80 chars) and lack periods
            if len(last) < 80 and not last.endswith("."):
                lines.pop()
                continue
            break
        body = "\n".join(lines).strip()

        return body

    def parse_article(self, response, title, rss_description, published_at):
        """Extract full article body from the page."""
        body = ""

        for selector in ("div.article_section", "div.articleBody"):
            section = response.css(selector)
            if section:
                body = extract_structured_text(section[0])
                if body:
                    break

        if body:
            body = self._clean_article_body(body)

        description = body if len(body) > len(rss_description) else rss_description

        self.logger.info(
            f"[BleepingComputer] Article '{title[:50]}' — {len(description)} chars"
        )

        yield NewsItem(
            title=title,
            summary="",
            description=description,
            url=response.url,
            source="BleepingComputer",
            published_at=published_at,
        )
