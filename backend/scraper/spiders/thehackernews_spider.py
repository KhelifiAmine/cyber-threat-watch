"""
TheHackerNews Spider — Scrapes cybersecurity news via RSS.
Source: https://feeds.feedburner.com/TheHackersNews

Two-step: RSS feed → follow each article link → extract full article body.
"""

import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import scrapy

from scraper.items import NewsItem
from scraper.utils import extract_structured_text


class TheHackerNewsSpider(scrapy.Spider):
    name = "thehackernews"
    allowed_domains = ["feeds.feedburner.com", "thehackernews.com"]
    start_urls = ["https://feeds.feedburner.com/TheHackersNews"]

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
        self.logger.info(f"[TheHackerNews] Found {len(items)} articles in feed")

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

    def parse_article(self, response, title, rss_description, published_at):
        """Extract full article body from the page."""
        body = ""

        for selector in ("div.articlebody", "#articlebody"):
            section = response.css(selector)
            if section:
                body = extract_structured_text(section[0])
                if body:
                    break

        description = body if len(body) > len(rss_description) else rss_description

        self.logger.info(
            f"[TheHackerNews] Article '{title[:50]}' — {len(description)} chars"
        )

        yield NewsItem(
            title=title,
            summary="",
            description=description,
            url=response.url,
            source="TheHackerNews",
            published_at=published_at,
        )
