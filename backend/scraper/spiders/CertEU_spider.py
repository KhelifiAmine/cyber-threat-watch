"""
CERT-EU Spider
Source: https://cert.europa.eu/publications/security-advisories-rss
Type: RSS feed → follow advisory links for full content
Schedule: Every 2 hours at :15
Auth: None required

CERT-EU publishes technical security advisories covering:
- Critical vulnerabilities in enterprise software
- CVE references with remediation guidance
- Technical descriptions of security issues
- Affected vendor/product information

Similar in style to CERT-FR (which achieves 100% NLP pass rate).
Expected NLP pass rate: ~98-100% (government CERT advisory language)
"""

import scrapy
from scrapy import Request
from datetime import datetime, timezone, timedelta
import re
import logging

from scraper.items import ThreatItem
from scraper.utils import extract_structured_text

logger = logging.getLogger(__name__)


class CERTEUSpider(scrapy.Spider):
    name = "certeu"
    # Don't restrict domains — CERT-EU may redirect to subdomains or CDN
    start_urls = ["https://cert.europa.eu/publications/security-advisories-rss"]

    # Alternative URLs to try if the primary fails
    FALLBACK_URLS = [
        "https://www.cert.europa.eu/publications/security-advisories-rss",
        "https://cert.europa.eu/cert/filteredsite/newsroom/cert_bulletins_rss.xml",
    ]

    # How many days back to fetch on each run
    DAYS_BACK = 7

    custom_settings = {
        "DOWNLOAD_DELAY": 3,
        "CONCURRENT_REQUESTS": 1,
        "ROBOTSTXT_OBEY": False,  # Government public advisories — robots.txt may block bots
        "DEFAULT_REQUEST_HEADERS": {
            "User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)",
            "Accept": "application/xml, application/rss+xml, text/xml, application/atom+xml, */*",
            "Accept-Language": "en-US,en;q=0.9",
        },
    }

    SEVERITY_KEYWORDS = {
        "CRITICAL": ["critical", "cvss 9", "cvss 10", "remote code execution", "rce",
                      "zero-day", "0-day", "actively exploited"],
        "HIGH": ["high", "cvss 7", "cvss 8", "privilege escalation",
                 "authentication bypass", "arbitrary code"],
        "MEDIUM": ["medium", "cvss 4", "cvss 5", "cvss 6", "denial of service",
                   "information disclosure", "cross-site scripting"],
        "LOW": ["low", "cvss 1", "cvss 2", "cvss 3"],
    }

    TIMEZONE_MAP = {
        "CET": "+0100", "CEST": "+0200",
        "EET": "+0200", "EEST": "+0300",
        "WET": "+0000", "WEST": "+0100",
        "GMT": "+0000", "BST": "+0100", "UTC": "+0000",
        "EST": "-0500", "EDT": "-0400",
        "CST": "-0600", "CDT": "-0500",
        "MST": "-0700", "MDT": "-0600",
        "PST": "-0800", "PDT": "-0700",
    }

    def __init__(self, days_back=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if days_back:
            self.DAYS_BACK = int(days_back)
        self.cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.DAYS_BACK)

    def parse(self, response):
        """Parse the CERT-EU RSS/Atom feed."""
        if response.status != 200:
            logger.error(
                f"CERT-EU: RSS feed returned HTTP {response.status} for {response.url}. "
                f"Body preview: {response.text[:300]}"
            )
            # Try fallback URLs
            for fallback in self.FALLBACK_URLS:
                if fallback != response.url:
                    logger.info(f"CERT-EU: Trying fallback URL: {fallback}")
                    yield Request(fallback, callback=self.parse)
                    return
            return

        body = re.sub(rb"xmlns[^\"]+\"[^\"]+\"", b"", response.body)
        response = response.replace(body=body)

        items = response.xpath("//item")
        if not items:
            items = response.xpath("//entry")
            logger.info(f"CERT-EU: Using Atom format, found {len(items)} entries (filtering to last {self.DAYS_BACK} days)")
        else:
            logger.info(f"CERT-EU: Using RSS format, found {len(items)} items (filtering to last {self.DAYS_BACK} days)")

        if not items:
            logger.error(
                f"CERT-EU: No items found in feed. "
                f"Content-Type: {response.headers.get('Content-Type', b'').decode()}, "
                f"Body preview: {response.text[:500]}"
            )

        skipped_old = 0

        for item in items:
            title = item.xpath("title/text()").get("").strip()
            link = item.xpath("link/text()").get("").strip()
            description = item.xpath("description/text()").get("").strip()
            pub_date = item.xpath("pubDate/text()").get("").strip()

            if not link:
                link = item.xpath("link/@href").get("").strip()
            if not pub_date:
                pub_date = item.xpath("updated/text()").get("").strip()
                if not pub_date:
                    pub_date = item.xpath("published/text()").get("").strip()
            if not description:
                description = item.xpath("summary/text()").get("").strip()
                if not description:
                    description = item.xpath("content/text()").get("").strip()

            if not title or not link:
                continue

            # --- Date filter: skip items older than days_back ---
            published_at = self._parse_date(pub_date)
            if published_at < self.cutoff_date:
                skipped_old += 1
                continue

            if description and len(description) > 100:
                yield from self._yield_threat(
                    title=title,
                    description=description,
                    source_url=link,
                    published_at=published_at,
                )
            else:
                yield Request(
                    url=link,
                    callback=self.parse_advisory,
                    meta={
                        "rss_title": title,
                        "rss_description": description,
                        "source_url": link,
                        "published_at": published_at,
                    },
                )

        if skipped_old:
            logger.info(f"CERT-EU: Skipped {skipped_old} advisories older than {self.DAYS_BACK} days")

    def parse_advisory(self, response):
        """Parse a full CERT-EU advisory page for detailed content."""
        meta = response.meta
        source_url = meta["source_url"]
        title = meta.get("rss_title", "")
        published_at = meta["published_at"]

        description = ""
        for selector in ("article", ".content", "main", ".publication-content", ".advisory-content", "#content"):
            section = response.css(selector)
            if section:
                description = extract_structured_text(section[0])
                if description and len(description) > 100:
                    break

        if not description:
            description = meta.get("rss_description", "")

        if not description:
            logger.warning(f"CERT-EU: No description for {source_url}, skipping")
            return

        yield from self._yield_threat(
            title=title,
            description=description,
            source_url=source_url,
            published_at=published_at,
        )

    def _yield_threat(self, title, description, source_url, published_at):
        """Build and yield a ThreatItem from advisory data."""
        if not title or not description:
            return

        description = re.sub(r"<[^>]+>", " ", description).strip()

        combined_text = f"{title} {description}"
        cve_ids = list(set(re.findall(r"CVE-\d{4}-\d{4,}", combined_text)))

        severity = self._determine_severity(combined_text)

        if cve_ids and not any(cve in description for cve in cve_ids[:3]):
            cve_str = ", ".join(cve_ids[:10])
            description = f"{description} (CVE references: {cve_str})"

        threat = ThreatItem()
        threat["title"] = title[:500]
        threat["description"] = description
        threat["source"] = "CERT-EU"
        threat["source_url"] = source_url
        threat["severity"] = severity
        threat["threat_type"] = ""
        threat["ttp_codes"] = ""
        threat["regions"] = "Europe"
        threat["published_at"] = published_at

        yield threat

        logger.info(
            f"CERT-EU: Yielded '{title[:60]}...' "
            f"severity={severity} CVEs={len(cve_ids)}"
        )

    def _determine_severity(self, text):
        """Determine severity from advisory text using keyword matching."""
        text_lower = text.lower()

        cvss_match = re.search(r"cvss[:\s]*(\d+\.?\d*)", text_lower)
        if cvss_match:
            score = float(cvss_match.group(1))
            if score >= 9.0:
                return "CRITICAL"
            elif score >= 7.0:
                return "HIGH"
            elif score >= 4.0:
                return "MEDIUM"
            else:
                return "LOW"

        for severity, keywords in self.SEVERITY_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                return severity

        return "HIGH"

    def _parse_date(self, date_str):
        """Parse various date formats, handling European timezone abbreviations."""
        if not date_str:
            return datetime.now(timezone.utc)

        cleaned = date_str.strip()

        for tz_name, tz_offset in self.TIMEZONE_MAP.items():
            pattern = r'\b' + re.escape(tz_name) + r'\b'
            if re.search(pattern, cleaned):
                cleaned = re.sub(pattern, tz_offset, cleaned)
                break

        cleaned = re.sub(r"(\d+)(st|nd|rd|th)", r"\1", cleaned)

        date_formats = [
            "%a, %d %b %Y %H:%M:%S %z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%d %B %Y",
            "%B %d, %Y",
        ]

        for fmt in date_formats:
            try:
                dt = datetime.strptime(cleaned, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue

        logger.warning(f"CERT-EU: Could not parse date '{date_str}', using now()")
        return datetime.now(timezone.utc)