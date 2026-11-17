"""
FortiGuard Spider — Scrapes Fortinet PSIRT advisories.

Approach:
1. Fetch the RSS feed from FortiGuard to get recent advisory URLs
2. For each advisory URL, parse the HTML page for CVE details,
   affected products, CVSS scores, and remediation steps.
"""

import re
from datetime import datetime

import scrapy
from scrapy.http import XmlResponse

from scraper.items import CVEItem


class FortiGuardSpider(scrapy.Spider):
    name = "fortiguard"
    allowed_domains = ["fortiguard.fortinet.com", "fortiguard.com", "filestore.fortinet.com"]

    # RSS feed redirects: fortiguard.com/rss/ir.xml → filestore.fortinet.com/fortiguard/rss/ir.xml
    rss_url = "https://filestore.fortinet.com/fortiguard/rss/ir.xml"

    custom_settings = {
        "DOWNLOAD_DELAY": 2,
        "RANDOMIZE_DOWNLOAD_DELAY": True,
        "CONCURRENT_REQUESTS_PER_DOMAIN": 1,
        "RETRY_TIMES": 3,
    }

    MAX_ITEMS = 20  # Limit to recent advisories per run

    def start_requests(self):
        self.logger.info("[FortiGuard] Fetching RSS feed")
        yield scrapy.Request(self.rss_url, callback=self.parse_rss)

    def parse_rss(self, response):
        # RSS feed is XML — use Selector with xml type
        response.selector.remove_namespaces()
        items = response.xpath("//item")
        self.logger.info(f"[FortiGuard] RSS feed has {len(items)} items, processing up to {self.MAX_ITEMS}")

        for item in items[:self.MAX_ITEMS]:
            title = item.xpath("title/text()").get("").strip()
            link = item.xpath("link/text()").get("").strip()
            # Sometimes <link> content is in the tail of the tag
            if not link:
                link = item.xpath("guid/text()").get("").strip()
            pub_date_str = item.xpath("pubDate/text()").get("")

            if not link:
                continue

            # Extract CVSS from description CDATA if available
            desc_html = item.xpath("description/text()").get("")
            rss_cvss = None
            cvss_match = re.search(r"CVSSv3\s*Score:\s*</strong>\s*([\d.]+)", desc_html)
            if cvss_match:
                try:
                    rss_cvss = float(cvss_match.group(1))
                except ValueError:
                    pass

            yield scrapy.Request(
                link,
                callback=self.parse_advisory,
                cb_kwargs={
                    "rss_title": title,
                    "pub_date_str": pub_date_str,
                    "rss_cvss": rss_cvss,
                },
            )

    def parse_advisory(self, response, rss_title, pub_date_str, rss_cvss):
        # Extract advisory ID from URL (FG-IR-YY-NNN)
        advisory_id = ""
        id_match = re.search(r"(FG-IR-\d{2,4}-\d{3,4})", response.url)
        if id_match:
            advisory_id = id_match.group(1)

        # Page title
        page_title = response.xpath("//h1/text()").get("").strip() or rss_title

        # Extract all CVE IDs from the page
        page_text = response.text
        cve_ids = list(dict.fromkeys(re.findall(r"CVE-\d{4}-\d{4,7}", page_text)))

        if not cve_ids:
            self.logger.warning(f"[FortiGuard] No CVE IDs found on {response.url}, skipping")
            return

        # CVSS score — look in page tables first, fall back to RSS
        cvss_score = rss_cvss
        cvss_link = response.xpath("//a[contains(@href,'cvss/v3-calculator')]")
        if cvss_link:
            score_text = cvss_link.xpath("text()").get("")
            try:
                cvss_score = float(score_text.strip())
            except (ValueError, AttributeError):
                pass

        # Map CVSS to severity
        cvss_severity = self._cvss_to_severity(cvss_score)

        # Summary / Description
        summary = ""
        summary_header = response.xpath("//h3[contains(text(),'Summary')]")
        if summary_header:
            # Get all text after the Summary heading until the next heading
            summary_parts = summary_header.xpath("following-sibling::p/text()").getall()
            summary = "\n\n".join(p.strip() for p in summary_parts if p.strip())
        if not summary:
            # Fallback: get first substantial paragraph
            paragraphs = response.xpath("//p/text()").getall()
            for p in paragraphs:
                if len(p.strip()) > 50:
                    summary = p.strip()
                    break

        # Affected products table
        affected_products = []
        remediation_steps = []
        tables = response.xpath("//table")
        for table in tables:
            headers = [h.xpath(".//text()").get("").strip().lower() for h in table.xpath(".//thead//th | .//tr[1]/th | .//tr[1]/td")]
            # Look for a table with Version/Affected/Solution columns
            has_version = any("version" in h for h in headers)
            has_affected = any("affected" in h for h in headers)

            if has_version or has_affected:
                rows = table.xpath(".//tbody/tr | .//tr[position()>1]")
                for row in rows:
                    cells = row.xpath("td")
                    if len(cells) < 2:
                        continue

                    cell_texts = [" ".join(c.xpath(".//text()").getall()).strip() for c in cells]

                    product_name = cell_texts[0] if len(cell_texts) > 0 else ""
                    affected_range = cell_texts[1] if len(cell_texts) > 1 else ""
                    solution = cell_texts[2] if len(cell_texts) > 2 else ""

                    if not product_name or not affected_range:
                        continue

                    # Determine product family from product name
                    product_family = re.sub(r'\s+\d[\d.]*$', '', product_name).strip()

                    affected_products.append({
                        "vendor": "Fortinet",
                        "product_raw": product_name,
                        "product_family": product_family,
                        "versions": [affected_range],
                    })

                    if solution and "upgrade" in solution.lower():
                        remediation_steps.append(f"{product_name}: {solution}")
                break  # Only use the first matching table

        # Published date
        published_at = self._parse_pub_date(pub_date_str)

        # Build enrichment data for the pipeline guard
        enrichment_data = {
            "affected_products": affected_products,
        }
        if remediation_steps:
            enrichment_data["remediation_steps"] = remediation_steps

        # Build affected_products string for the CVEItem field
        products_str = ", ".join(
            f"{p['product_raw']} ({'; '.join(p['versions'])})" for p in affected_products
        ) if affected_products else ""

        # Use the first CVE as the primary cve_id, store all in references
        primary_cve = cve_ids[0]
        references = " | ".join(cve_ids[1:]) if len(cve_ids) > 1 else ""
        if advisory_id:
            references = f"{advisory_id} | {references}" if references else advisory_id

        item = CVEItem()
        item["cve_id"] = primary_cve
        item["title"] = f"{primary_cve}: {page_title}"
        item["description"] = summary or page_title
        item["affected_products"] = products_str
        item["vendor"] = "Fortinet"
        item["cvss_base_score"] = cvss_score
        item["cvss_vector"] = ""
        item["cvss_severity"] = cvss_severity
        item["exploit_available"] = "unknown"
        item["patch_available"] = "yes" if remediation_steps else "unknown"
        item["source"] = "FortiGuard"
        item["source_url"] = response.url
        item["references"] = references
        item["published_at"] = published_at
        item["_enrichment"] = enrichment_data

        self.logger.info(f"[FortiGuard] Yielding {primary_cve} — {len(affected_products)} affected products")
        yield item

    @staticmethod
    def _cvss_to_severity(score):
        if score is None:
            return "UNKNOWN"
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "UNKNOWN"

    @staticmethod
    def _parse_pub_date(pub_date_str):
        if not pub_date_str:
            return datetime.utcnow()
        # RFC 2822 format: "Wed, 15 Apr 2026 00:00:00 -0700"
        try:
            from email.utils import parsedate_to_datetime
            # parsedate_to_datetime returns timezone-aware datetime;
            # strip tzinfo to match PostgreSQL TIMESTAMP WITHOUT TIME ZONE column
            return parsedate_to_datetime(pub_date_str).replace(tzinfo=None)
        except Exception:
            pass
        # Fallback
        try:
            return datetime.strptime(pub_date_str[:25].strip(), "%a, %d %b %Y %H:%M:%S")
        except Exception:
            return datetime.utcnow()
