"""
NVD Spider — Scrapes the NIST National Vulnerability Database.
Uses the official NVD API 2.0 (free, no API key required but rate-limited).

Pulls recent CVEs with CVSS scores, affected products, and exploit status.
This is the primary source of real vulnerability data.
"""

import json
import os
from datetime import datetime, timedelta

import scrapy

from scraper.items import CVEItem


class NVDSpider(scrapy.Spider):
    name = "nvd"
    allowed_domains = ["services.nvd.nist.gov"]

    # NVD allows 5 req/30s without API key → 1 req every 6s minimum
    custom_settings = {
        "DOWNLOAD_DELAY": 6,
        "RANDOMIZE_DOWNLOAD_DELAY": False,
        "AUTOTHROTTLE_ENABLED": False,
        "RETRY_HTTP_CODES": [429, 500, 502, 503, 504],
        "RETRY_TIMES": 3,
        "RETRY_BACKOFF_MAX": 60,
    }

    def __init__(self, days_back=1, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.days_back = int(days_back)
        self.api_key = os.getenv("NVD_API_KEY", "")
        # With API key: 50 req/30s → 0.6s delay; without: 5 req/30s → 6s delay
        if self.api_key:
            self.custom_settings["DOWNLOAD_DELAY"] = 1

    def start_requests(self):
        """Build the NVD API request with date range."""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=self.days_back)

        # NVD API 2.0 format
        pub_start = start_date.strftime("%Y-%m-%dT00:00:00.000")
        pub_end = end_date.strftime("%Y-%m-%dT23:59:59.999")

        # Cap at the newest 40 CVEs of the window — keeps each run light so a
        # single Ollama hiccup can't stall a 300-item batch. Pagination disabled below.
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?pubStartDate={pub_start}"
            f"&pubEndDate={pub_end}"
            f"&resultsPerPage=40"
        )

        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        self.logger.info(f"[NVD] Fetching CVEs from {start_date.date()} to {end_date.date()}")
        yield scrapy.Request(url=url, callback=self.parse, headers=headers)

    def parse(self, response):
        """Parse the NVD API JSON response."""
        try:
            data = json.loads(response.text)
        except json.JSONDecodeError:
            self.logger.error("[NVD] Failed to parse JSON response")
            return

        total = data.get("totalResults", 0)
        vulnerabilities = data.get("vulnerabilities", [])
        self.logger.info(f"[NVD] Found {total} total CVEs, processing {len(vulnerabilities)}")

        for vuln_wrapper in vulnerabilities:
            cve_data = vuln_wrapper.get("cve", {})
            yield self._parse_cve(cve_data)

        # Pagination intentionally disabled — we only want the newest ~40 CVEs
        # per run to keep enrichment batches small and runs fast.

    def _parse_cve(self, cve_data):
        """Extract structured data from a single CVE entry."""
        cve_id = cve_data.get("id", "")

        # Get English description
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Extract CVSS score (try v3.1 first, then v3.0, then v2.0)
        metrics = cve_data.get("metrics", {})
        cvss_score = None
        cvss_vector = ""
        cvss_severity = "UNKNOWN"

        for version in ["cvssMetricV31", "cvssMetricV30"]:
            if version in metrics:
                metric = metrics[version][0]
                cvss_data = metric.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString", "")
                cvss_severity = cvss_data.get("baseSeverity", "UNKNOWN")
                break

        if cvss_score is None and "cvssMetricV2" in metrics:
            metric = metrics["cvssMetricV2"][0]
            cvss_data = metric.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString", "")
            cvss_severity = metric.get("baseSeverity", "UNKNOWN")

        # Extract affected products (CPE)
        configurations = cve_data.get("configurations", [])
        products = []
        vendors = set()
        affected_products = []  # structured enrichment format
        seen_products = set()
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3].replace("_", " ").title()
                        product = parts[4].replace("_", " ").title()
                        vendors.add(parts[3])
                        products.append(f"{parts[3]} {parts[4]}")
                        # Build structured product entry
                        key = f"{vendor}:{product}".lower()
                        if key not in seen_products:
                            seen_products.add(key)
                            version_start = match.get("versionStartIncluding", "")
                            version_end = match.get("versionEndIncluding", match.get("versionEndExcluding", ""))
                            version_str = ""
                            if version_start and version_end:
                                version_str = f"{version_start} – {version_end}"
                            elif version_end:
                                version_str = f"up to {version_end}"
                            elif len(parts) >= 6 and parts[5] != "*":
                                version_str = parts[5]
                            affected_products.append({
                                "vendor": vendor,
                                "product_raw": f"{vendor} {product}",
                                "product_family": product,
                                "versions": [version_str] if version_str else [],
                            })

        # Check for exploit references
        references = cve_data.get("references", [])
        ref_urls = []
        exploit_available = "unknown"
        for ref in references:
            ref_urls.append(ref.get("url", ""))
            tags = ref.get("tags", [])
            if "Exploit" in tags:
                exploit_available = "yes"

        # Published date
        published_str = cve_data.get("published", "")
        published_at = None
        if published_str:
            try:
                published_at = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
            except ValueError:
                published_at = datetime.utcnow()

        item = CVEItem()
        item["cve_id"] = cve_id
        item["title"] = f"{cve_id}: {description[:100]}" if description else cve_id
        item["description"] = description
        item["affected_products"] = ", ".join(products[:10])
        item["vendor"] = ", ".join(list(vendors)[:5])
        item["cvss_base_score"] = cvss_score
        item["cvss_vector"] = cvss_vector
        item["cvss_severity"] = cvss_severity
        item["exploit_available"] = exploit_available
        item["patch_available"] = "unknown"
        item["source"] = "NVD"
        item["source_url"] = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        item["references"] = " | ".join(ref_urls[:5])
        item["published_at"] = published_at
        if affected_products:
            item["_enrichment"] = {"affected_products": affected_products[:15]}

        return item