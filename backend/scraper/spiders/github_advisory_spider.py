"""
GitHub Advisory Spider — Scrapes the GitHub Advisory Database via REST API.

Source: https://api.github.com/advisories
No authentication required for public advisories.

Provides:
- Detailed technical vulnerability descriptions (1000+ chars)
- CVE and GHSA identifiers
- Severity ratings
- Affected packages with versions
- Patch information

Data quality is excellent for NLP classification — descriptions are
written by security researchers, not journalists.
"""

import json
from datetime import datetime, timezone, timedelta

import scrapy

from scraper.items import ThreatItem


class GithubAdvisorySpider(scrapy.Spider):
    name = "github"
    allowed_domains = ["api.github.com"]

    custom_settings = {
        "ROBOTSTXT_OBEY": False,
        "DOWNLOAD_DELAY": 1.0,
        "DEFAULT_REQUEST_HEADERS": {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    }

    # How many days back to fetch on each run
    DAYS_BACK = 1
    # Max advisories per run — capped low so each run stays light and fast
    MAX_ADVISORIES = 40
    # Only fetch reviewed (curated) advisories
    ADVISORY_TYPE = "reviewed"

    def __init__(self, days_back=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if days_back:
            self.DAYS_BACK = int(days_back)
        self.advisories_fetched = 0

    def start_requests(self):
        since = (datetime.now(timezone.utc) - timedelta(days=self.DAYS_BACK)).strftime(
            "%Y-%m-%d"
        )
        until = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        url = (
            f"https://api.github.com/advisories"
            f"?type={self.ADVISORY_TYPE}"
            f"&per_page=100"
            f"&sort=published"
            f"&direction=desc"
            f"&published={since}..{until}"
        )

        self.logger.info(f"[GitHub] Fetching advisories since {since}")
        yield scrapy.Request(url, callback=self.parse)

    def parse(self, response):
        """Parse the advisory list response."""
        if response.status != 200:
            self.logger.error(
                f"[GitHub] API returned {response.status}: {response.text[:200]}"
            )
            return

        advisories = json.loads(response.text)
        self.logger.info(f"[GitHub] Received {len(advisories)} advisories")

        for advisory in advisories:
            if self.advisories_fetched >= self.MAX_ADVISORIES:
                self.logger.info(
                    f"[GitHub] Reached max advisories ({self.MAX_ADVISORIES})"
                )
                return

            item = self._parse_advisory(advisory)
            if item:
                self.advisories_fetched += 1
                yield item

        # Handle pagination via Link header
        if len(advisories) >= 100 and self.advisories_fetched < self.MAX_ADVISORIES:
            link_header = response.headers.get("Link", b"").decode("utf-8", errors="ignore")
            next_url = self._extract_next_url(link_header)
            if next_url:
                self.logger.info(f"[GitHub] Following pagination")
                yield scrapy.Request(next_url, callback=self.parse)

    def _parse_advisory(self, advisory):
        """Parse a single GitHub advisory into a ThreatItem."""
        ghsa_id = advisory.get("ghsa_id", "")
        cve_id = advisory.get("cve_id", "")
        summary = advisory.get("summary", "")
        description = advisory.get("description", "")
        severity = advisory.get("severity", "medium")
        published = advisory.get("published_at", "")
        source_url = advisory.get("html_url", "")

        # Must have at least a summary
        if not summary or len(summary) < 10:
            return None

        # Build title
        if cve_id and cve_id not in summary:
            title = f"[{cve_id}] {summary}"
        elif ghsa_id and not cve_id:
            title = f"[{ghsa_id}] {summary}"
        else:
            title = summary

        # Build description — combine summary + full description
        full_description = description if description else summary

        # Extract affected products from vulnerabilities array
        products = []
        version_details = []
        vulns = advisory.get("vulnerabilities", [])
        for vuln in vulns:
            pkg = vuln.get("package", {})
            pkg_name = pkg.get("name", "")
            pkg_ecosystem = pkg.get("ecosystem", "")
            if pkg_name:
                products.append(f"{pkg_ecosystem}/{pkg_name}" if pkg_ecosystem else pkg_name)

            # Extract version range (affected versions) AND patched version
            vuln_range = vuln.get("vulnerable_version_range", "")
            patched = vuln.get("first_patched_version", "")
            if pkg_name and vuln_range:
                version_details.append(f"{pkg_name} affected versions: {vuln_range}")
            if pkg_name and patched:
                version_details.append(f"{pkg_name} patched in version {patched}")
            elif patched:
                full_description += f" Patched in version {patched}."

        if products:
            full_description += f" Affected packages: {', '.join(products[:10])}."
        if version_details:
            full_description += " " + " ".join(version_details[:20])

        # Build CVE/GHSA reference string
        refs = []
        if cve_id:
            refs.append(cve_id)
        if ghsa_id:
            refs.append(ghsa_id)
        ttp_codes = ",".join(refs)

        # Map severity
        severity_map = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
        }
        mapped_severity = severity_map.get(severity, "MEDIUM")

        # Parse publication date
        published_at = datetime.now(timezone.utc)
        if published:
            try:
                published_at = datetime.fromisoformat(
                    published.replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        # Detect threat type from content
        threat_type = self._detect_threat_type(
            f"{summary} {description}".lower()
        )

        item = ThreatItem()
        item["title"] = title[:500]
        item["description"] = full_description[:5000]
        item["source"] = "GitHub Advisory"
        item["source_url"] = source_url or f"https://github.com/advisories/{ghsa_id}"
        item["severity"] = mapped_severity
        item["threat_type"] = threat_type
        item["ttp_codes"] = ttp_codes[:500]
        item["regions"] = "Global"
        item["published_at"] = published_at

        return item

    def _detect_threat_type(self, text):
        """Detect threat type from advisory content."""
        type_map = {
            "remote code execution": "rce",
            "arbitrary code execution": "rce",
            "code injection": "rce",
            "command injection": "rce",
            "sql injection": "sqli",
            "cross-site scripting": "xss",
            "xss": "xss",
            "denial of service": "ddos",
            "dos": "ddos",
            "path traversal": "path_traversal",
            "directory traversal": "path_traversal",
            "authentication bypass": "auth_bypass",
            "authorization bypass": "auth_bypass",
            "privilege escalation": "privilege_escalation",
            "information disclosure": "data_leak",
            "sensitive data": "data_leak",
            "data exposure": "data_leak",
            "deserialization": "deserialization",
            "ssrf": "ssrf",
            "server-side request": "ssrf",
            "csrf": "csrf",
            "open redirect": "open_redirect",
            "buffer overflow": "buffer_overflow",
            "memory corruption": "buffer_overflow",
            "race condition": "race_condition",
        }
        for keyword, ttype in type_map.items():
            if keyword in text:
                return ttype
        return "vulnerability"

    def _extract_next_url(self, link_header):
        """Extract next page URL from GitHub Link header."""
        if not link_header:
            return None
        for part in link_header.split(","):
            if 'rel="next"' in part:
                url = part.split(";")[0].strip().strip("<>")
                return url
        return None