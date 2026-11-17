"""
CERT-FR Spider — Scrapes French national CERT advisories via RSS feed.

Source: https://www.cert.ssi.gouv.fr/feed/
Published by ANSSI (Agence nationale de la securite des systemes d'information).

Provides:
- Detailed technical vulnerability advisories in French
- CVE references
- Affected products and versions
- Severity ratings
- Remediation guidance

French technical language works well with SecureBERT/TTPXHunter as the model
understands cybersecurity terminology across languages.
"""

import re
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime

import scrapy

from scraper.items import ThreatItem
from scraper.utils import extract_structured_text


class CertFRSpider(scrapy.Spider):
    name = "certfr"
    allowed_domains = ["www.cert.ssi.gouv.fr", "cert.ssi.gouv.fr"]

    start_urls = [
        "https://www.cert.ssi.gouv.fr/feed/",
    ]

    DAYS_BACK = 7

    custom_settings = {
        "DOWNLOAD_DELAY": 2.0,
    }

    def __init__(self, days_back=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if days_back:
            self.DAYS_BACK = int(days_back)
        self.cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.DAYS_BACK)

    def parse(self, response):
        """Parse the CERT-FR RSS feed."""
        self.logger.info(f"[CERT-FR] Parsing RSS feed (filtering to last {self.DAYS_BACK} days)")

        items = response.xpath("//item")
        self.logger.info(f"[CERT-FR] Found {len(items)} advisories in feed")

        skipped_old = 0
        for entry in items:
            title = entry.xpath("title/text()").get("")
            link = entry.xpath("link/text()").get("")
            description = entry.xpath("description/text()").get("")
            pub_date = entry.xpath("pubDate/text()").get("")

            if not title or len(title) < 10:
                continue

            # Date filter: skip items older than days_back
            published_at_check = None
            if pub_date:
                try:
                    published_at_check = parsedate_to_datetime(pub_date)
                except (ValueError, TypeError):
                    pass
            if published_at_check and published_at_check < self.cutoff_date:
                skipped_old += 1
                continue

            # Follow the link to get full advisory details
            if link:
                yield scrapy.Request(
                    link,
                    callback=self.parse_advisory,
                    meta={
                        "title": title.strip(),
                        "source_url": link.strip(),
                        "pub_date": pub_date,
                        "rss_description": description.strip() if description else "",
                    },
                )

        if skipped_old:
            self.logger.info(f"[CERT-FR] Skipped {skipped_old} advisories older than {self.DAYS_BACK} days")

    def parse_advisory(self, response):
        """Parse an individual CERT-FR advisory page."""
        title = response.meta["title"]
        source_url = response.meta["source_url"]
        pub_date = response.meta["pub_date"]
        rss_description = response.meta["rss_description"]

        self.logger.info(f"[CERT-FR] Parsing advisory: {title[:60]}")

        # Extract full page text
        all_texts = response.xpath("//body//text()").getall()
        all_texts = [t.strip() for t in all_texts if t.strip()]
        page_text = " ".join(all_texts)

        # Extract main content from the advisory page
        # CERT-FR uses structured sections: Risque, Systemes affectes, Description, Solution
        description = ""
        for selector in (".certfr-advisory-description", "article", ".content", "section", "main", ".advisory"):
            section = response.css(selector)
            if section:
                description = extract_structured_text(section[0])
                if description and len(description) > 100:
                    break

        # Fall back to full page text (already has everything including affected systems)
        # Limit to 4000 chars to avoid DOM noise but capture full advisory body
        if not description or len(description) < 100:
            description = page_text[:4000]

        if not description:
            description = rss_description

        if not description:
            description = title

        # Extract CVE references
        cve_ids = re.findall(r"CVE-\d{4}-\d{4,}", page_text)
        cve_str = ",".join(sorted(set(cve_ids)))

        # Extract CERT-FR reference ID (e.g., CERTFR-2026-AVI-0155)
        certfr_ref = re.search(r"CERTFR-\d{4}-[A-Z]{3}-\d+", page_text)
        certfr_id = certfr_ref.group(0) if certfr_ref else ""

        if certfr_id and certfr_id not in title:
            full_title = f"[{certfr_id}] {title}"
        else:
            full_title = title

        # Add CVE info to description
        if cve_ids:
            description += f" ({len(cve_ids)} CVEs: {cve_str[:200]})"

        # Detect severity from French text
        severity = self._detect_severity(page_text.lower())

        # Detect threat type
        threat_type = self._detect_threat_type(page_text.lower())

        # Parse publication date
        published_at = datetime.now(timezone.utc)
        if pub_date:
            try:
                published_at = parsedate_to_datetime(pub_date)
            except (ValueError, TypeError):
                pass

        # Build TTP codes — combine CERT-FR ref + CVEs
        refs = []
        if certfr_id:
            refs.append(certfr_id)
        if cve_str:
            refs.append(cve_str)
        ttp_codes = ",".join(refs)

        item = ThreatItem()
        item["title"] = full_title[:500]
        item["description"] = description[:5000]
        item["source"] = "CERT-FR"
        item["source_url"] = source_url
        item["severity"] = severity
        item["threat_type"] = threat_type
        item["ttp_codes"] = ttp_codes[:500]
        item["regions"] = "Europe"
        item["published_at"] = published_at

        yield item

    def _detect_severity(self, text):
        """Detect severity from French advisory text."""
        # Normalize accents
        normalized = text
        for char_from, char_to in [
            ("\xe8", "e"), ("\xe9", "e"), ("\xea", "e"),
            ("\xe0", "a"), ("\xe2", "a"), ("\xf4", "o"),
        ]:
            normalized = normalized.replace(char_from, char_to)

        if "execution de code arbitraire" in normalized:
            return "CRITICAL"
        if "activement exploitee" in normalized or "activement exploite" in normalized:
            return "CRITICAL"
        if "elevation de privileges" in normalized:
            return "HIGH"
        if "deni de service" in normalized:
            return "HIGH"
        if "atteinte a la confidentialite" in normalized:
            return "MEDIUM"
        if "injection de code" in normalized:
            return "HIGH"

        return "MEDIUM"

    def _detect_threat_type(self, text):
        """Detect threat type from French advisory text."""
        normalized = text
        for char_from, char_to in [
            ("\xe8", "e"), ("\xe9", "e"), ("\xea", "e"),
            ("\xe0", "a"), ("\xe2", "a"), ("\xf4", "o"),
        ]:
            normalized = normalized.replace(char_from, char_to)

        if "execution de code arbitraire" in normalized:
            return "rce"
        if "deni de service" in normalized:
            return "ddos"
        if "injection de code" in normalized:
            return "code_injection"
        if "elevation de privileges" in normalized:
            return "privilege_escalation"
        if "atteinte a la confidentialite" in normalized:
            return "data_leak"
        if "contournement de la politique de securite" in normalized:
            return "auth_bypass"

        return "vulnerability"