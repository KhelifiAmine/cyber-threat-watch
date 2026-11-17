"""
Cisco Spider — Scrapes Cisco PSIRT advisories via the public RSS feed.

No authentication required. Fetches advisories published in the last 30 days,
then follows each advisory link to extract CVE IDs, CVSS scores, affected
products, and remediation info from the full advisory page.
"""

import re
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime

import scrapy

from scraper.items import CVEItem
from scraper.utils import extract_structured_text


class CiscoSpider(scrapy.Spider):
    name = "cisco"
    allowed_domains = [
        "feeds.feedburner.com",
        "sec.cloudapps.cisco.com",
        "tools.cisco.com",
        "www.cisco.com",
    ]

    RSS_URL = "https://feeds.feedburner.com/CiscoSecurityAdvisory"

    custom_settings = {
        "DOWNLOAD_DELAY": 1,
        "CONCURRENT_REQUESTS_PER_DOMAIN": 1,
        "RETRY_TIMES": 3,
        "ROBOTSTXT_OBEY": False,
    }

    def start_requests(self):
        self.logger.info("[Cisco] Fetching public RSS feed")
        yield scrapy.Request(self.RSS_URL, callback=self.parse_rss)

    # ── RSS layer ──────────────────────────────────────────────────────────────

    def parse_rss(self, response):
        items = response.xpath("//item")
        self.logger.info(f"[Cisco] Found {len(items)} RSS items")

        cutoff = datetime.utcnow() - timedelta(days=7)

        for entry in items:
            title = entry.xpath("title/text()").get("").strip()
            link = (
                entry.xpath("link/text()").get("")
                or entry.xpath("guid/text()").get("")
            ).strip()
            pub_date_str = entry.xpath("pubDate/text()").get("")
            description = entry.xpath("description/text()").get("").strip()

            pub_date = self._parse_pub_date(pub_date_str)
            if pub_date and pub_date < cutoff:
                self.logger.debug(f"[Cisco] Skipping old advisory: {title}")
                continue

            if not link:
                continue

            yield scrapy.Request(
                link,
                callback=self.parse_advisory,
                cb_kwargs={
                    "rss_title": title,
                    "rss_description": description,
                    "published_at": pub_date,
                },
            )

    # ── Advisory page layer ────────────────────────────────────────────────────

    def parse_advisory(self, response, rss_title, rss_description, published_at):
        """Parse a full Cisco PSIRT advisory page."""
        # Extract all CVE IDs — deduplicate but preserve order
        cves = list(dict.fromkeys(re.findall(r"CVE-\d{4}-\d{4,}", response.text)))
        if not cves:
            self.logger.debug(f"[Cisco] No CVE found at {response.url} — skipping")
            return

        primary_cve = cves[0]

        # Advisory slug from URL e.g. cisco-sa-webex-app-client-esc-gLMLqEeN
        advisory_id = response.url.rstrip("/").split("/")[-1]

        # ── CVSS score ─────────────────────────────────────────────────────────
        cvss_score = self._extract_cvss_score(response)
        severity = self._score_to_severity(cvss_score)

        # Override severity from page text if CVSS not found
        if severity == "UNKNOWN":
            sev_match = re.search(
                r"\b(Critical|High|Medium|Low)\b.*?Advisory",
                response.text,
                re.IGNORECASE,
            )
            if sev_match:
                severity = sev_match.group(1).upper()

        # ── CVSS vector ────────────────────────────────────────────────────────
        cvss_vector = ""
        vec_match = re.search(r"(CVSS:[\d.]+/[A-Za-z:/0-9.]+)", response.text)
        if vec_match:
            cvss_vector = vec_match.group(1)

        # ── Description ────────────────────────────────────────────────────────
        description = self._extract_description(response, rss_description)

        # ── Affected products ──────────────────────────────────────────────────
        product_names, affected_products = self._extract_products(response, rss_title)

        # ── Remediation (used only for patch_available detection) ─────────────
        remediation = self._extract_remediation(response)

        # ── Patch availability ─────────────────────────────────────────────────
        patch_available = "unknown"
        if remediation or re.search(
            r"\b(fixed in|upgrade to|update to|install version)\b",
            response.text,
            re.IGNORECASE,
        ):
            patch_available = "yes"
        elif re.search(r"\bno fix\b|\bno patch\b", response.text, re.IGNORECASE):
            patch_available = "no"

        # ── References ────────────────────────────────────────────────────────
        other_cves = [c for c in cves[1:] if c != primary_cve]
        references = " | ".join(other_cves) if other_cves else ""
        if advisory_id and advisory_id.startswith("cisco-sa-"):
            references = f"{advisory_id} | {references}" if references else advisory_id

        products_str = ", ".join(product_names[:10]) if product_names else ""

        item = CVEItem()
        item["cve_id"] = primary_cve
        item["title"] = f"{primary_cve}: {rss_title}" if rss_title else primary_cve
        item["description"] = description
        item["affected_products"] = products_str
        item["vendor"] = "Cisco"
        item["cvss_base_score"] = cvss_score
        item["cvss_vector"] = cvss_vector
        item["cvss_severity"] = severity
        item["exploit_available"] = "unknown"
        item["patch_available"] = patch_available
        item["source"] = "Cisco PSIRT"
        item["source_url"] = response.url
        item["references"] = references
        item["published_at"] = published_at or datetime.utcnow()
        enrichment = {"affected_products": affected_products}
        if remediation:
            enrichment["remediation_steps"] = [remediation]
        item["_enrichment"] = enrichment

        self.logger.info(
            f"[Cisco] Yielding {primary_cve} severity={severity} "
            f"products={len(affected_products)}"
        )
        yield item

    # ── Extraction helpers ─────────────────────────────────────────────────────

    def _extract_cvss_score(self, response):
        """Try multiple patterns to extract the CVSS base score."""
        # Cisco-specific: hidden input with CVSS vector and score
        hdn = response.css('#hdncvssvector::attr(value)').get("")
        if hdn:
            m = re.search(r'Base\s+([\d.]+)', hdn)
            if m:
                try:
                    return float(m.group(1))
                except ValueError:
                    pass
        # JSON-style: "cvssBaseScore": "9.8"
        m = re.search(r'"cvssBaseScore"\s*:\s*"?([\d.]+)"?', response.text)
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                pass
        # Table/label style: "CVSS Base Score 9.8" or "CVSS Base Score: 9.8"
        m = re.search(
            r"CVSS\s+Base\s+Score\s*[:\|]?\s*([\d.]+)",
            response.text,
            re.IGNORECASE,
        )
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                pass
        # Embedded JSON "baseScore": 9.8
        m = re.search(r'"baseScore"\s*:\s*([\d.]+)', response.text)
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                pass
        return None

    @staticmethod
    def _score_to_severity(score):
        if score is None:
            return "UNKNOWN"
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _strip_cisco_boilerplate(text):
        """Remove standard Cisco advisory boilerplate from description text."""
        # Remove "This advisory is available at the following link:..." and everything after
        text = re.sub(
            r"\s*This advisory is available at the following link:.*",
            "", text, flags=re.DOTALL | re.IGNORECASE,
        ).strip()
        # Remove "Cisco has released...There are (no) workarounds..." as a pair
        text = re.sub(
            r"\s*Cisco has released software updates that address th(?:is|ese) vulnerabilit(?:y|ies)\.?\s*"
            r"There are (?:no )?workarounds that address th(?:is|ese) vulnerabilit(?:y|ies)\.?",
            "", text, flags=re.IGNORECASE,
        ).strip()
        # Remove standalone "Cisco has released software updates..." sentence
        text = re.sub(
            r"\s*Cisco has released software updates that address th(?:is|ese) vulnerabilit(?:y|ies)\.?",
            "", text, flags=re.IGNORECASE,
        ).strip()
        # Remove standalone workarounds sentence
        text = re.sub(
            r"\s*There are (?:no )?workarounds that address th(?:is|ese) vulnerabilit(?:y|ies)\.?",
            "", text, flags=re.IGNORECASE,
        ).strip()
        return text

    def _extract_description(self, response, fallback):
        """Extract advisory summary/description from the page."""
        # Prefer the actual summary section on the advisory page
        for selector in (
            "#summaryfield",
            "div.ud-section-summary",
            "#ud-summary",
            "div.sectionBody",
        ):
            section = response.css(selector)
            if section:
                text = extract_structured_text(section[0])
                text = self._strip_cisco_boilerplate(text)
                if text and len(text) > 30:
                    return text[:2000]

        # Fall back to meta description tag
        meta = response.css('meta[name="description"]::attr(content)').get("")
        if meta and len(meta) > 50:
            return self._strip_cisco_boilerplate(meta)[:2000]

        # Fall back to RSS description
        text = (fallback or "").strip()
        if text:
            return self._strip_cisco_boilerplate(text)[:2000]
        return text

    # Words that start configuration/diagnostic instructions — not product names.
    _INSTRUCTION_STARTS = re.compile(
        r"^(connect|choose|determine|check|verify|use |in the|to |"
        r"for information|see the|if the|log in|navigate|go to|"
        r"enter|click|select|note:|there are no|an? |local |"
        r"ip |the |this |when |session )",
        re.IGNORECASE,
    )

    # Generic words that are not product names.
    _GENERIC_WORDS = frozenset({
        "platforms", "products", "devices", "software", "releases",
        "services", "systems", "configurations", "features",
        "deployment", "telemetry", "radsec", "radius", "tacacs",
        "protocol", "interface", "module", "mode",
    })
    # Phrases extracted from boilerplate text — not real products.
    _BOILERPLATE_PHRASES = re.compile(
        r"Cisco\s+(software releases|devices that are running)|"
        r"^(On-Prem Deployment|Cloud Deployment|High Availability|"
        r"REST API|SNMP|SSH|CLI Access|Web UI)$",
        re.IGNORECASE,
    )

    def _is_product_name(self, text: str) -> bool:
        """Return True if text looks like a product name, not an instruction."""
        if not text or len(text) > 120:
            return False
        if self._INSTRUCTION_STARTS.match(text):
            return False
        # Must contain at least one alphanumeric word
        if not re.search(r"[A-Za-z]{2,}", text):
            return False
        # Reject generic phrases like "Cisco platforms"
        words = text.lower().replace("cisco", "").split()
        if len(words) <= 1 and words and words[0] in self._GENERIC_WORDS:
            return False
        # Reject boilerplate phrases
        if self._BOILERPLATE_PHRASES.match(text):
            return False
        # Reject bare single words without "Cisco" or a model number — likely features
        if "cisco" not in text.lower() and not re.search(r"\d", text):
            stripped = text.lower().replace("cisco", "").split()
            if len(stripped) <= 1:
                return False
        # Reject configuration/status descriptions
        if re.search(
            r"is (not )?(configured|affected|enabled)|are not affected|"
            r"has the\s|Administration interface|VLAN|sub-interface|"
            r"web UI|not affected by",
            text, re.IGNORECASE,
        ):
            return False
        return True

    def _extract_products(self, response, rss_title=""):
        """Return (product_names: list[str], affected_products: list[dict])."""
        product_names = []

        # ── Step 1: Extract from paragraph text in the vulnerable products section.
        # Cisco advisories name products in prose: "this vulnerability affected
        # Cisco Unity Connection" or "affected the following Cisco platforms:".
        section_text = ""
        for selector in (
            "#vulnerableproducts",
            "#affectedproducts",
            "div.ud-section-vulnerable",
            "#ud-affected-products",
        ):
            section = response.css(selector)
            if section:
                section_text = " ".join(section.css("p::text, ::text").getall())
                section_text = re.sub(r"\s+", " ", section_text).strip()

                # Extract "Cisco <Product>" mentions from paragraph text
                for m in re.finditer(r"Cisco\s+([\w][\w ./-]+?)(?=,|\.|;| if | and | when | Software| regardless)", section_text):
                    name = f"Cisco {m.group(1).strip()}"
                    name = re.sub(r"\s*\(\s*CSC\w+\s*\)", "", name).strip()
                    if self._is_product_name(name):
                        product_names.append(name)

                # ── Step 2: Check li tags but filter out instructions.
                # Some advisories list platforms in <li> (e.g. "Catalyst 9200 Series Switches").
                for li in section.css("li"):
                    name = " ".join(li.css("::text").getall()).strip()
                    name = re.sub(r"\s*\(\s*CSC\w+\s*\)", "", name).strip()
                    if self._is_product_name(name):
                        product_names.append(name)

                if product_names:
                    break

        # ── Step 3: Fallback — extract from RSS title if nothing else worked.
        if not product_names:
            title = rss_title or ""
            m = re.search(
                r"Cisco\s+([\w][\w ./-]+?)(?:\s+(?:Vulnerability|Advisory|Denial|"
                r"Remote|Elevation|Information|Arbitrary|Cross-Site|Privilege|"
                r"Command|Path|SQL|Unauthorized|Authentication|Stored|Insecure|"
                r"Multiple|Persistent))",
                title,
            )
            if m:
                name = f"Cisco {m.group(1).strip()}"
                name = re.sub(r"\s*\(\s*CSC\w+\s*\)", "", name).strip()
                if self._is_product_name(name):
                    product_names.append(name)
            if not product_names:
                for m2 in re.finditer(
                    r"Cisco\s+([\w][\w ./-]+?)(?=\s+and\s+|\s*$|,)", title
                ):
                    name = f"Cisco {m2.group(1).strip()}"
                    name = re.sub(r"\s*\(\s*CSC\w+\s*\)", "", name).strip()
                    if self._is_product_name(name):
                        product_names.append(name)

        # ── Step 4: Last resort — extract from page <h1> title
        if not product_names:
            page_title = response.css("h1::text").get("").strip()
            if page_title:
                for m in re.finditer(
                    r"Cisco\s+([\w][\w ./-]+?)(?=\s+and\s+|,|\s*$)", page_title
                ):
                    name = f"Cisco {m.group(1).strip()}"
                    name = re.sub(r"\s*\(\s*CSC\w+\s*\)", "", name).strip()
                    if self._is_product_name(name):
                        product_names.append(name)

        # Deduplicate, preserve order, cap at 20
        seen: set = set()
        unique: list = []
        for p in product_names:
            key = p.lower()
            if key not in seen:
                seen.add(key)
                unique.append(p)
        product_names = unique[:20]

        affected_products = [
            {
                "vendor": "Cisco",
                "product_raw": p,
                "product_family": self._normalize_product_family(p),
                "versions": [],
            }
            for p in product_names
        ]

        return product_names, affected_products

    def _extract_remediation(self, response):
        """Extract fixed-software or workaround text from the advisory page."""
        for selector in (
            "#fixedsoftware",
            "#fs",
            "div.ud-section-fixed-software",
            "#ud-fixed-software",
        ):
            section = response.css(selector)
            if section:
                text = extract_structured_text(section[0])
                if text and len(text) > 10:
                    return text[:1000]

        # Regex fallback — strip any HTML tags from the match
        m = re.search(
            r"(?:Fixed\s+(?:Software|Release[s]?)|Recommended\s+Release[s]?)"
            r"[:\s]+([^\n]{10,300})",
            response.text,
            re.IGNORECASE,
        )
        if m:
            clean = re.sub(r"<[^>]+>", "", m.group(1)).strip()
            if clean:
                return clean

        return ""

    @staticmethod
    def _normalize_product_family(product_name):
        name = re.sub(r"^Cisco\s+", "", product_name, flags=re.IGNORECASE)
        name = re.sub(r"\s+(Software|Firmware)$", "", name, flags=re.IGNORECASE)
        known = {
            # Security appliances
            "adaptive security appliance (asa)": "ASA",
            "adaptive security appliance": "ASA",
            "secure firewall threat defense": "Secure Firewall",
            "secure firewall management center": "Secure Firewall",
            "secure firewall": "Secure Firewall",
            "firepower threat defense": "Firepower",
            "firepower management center": "Firepower",
            "secure web appliance": "Secure Web Appliance",
            "secure email": "Secure Email",
            "secure endpoint": "Secure Endpoint",
            "secure client": "Secure Client",
            "anyconnect": "AnyConnect",
            "umbrella": "Umbrella",
            "duo": "Duo",
            # Networking OS
            "ios xe": "IOS XE",
            "ios xr": "IOS XR",
            "nx-os": "NX-OS",
            # Switching/routing
            "catalyst center": "Catalyst Center",
            "dna center": "Catalyst Center",
            "catalyst sd-wan": "SD-WAN",
            "sd-wan": "SD-WAN",
            "catalyst": "Catalyst",
            "nexus dashboard": "Nexus Dashboard",
            "nexus": "Nexus",
            "meraki": "Meraki",
            "sg350": "Small Business",
            "rv340": "Small Business",
            "small business": "Small Business",
            "aironet": "Aironet",
            # Compute
            "integrated management controller": "IMC",
            "imc": "IMC",
            "ucs": "UCS",
            "hyperflex": "HyperFlex",
            "enterprise network compute system": "ENCS",
            "encs": "ENCS",
            # Collaboration
            "webex meetings": "Webex",
            "webex app": "Webex",
            "webex contact center": "Webex",
            "webex": "Webex",
            "unified communications manager": "UCM",
            "unity connection": "Unity Connection",
            "meeting server": "Meeting Server",
            "expressway": "Expressway",
            "telepresence": "TelePresence",
            "jabber": "Jabber",
            "finesse": "Finesse",
            "enterprise chat and email": "ECE",
            "enterprise chat": "ECE",
            "slido": "Slido",
            # Identity & access
            "identity services engine (ise)": "ISE",
            "identity services engine": "ISE",
            "ise": "ISE",
            # Management & orchestration
            "prime infrastructure": "Prime Infrastructure",
            "evolved programmable network manager": "EPNM",
            "epnm": "EPNM",
            "crosswork": "Crosswork",
            "network services orchestrator": "NSO",
            "nso": "NSO",
            "smart software manager": "SSM",
            "ssm": "SSM",
            "cyber vision": "Cyber Vision",
            "thousandeyes": "ThousandEyes",
            "ndfc": "NDFC",
            # APIC
            "application policy infrastructure controller": "APIC",
            "apic": "APIC",
        }
        lower = name.strip().lower()
        for pattern, family in known.items():
            if pattern in lower:
                return family
        # Strip common suffixes for unmatched names
        name = re.sub(
            r"\s+(Appliances?|Switches|Routers|Servers|Nodes|Controllers|Series|Devices)$",
            "", name.strip(), flags=re.IGNORECASE,
        )
        return name.strip()

    @staticmethod
    def _parse_pub_date(pub_date_str):
        if not pub_date_str:
            return datetime.utcnow()
        try:
            return parsedate_to_datetime(pub_date_str).replace(tzinfo=None)
        except Exception:
            pass
        try:
            return datetime.strptime(pub_date_str[:25].strip(), "%a, %d %b %Y %H:%M:%S")
        except Exception:
            return datetime.utcnow()
