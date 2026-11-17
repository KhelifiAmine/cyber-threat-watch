"""
Microsoft Spider — Scrapes Microsoft Security Response Center (MSRC) CVRF advisories.

Uses the MSRC CVRF API v3.0 — no authentication required.
Extracts CVEs with:
  - Impacted product versions (from FullProductName product tree)
  - KB article numbers and fixed build versions (from Remediations array)
  - Severity and CVSS scores
  - Full description from Notes
"""

import re
from datetime import datetime, timedelta

import scrapy

from scraper.items import CVEItem


class MicrosoftSpider(scrapy.Spider):
    name = "microsoft"
    allowed_domains = ["api.msrc.microsoft.com"]

    api_base = "https://api.msrc.microsoft.com/cvrf/v3.0"

    custom_settings = {
        "DOWNLOAD_DELAY": 1,
        "CONCURRENT_REQUESTS_PER_DOMAIN": 2,
        "RETRY_TIMES": 3,
        "ROBOTSTXT_OBEY": False,
    }

    # MSRC bundles a whole month into one document but revises individual CVEs
    # throughout the month. We fetch the most recent monthly document(s) — two, to
    # cover the few days around a new Patch Tuesday — and then keep only the CVEs
    # whose own revision/release date falls within RECENT_DAYS ("posted newly").
    MAX_DOCUMENTS = 2
    RECENT_DAYS = 7

    def start_requests(self):
        url = f"{self.api_base}/Updates"
        self.logger.info("[Microsoft] Fetching MSRC update list")
        yield scrapy.Request(
            url,
            callback=self.parse_updates,
            headers={"Accept": "application/json"},
        )

    def parse_updates(self, response):
        try:
            data = response.json()
        except Exception:
            self.logger.error(
                f"[Microsoft] Failed to parse JSON response: {response.text[:200]}"
            )
            return

        updates = data.get("value", [])
        self.logger.info(f"[Microsoft] Got {len(updates)} total MSRC update documents")

        # MSRC publishes monthly ("Patch Tuesday"). A short date window misses the
        # latest document for most of the month, so instead we always take the most
        # recent MAX_DOCUMENTS monthly documents. The pipeline de-duplicates CVEs,
        # so re-processing the latest document on each run is safe.
        recent = []
        for u in updates:
            doc_id = u.get("ID", "")
            # Monthly docs have IDs like "YYYY-Mon"; skip advisory-only docs
            if not doc_id or len(doc_id) > 10:
                continue
            release_str = u.get("InitialReleaseDate", "")[:10]
            try:
                release_date = datetime.strptime(release_str, "%Y-%m-%d")
            except ValueError:
                continue
            recent.append((release_date, doc_id))

        # Sort newest first, take only MAX_DOCUMENTS
        recent.sort(key=lambda x: x[0], reverse=True)
        selected = recent[: self.MAX_DOCUMENTS]

        self.logger.info(
            "[Microsoft] Processing %d recent document(s): %s",
            len(selected),
            ", ".join(d for _, d in selected),
        )

        for _, doc_id in selected:
            url = f"{self.api_base}/cvrf/{doc_id}"
            yield scrapy.Request(
                url,
                callback=self.parse_cvrf_document,
                headers={"Accept": "application/json"},
                cb_kwargs={"doc_id": doc_id},
            )

    def parse_cvrf_document(self, response, doc_id):
        try:
            data = response.json()
        except Exception:
            self.logger.error(
                f"[Microsoft] Failed to parse CVRF document {doc_id}"
            )
            return

        vulnerabilities = data.get("Vulnerability", [])
        product_tree = data.get("ProductTree", {})

        # Build full product map: ProductID → full name (including version)
        product_map = self._build_product_map(product_tree)

        # Only emit CVEs newly posted/revised within the recency window.
        recency_cutoff = datetime.utcnow() - timedelta(days=self.RECENT_DAYS)
        recent_count = 0

        self.logger.info(
            f"[Microsoft] Document {doc_id}: {len(vulnerabilities)} vulnerabilities, "
            f"{len(product_map)} products in tree"
        )

        for vuln in vulnerabilities:
            cve_id = vuln.get("CVE", "")
            if not cve_id or not cve_id.startswith("CVE-"):
                continue

            # Skip CVEs that were not posted or revised recently.
            latest_date = self._vuln_latest_date(vuln)
            if latest_date is not None and latest_date < recency_cutoff:
                continue
            recent_count += 1

            raw_title = vuln.get("Title", {}).get("Value", cve_id)
            # Some MSRC entries (third-party CVEs on Azure Linux) put the full
            # description in the Title field. Cap at 120 chars for display.
            title = raw_title if len(raw_title) <= 120 else raw_title[:117] + "..."

            # ── CVSS & severity ──────────────────────────────────────────────
            cvss_score = None
            cvss_vector = ""
            severity = "UNKNOWN"

            cvss_sets = vuln.get("CVSSScoreSets", [])
            if cvss_sets:
                score_set = cvss_sets[0]
                base = score_set.get("BaseScore")
                if base is not None:
                    try:
                        cvss_score = float(base)
                    except (ValueError, TypeError):
                        pass
                cvss_vector = score_set.get("Vector", "")

            for threat in vuln.get("Threats", []):
                if threat.get("Type") == 3:  # Severity type
                    desc = threat.get("Description", {}).get("Value", "")
                    if desc:
                        severity = desc.upper()
                        break

            # Only keep Critical and Important (skip Moderate / Low)
            if severity not in ("CRITICAL", "IMPORTANT"):
                continue

            # Normalize Microsoft's "IMPORTANT" to standard CVSS "HIGH"
            if severity == "IMPORTANT":
                severity = "HIGH"

            # ── Description ──────────────────────────────────────────────────
            description = ""
            for note in vuln.get("Notes", []):
                if note.get("Type") == 1:  # Description note type
                    description = note.get("Value", "")
                    break

            # ── Remediations: KB articles + fixed builds ─────────────────────
            # Each remediation entry has KB number, FixedBuild, and ProductID list.
            # We build: (kb, fixed_build, {product_ids}) per remediation.
            remediation_entries = []  # list of (kb_str, fixed_build, product_id_set)
            for rem in vuln.get("Remediations", []):
                rem_type = rem.get("Type", 0)
                # CVRF Remediation types: 2 = VendorFix, 1 = Workaround
                # Only collect VendorFix entries (they have KB numbers and FixedBuild)
                if rem_type != 2:
                    continue
                kb = rem.get("Description", {}).get("Value", "").strip()
                fixed_build = rem.get("FixedBuild", "").strip()
                product_ids = set(str(p) for p in rem.get("ProductID", []))
                if kb or fixed_build:
                    remediation_entries.append((kb, fixed_build, product_ids))

            # ── Affected products with versions ──────────────────────────────
            # Collect all product IDs referenced in remediations
            all_product_ids: set = set()
            for _, _, pids in remediation_entries:
                all_product_ids.update(pids)

            # Also collect from Threats type 1 (Affected products)
            for threat in vuln.get("Threats", []):
                if threat.get("Type") == 1:
                    for pid in threat.get("ProductID", []):
                        all_product_ids.add(str(pid))

            # Map product IDs → full names (with version strings)
            product_names = []
            for pid in all_product_ids:
                name = product_map.get(pid)
                if name:
                    product_names.append(name)

            # Deduplicate
            product_names = list(dict.fromkeys(product_names))

            # Build structured affected_products
            affected_products = []
            seen_families: set = set()
            for p in product_names:
                family = self._normalize_product_family(p)
                version = self._extract_version(p)
                key = family.lower()
                if key not in seen_families:
                    seen_families.add(key)
                    affected_products.append({
                        "vendor": "Microsoft",
                        "product_raw": p,
                        "product_family": family,
                        "versions": [version] if version else [],
                    })
                else:
                    # Add version to existing entry if not already there
                    for ap in affected_products:
                        if ap["product_family"].lower() == key:
                            if version and version not in ap["versions"]:
                                ap["versions"].append(version)
                            break

            # ── Remediation steps (structured only, NOT injected into description) ──
            remediation_steps = []
            seen_kbs: set = set()
            for kb, fixed_build, _ in remediation_entries:
                if kb and kb not in seen_kbs:
                    seen_kbs.add(kb)
                    step = f"Apply KB{kb}"
                    if fixed_build:
                        step += f" (fixed build: {fixed_build})"
                    remediation_steps.append(step)

            products_str = ", ".join(product_names[:10]) if product_names else ""

            item = CVEItem()
            item["cve_id"] = cve_id
            item["title"] = f"{cve_id}: {title}"
            item["description"] = description or raw_title
            item["affected_products"] = products_str
            item["vendor"] = "Microsoft"
            item["cvss_base_score"] = cvss_score
            item["cvss_vector"] = cvss_vector
            item["cvss_severity"] = severity
            item["exploit_available"] = "unknown"
            item["patch_available"] = "yes" if remediation_entries else "unknown"
            item["source"] = "Microsoft MSRC"
            item["source_url"] = (
                f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}"
            )
            item["references"] = doc_id
            item["published_at"] = datetime.utcnow()
            item["_enrichment"] = {
                "affected_products": affected_products,
                "remediation_steps": remediation_steps[:5],
            }

            yield item

        self.logger.info(
            f"[Microsoft] Document {doc_id}: {recent_count} CVE(s) posted/revised "
            f"within last {self.RECENT_DAYS} days"
        )

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _vuln_latest_date(vuln):
        """Most recent date for a vulnerability: the max of its RevisionHistory
        dates, falling back to ReleaseDate. Returns a datetime or None."""
        dates = []
        for rev in (vuln.get("RevisionHistory") or []):
            d = (rev.get("Date") or "")[:10]
            if d:
                dates.append(d)
        rel = (vuln.get("ReleaseDate") or "")[:10]
        if rel:
            dates.append(rel)
        parsed = []
        for d in dates:
            try:
                parsed.append(datetime.strptime(d, "%Y-%m-%d"))
            except ValueError:
                continue
        return max(parsed) if parsed else None

    @staticmethod
    def _build_product_map(product_tree):
        """
        Return a dict: ProductID (str) → full product name.
        The CVRF product tree has both a Branch hierarchy and a flat
        FullProductName list. The flat list is authoritative and always present.
        """
        product_map = {}

        # Flat list — most reliable source
        for fp in product_tree.get("FullProductName", []):
            pid = fp.get("ProductID", "")
            name = fp.get("Value", "")
            if pid and name:
                product_map[str(pid)] = name

        # Branch hierarchy as fallback for any missing IDs
        def traverse(node, prefix=""):
            items = node.get("ProductItems") or node.get("Items") or []
            for item in items:
                pid = item.get("ProductID", "")
                name = item.get("Value", "") or item.get("Name", "")
                if pid and name and str(pid) not in product_map:
                    full_name = f"{prefix} {name}".strip() if prefix else name
                    product_map[str(pid)] = full_name
                traverse(item, name)

        branches = product_tree.get("Branch", [])
        if isinstance(branches, dict):
            branches = [branches]
        for branch in branches:
            branch_name = branch.get("Name", "")
            for item in branch.get("Items", []):
                traverse(item, branch_name if branch_name != "Microsoft" else "")

        return product_map

    @staticmethod
    def _extract_version(product_name):
        """
        Extract the version string from a full product name.
        Examples:
          "Windows 10 Version 22H2 for x64-based Systems" → "22H2"
          "Windows Server 2022 Datacenter" → "2022"
          "Microsoft Exchange Server 2019 Cumulative Update 15" → "2019 CU15"
          ".NET 8.0" → "8.0"
        """
        # Windows Version XXHX
        m = re.search(r"\bVersion\s+(\S+)", product_name, re.IGNORECASE)
        if m:
            return m.group(1)
        # Cumulative Update / Service Pack
        m = re.search(
            r"\b(\d{4})\b.*?Cumulative\s+Update\s+(\d+)",
            product_name,
            re.IGNORECASE,
        )
        if m:
            return f"{m.group(1)} CU{m.group(2)}"
        # Year version (Server 2019, Office 2021, etc.)
        m = re.search(r"\b(20\d{2})\b", product_name)
        if m:
            return m.group(1)
        # .NET / runtime versions like "8.0", "6.0.36"
        m = re.search(r"\b(\d+\.\d[\d.]*)\b", product_name)
        if m:
            return m.group(1)
        return ""

    @staticmethod
    def _normalize_product_family(product_name):
        """
        Strip version suffixes to get a clean product family name.
        E.g.:
          "Windows 10 Version 22H2 for x64-based Systems" → "Windows 10"
          "Windows Server 2022 Datacenter" → "Windows Server"
          "Microsoft Exchange Server 2019 CU15" → "Exchange Server"
          ".NET 8.0" → ".NET"
        """
        name = product_name
        # Remove "Microsoft " prefix
        name = re.sub(r"^Microsoft\s+", "", name, flags=re.IGNORECASE)
        # Windows Server YYYY → Windows Server
        name = re.sub(r"(Windows Server)\s+\d{4}.*", r"\1", name)
        # Windows 10/11 Version … → Windows 10/11
        name = re.sub(r"(Windows\s+\d+)\s+Version\s+\S+.*", r"\1", name)
        # Windows 10/11 for x64 (no version tag) → Windows 10/11
        name = re.sub(r"(Windows\s+\d+)\s+for\s+.*", r"\1", name, flags=re.IGNORECASE)
        # Exchange Server YYYY → Exchange Server
        name = re.sub(r"(Exchange Server)\s+\d{4}.*", r"\1", name)
        # SharePoint YYYY → SharePoint
        name = re.sub(r"(SharePoint).*", r"\1", name, flags=re.IGNORECASE)
        # Office YYYY → Office
        name = re.sub(r"(Office)\s+\d{4}.*", r"\1", name, flags=re.IGNORECASE)
        # .NET X.Y → .NET
        name = re.sub(r"(\.NET)\s+[\d.]+.*", r"\1", name)
        # Azure / Visual Studio → keep as-is up to first version number
        name = re.sub(r"\s+\d+\.\d+.*$", "", name)
        # Strip "for x64/x86/ARM-based Systems" trailing parts
        name = re.sub(r"\s+for\s+.+$", "", name, flags=re.IGNORECASE)
        return name.strip()
