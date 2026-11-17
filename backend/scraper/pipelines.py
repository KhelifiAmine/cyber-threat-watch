"""
Scrapy Pipelines — Process every item before it reaches the database.

Five stages:
1. CleaningPipeline:    Normalize and validate data
2. NLPPipeline:         Classify with TTPXHunter, extract TTPs, detect exploits
3. RiskScoringPipeline: Calculate risk score using enriched data
4. EnrichmentPipeline:  LLM extraction via phi3.5 for ALL items (no threshold)
5. DatabasePipeline:    Store to PostgreSQL after full pipeline completes (skip duplicates)
"""

import json
import os
import logging
from datetime import datetime

import psycopg2
from scrapy.exceptions import DropItem
from scraper.items import NewsItem

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://cybershield:CHANGE_ME@postgres:5432/cybershield",
).replace("postgresql+asyncpg://", "postgresql://")


def get_db_connection():
    """Create a synchronous PostgreSQL connection for Scrapy pipelines."""
    return psycopg2.connect(DATABASE_URL)


class CleaningPipeline:
    """
    Stage 1: Clean and validate scraped data.
    Drop items that are garbage — no title, no description, too short.
    """

    def process_item(self, item, spider):
        if isinstance(item, NewsItem):
            return self._clean_news(item, spider)

        title = item.get("title", "")
        if not title or len(str(title).strip()) < 5:
            raise DropItem(f"No valid title: {item}")

        item["title"] = str(item["title"]).strip()[:500]

        if item.get("description"):
            item["description"] = str(item["description"]).strip()
        else:
            item["description"] = item["title"]

        if item.get("severity"):
            item["severity"] = str(item["severity"]).upper()

        if not item.get("source"):
            item["source"] = spider.name

        return item

    def _clean_news(self, item, spider):
        title = item.get("title", "")
        if not title or len(str(title).strip()) < 5:
            raise DropItem(f"No valid title for news: {item}")
        url = item.get("url", "")
        if not url or not str(url).strip():
            raise DropItem(f"No valid URL for news: {item}")
        item["title"] = str(title).strip()[:500]
        if item.get("description"):
            item["description"] = str(item["description"]).strip()
        if item.get("summary"):
            item["summary"] = str(item["summary"]).strip()
        if not item.get("source"):
            item["source"] = spider.name
        # Drop news articles with empty or very short descriptions
        desc = str(item.get("description") or "").strip()
        if len(desc) < 50:
            raise DropItem(f"News description too short ({len(desc)} chars): {title[:80]}")
        return item


class NLPPipeline:
    """
    Stage 2: NLP classification using TTPXHunter.

    - Verifies if scraped content is a real security threat
    - Extracts MITRE ATT&CK TTP codes
    - Detects exploit status from natural language
    - Extracts affected product names
    - Drops irrelevant content for both threats AND CVEs (e.g. RESERVED entries)

    Same VERIFIED/DROPPED logic applies to all item types.
    """

    def __init__(self):
        self.items_classified = 0
        self.items_dropped = 0

    _NEWS_SPIDERS = {"bleepingcomputer", "thehackernews", "darkreading", "securityweek"}

    def open_spider(self, spider):
        # News spiders don't use TTPXHunter — skip the model load entirely
        if spider.name in self._NEWS_SPIDERS:
            logger.info(f"[NLPPipeline] {spider.name} is a news spider — skipping NLP model load")
            return

        from app.services.nlp_classifier import _load_model
        logger.info(f"[NLPPipeline] Initializing for {spider.name} — loading NLP model...")
        loaded = _load_model()
        if loaded:
            logger.info("[NLPPipeline] NLP model ready")
        else:
            logger.warning("[NLPPipeline] NLP model FAILED to load — items will use fallback scoring")

    def process_item(self, item, spider):
        if isinstance(item, NewsItem):
            return self._process_news(item, spider)

        from app.services.nlp_classifier import classify_threat

        title = item.get("title", "")
        description = item.get("description", "")

        result = classify_threat(title, description)

        # Apply NLP-detected TTPs to item (both threats and CVEs)
        if result["ttp_codes"]:
            existing = item.get("ttp_codes", "")
            item["ttp_codes"] = f"{existing},{result['ttp_codes']}" if existing else result["ttp_codes"]

        item["_nlp_confidence"] = result["max_confidence"]

        # CVE-specific: upgrade exploit status if NLP detected active exploitation
        if "cve_id" in item:
            if result["exploit_status"] == "yes" and item.get("exploit_available") == "unknown":
                item["exploit_available"] = "yes"

        # Threat-specific: store exploit + product signals for risk scoring
        if "threat_type" in item:
            item["_nlp_exploit"] = "yes" if result["exploit_status"] == "yes" else item.get("_nlp_exploit", "unknown")
            if result["products"]:
                item["_nlp_products"] = ",".join(result["products"])

        # Drop anything the model considers irrelevant (e.g. RESERVED CVEs, non-security articles)
        if not result["is_relevant"]:
            self.items_dropped += 1
            label = item.get("cve_id", title[:80])
            logger.info(
                f"[NLP] DROPPED (confidence {result['max_confidence']:.2f}): {label}"
            )
            raise DropItem(
                f"NLP: Not a relevant security threat (confidence: {result['max_confidence']:.2f})"
            )

        self.items_classified += 1
        label = item.get("cve_id", title[:60])
        logger.info(
            f"[NLP] VERIFIED (confidence {result['max_confidence']:.2f}, "
            f"TTPs: {result['ttp_codes'][:50] if result['ttp_codes'] else 'none'}, "
            f"exploit: {result['exploit_status']}): {label}"
        )
        return item

    _FR_STOPWORDS = {
        "le", "la", "les", "du", "des", "une", "un", "dans", "pour", "avec",
        "sur", "sont", "qui", "que", "est", "par", "se", "au", "aux", "ce",
    }

    def _process_news(self, item, spider):
        """Language detection + sector classification for news. No TTPXHunter."""
        from app.services.sector_classifier import infer_sectors

        title = item.get("title", "")
        summary = item.get("summary", "") or ""
        description = item.get("description", "") or ""
        combined = f"{title} {summary} {description}"

        # Language detection
        words = combined.lower().split()
        if words:
            fr_count = sum(1 for w in words if w in self._FR_STOPWORDS)
            item["language"] = "fr" if (fr_count / len(words)) > 0.30 else "en"
        else:
            item["language"] = "en"

        # Sector detection
        item["sectors"] = infer_sectors(combined, [])

        self.items_classified += 1
        logger.info(
            f"[NEWS] {title[:60]} | lang:{item['language']} | sectors:{item['sectors']}"
        )
        return item

    def close_spider(self, spider):
        logger.info(
            f"[NLPPipeline] {spider.name} complete: "
            f"{self.items_classified} classified, {self.items_dropped} dropped"
        )


class RiskScoringPipeline:
    """
    Stage 3: Calculate risk score for threats and CVEs.
    Uses enriched data from NLP pipeline for better scoring.
    """

    def process_item(self, item, spider):
        from app.services.risk_scorer import calculate_risk_score, severity_from_score

        if "cve_id" in item:
            cvss = item.get("cvss_base_score")
            exploit = item.get("exploit_available", "unknown")
            description = item.get("description", "")
            published = item.get("published_at")
            nlp_conf = item.get("_nlp_confidence")

            score_result = calculate_risk_score(
                cvss_score=float(cvss) if cvss else None,
                exploit_available=exploit,
                description=description,
                published_at=published,
                nlp_confidence=float(nlp_conf) if nlp_conf is not None else None,
            )

            item["_risk_score"] = score_result["risk_score"]
            item["_severity_label"] = severity_from_score(score_result["risk_score"])

        elif "threat_type" in item:
            description = item.get("description", "")
            published = item.get("published_at")
            exploit_status = item.get("_nlp_exploit", "unknown")

            # Use spider-assigned severity as implied CVSS when no real CVSS is available.
            # Curated security feeds (CERTFR, ZDI, etc.) label items correctly — respect that.
            severity_label = (item.get("severity") or "").upper()
            severity_to_cvss = {
                "CRITICAL": 9.0,
                "HIGH":     7.5,
                "MEDIUM":   5.5,
                "LOW":      3.0,
            }
            implied_cvss = severity_to_cvss.get(severity_label)

            nlp_conf = item.get("_nlp_confidence")
            score_result = calculate_risk_score(
                cvss_score=implied_cvss,
                exploit_available=exploit_status,
                published_at=published,
                nlp_confidence=float(nlp_conf) if nlp_conf is not None else None,
            )

            item["_risk_score"] = score_result["risk_score"]
            item["_severity_label"] = severity_from_score(score_result["risk_score"])

        return item


class EnrichmentPipeline:
    """
    Stage 4: LLM enrichment via phi3.5 (Ollama).

    Every item that passed NLP MUST be enriched before storing.
    If phi3.5 is unreachable, try to start Ollama. If that fails,
    stop the spider — no data enters the database without enrichment.
    """

    def open_spider(self, spider):
        self._ollama_down = False

    def process_item(self, item, spider):
        from app.services.enrichment import enrich, OllamaUnavailableError, start_ollama, normalize_affected_products

        if self._ollama_down:
            raise DropItem("Phi3.5 isn't reachable")

        # Save spider-provided structured products (FortiGuard/Cisco/Microsoft)
        # before LLM runs — they're more accurate than LLM extraction from text
        spider_products = None
        spider_remediation = None
        if item.get("_enrichment"):
            spider_enrichment = item["_enrichment"]
            if spider_enrichment.get("affected_products"):
                spider_products = normalize_affected_products(spider_enrichment["affected_products"])
            if spider_enrichment.get("remediation_steps"):
                spider_remediation = spider_enrichment["remediation_steps"]
            item["_enrichment"] = None  # Clear so LLM always runs

        title = str(item.get("title", ""))
        source = str(item.get("source", spider.name))

        if isinstance(item, NewsItem):
            description = str(item.get("description", "") or item.get("summary", ""))
        else:
            description = str(item.get("description", ""))

        try:
            item["_enrichment"] = enrich(title, description, source)
        except OllamaUnavailableError:
            # phi3.5 failed — try to start Ollama
            logger.warning("[Enrichment] Phi3.5 isn't reachable — attempting to start Ollama...")
            started = start_ollama()

            if started:
                # Retry enrichment once
                try:
                    item["_enrichment"] = enrich(title, description, source)
                except OllamaUnavailableError:
                    pass

            if not item.get("_enrichment"):
                # Still can't reach — stop the spider
                self._ollama_down = True
                logger.critical("[Enrichment] Phi3.5 isn't reachable — stopping spider")
                spider.crawler.engine.close_spider(spider, reason="Phi3.5 isn't reachable")
                raise DropItem("Phi3.5 isn't reachable")

        # Merge: spider-extracted products/remediation override LLM output
        # (structured HTML parsing is more accurate than LLM extraction)
        if spider_products:
            item["_enrichment"]["affected_products"] = spider_products
        if spider_remediation:
            item["_enrichment"].setdefault("remediation_steps", [])
            item["_enrichment"]["remediation_steps"] = spider_remediation + item["_enrichment"]["remediation_steps"]

        # Write LLM summary back to item so the DB summary column gets the clean version
        llm_summary = item["_enrichment"].get("summary", "")
        if llm_summary and isinstance(item, NewsItem):
            item["summary"] = llm_summary

        # Override keyword-based sectors with LLM-classified sectors for news
        llm_sectors = item["_enrichment"].get("sectors")
        if llm_sectors is not None and isinstance(item, NewsItem):
            item["sectors"] = llm_sectors

        return item


class DatabasePipeline:
    """
    Stage 5: Store items to PostgreSQL.
    Skips duplicates — checks by cve_id for CVEs, by title+source for threats.
    Auto-creates alerts for high-risk threats AND CVEs, then queues email delivery.
    """

    def open_spider(self, spider):
        self.conn = get_db_connection()
        self.cursor = self.conn.cursor()
        self.items_stored = 0
        self.items_skipped = 0
        logger.info(f"[DatabasePipeline] Connected to database for {spider.name}")

    def close_spider(self, spider):
        self.conn.commit()
        self.cursor.close()
        self.conn.close()
        logger.info(
            f"[DatabasePipeline] {spider.name} complete: "
            f"{self.items_stored} stored, {self.items_skipped} skipped"
        )

    def process_item(self, item, spider):
        try:
            if isinstance(item, NewsItem):
                self._store_news(item)
                return item
            elif "cve_id" in item:
                self._store_cve(item)
            else:
                self._store_threat(item)
        except Exception as e:
            self.conn.rollback()
            logger.error(f"[DatabasePipeline] Error storing item: {e}")

        # Run client matching if enrichment_data has affected_products
        try:
            self._run_client_matching(item)
        except Exception as e:
            self.conn.rollback()
            logger.error(f"[DatabasePipeline] Client matching error: {e}")

        return item

    def _run_client_matching(self, item):
        """Match stored CVE/threat against client inventory. Updates the record and any pending proposal."""
        enrichment = item.get("_enrichment") or {}
        affected_products = enrichment.get("affected_products", [])
        if not affected_products:
            return

        from app.services.matching_engine import match_clients_for_cve
        matches = match_clients_for_cve(affected_products, self.conn)
        if not matches:
            return

        matches_json = json.dumps(matches)
        label = item.get("cve_id") or item.get("title", "")[:40]

        if "cve_id" in item:
            cve_id = item.get("cve_id")
            # Write matches onto the CVE record itself (merged into enrichment_data)
            self.cursor.execute(
                """UPDATE cves
                   SET enrichment_data = COALESCE(enrichment_data, '{}'::jsonb) || %s::jsonb
                   WHERE cve_id = %s""",
                (json.dumps({"client_matches": matches}), cve_id),
            )
            # Also update any pending proposal for this CVE
            self.cursor.execute(
                """UPDATE cve_enrichment_proposals
                   SET client_matches = %s
                   WHERE cve_id = %s AND status = 'PENDING'""",
                (matches_json, cve_id),
            )
        else:
            title = item.get("title", "")
            source = item.get("source", "")
            self.cursor.execute(
                "SELECT id FROM threats WHERE title = %s AND source = %s LIMIT 1",
                (title, source),
            )
            row = self.cursor.fetchone()
            if row:
                threat_id = row[0]
                # Write matches onto the Threat record itself
                self.cursor.execute(
                    """UPDATE threats
                       SET enrichment_data = COALESCE(enrichment_data, '{}'::jsonb) || %s::jsonb
                       WHERE id = %s""",
                    (json.dumps({"client_matches": matches}), threat_id),
                )
                # Also update any pending proposal for this threat
                self.cursor.execute(
                    """UPDATE threat_enrichment_proposals
                       SET client_matches = %s
                       WHERE threat_id = %s AND status = 'PENDING'""",
                    (matches_json, threat_id),
                )

        self.conn.commit()
        logger.info(f"[Matching] {len(matches)} client(s) matched for {label}")

    def _store_news(self, item):
        """Store a news article. Dedup by URL."""
        url = item.get("url", "")
        self.cursor.execute("SELECT id FROM news_articles WHERE url = %s", (url,))
        if self.cursor.fetchone():
            self.items_skipped += 1
            return

        sectors = item.get("sectors", [])
        sectors_json = json.dumps(sectors) if sectors else "[]"
        enrichment = item.get("_enrichment")
        enrichment_json = json.dumps(enrichment) if enrichment else None
        now = datetime.utcnow()

        self.cursor.execute(
            """
            INSERT INTO news_articles (
                title, summary, description, url, source,
                published_at, language, sectors, status,
                enrichment_data, scraped_at, created_at, updated_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            ) RETURNING id
            """,
            (
                item.get("title", ""),
                item.get("summary", ""),
                item.get("description", ""),
                url,
                item.get("source", ""),
                item.get("published_at", now),
                item.get("language", "en"),
                sectors_json,
                "NEW",
                enrichment_json,
                now, now, now,
            ),
        )
        result = self.cursor.fetchone()
        self.conn.commit()
        self.items_stored += 1
        logger.info(f"[NEWS STORED] {item.get('title', '')[:60]}")

        # Client matching by sector overlap + enrichment products
        if result:
            try:
                affected_products = (enrichment or {}).get("affected_products", [])
                self._match_news_clients(result[0], sectors, affected_products)
            except Exception as e:
                self.conn.rollback()
                logger.error(f"[NEWS Matching] Error: {e}")

    def _match_news_clients(self, news_id, sectors, affected_products=None):
        """Match news article against client interests by sector overlap and product inventory."""
        news_sectors = set(s.lower() for s in (sectors or []))
        product_names = set()
        for p in (affected_products or []):
            name = p.get("name", "") if isinstance(p, dict) else str(p)
            if name:
                product_names.add(name.lower())

        if not news_sectors and not product_names:
            return

        self.cursor.execute(
            "SELECT id, interests, inventory FROM notification_recipients WHERE role = 'CLIENT' AND is_active = TRUE"
        )
        rows = self.cursor.fetchall()
        matched_ids = []
        for row in rows:
            interests_raw = row[1]
            inventory_raw = row[2]

            # Sector match
            if news_sectors and interests_raw:
                if isinstance(interests_raw, str):
                    try:
                        interests_raw = json.loads(interests_raw)
                    except (json.JSONDecodeError, TypeError):
                        interests_raw = []
                client_interests = set(i.lower() for i in (interests_raw or []))
                if client_interests & news_sectors:
                    matched_ids.append(row[0])
                    continue

            # Product match
            if product_names and inventory_raw:
                if isinstance(inventory_raw, str):
                    try:
                        inventory_raw = json.loads(inventory_raw)
                    except (json.JSONDecodeError, TypeError):
                        inventory_raw = []
                for inv_item in (inventory_raw or []):
                    inv_product = str(inv_item.get("product", "") if isinstance(inv_item, dict) else inv_item).lower()
                    inv_vendor = str(inv_item.get("vendor", "") if isinstance(inv_item, dict) else "").lower()
                    if inv_product and any(inv_product in pn or pn in inv_product for pn in product_names):
                        matched_ids.append(row[0])
                        break
                    if inv_vendor and any(inv_vendor in pn or pn in inv_vendor for pn in product_names):
                        matched_ids.append(row[0])
                        break

        if matched_ids:
            self.cursor.execute(
                """UPDATE news_articles
                   SET enrichment_data = COALESCE(enrichment_data, '{}'::jsonb) || %s::jsonb
                   WHERE id = %s""",
                (json.dumps({"client_matches": matched_ids}), news_id),
            )
            self.conn.commit()
            logger.info(f"[NEWS Matching] {len(matched_ids)} client(s) matched for news {news_id}")

    def _store_cve(self, item):
        cve_id = item.get("cve_id")

        self.cursor.execute("SELECT id FROM cves WHERE cve_id = %s", (cve_id,))
        if self.cursor.fetchone():
            self.items_skipped += 1
            # Don't drop the second source's data — file it as a proposal
            # for the analyst to review and optionally merge into the canonical CVE.
            self._create_proposal(item)
            return

        enrichment = item.get("_enrichment")
        enrichment_json = json.dumps(enrichment) if enrichment else None

        self.cursor.execute(
            """
            INSERT INTO cves (
                cve_id, title, description, affected_products, vendor,
                cvss_base_score, cvss_vector, cvss_severity,
                exploit_available, patch_available, source_url, "references",
                published_at, created_at, enrichment_data, source
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            ) RETURNING id
            """,
            (
                cve_id,
                item.get("title", ""),
                item.get("description", ""),
                item.get("affected_products", ""),
                item.get("vendor", ""),
                item.get("cvss_base_score"),
                item.get("cvss_vector", ""),
                (item.get("cvss_severity") if item.get("cvss_severity") not in (None, "", "UNKNOWN") else item.get("_severity_label") or "MEDIUM").upper(),
                item.get("exploit_available", "unknown"),
                item.get("patch_available", "unknown"),
                item.get("source_url", ""),
                item.get("references", ""),
                item.get("published_at", datetime.utcnow()),
                datetime.utcnow(),
                enrichment_json,
                item.get("source", "unknown"),
            ),
        )
        result = self.cursor.fetchone()
        cve_row_id = result[0] if result else None
        self.conn.commit()
        self.items_stored += 1
        logger.info(f"[Stored] CVE {cve_id} (CVSS: {item.get('cvss_base_score')})")

        risk_score = item.get("_risk_score") or 0
        if risk_score >= 70 and cve_row_id:
            self._create_alert(item, risk_score, cve_row_id=cve_row_id)

    def _store_threat(self, item):
        title = item.get("title", "")
        source = item.get("source", "")

        # Same-source exact duplicate — skip silently.
        self.cursor.execute(
            "SELECT id FROM threats WHERE title = %s AND source = %s",
            (title, source),
        )
        if self.cursor.fetchone():
            self.items_skipped += 1
            return

        # Cross-source duplicate — another source already has this title.
        # File an enrichment proposal against that existing threat instead of
        # inserting a new row.
        self.cursor.execute(
            "SELECT id FROM threats WHERE title = %s LIMIT 1",
            (title,),
        )
        existing = self.cursor.fetchone()
        if existing:
            self.items_skipped += 1
            self._create_threat_proposal(existing[0], item)
            return

        risk_score = item.get("_risk_score", 50.0)
        severity = (item.get("_severity_label") or item.get("severity") or "MEDIUM").upper()
        enrichment = item.get("_enrichment")
        enrichment_json = json.dumps(enrichment) if enrichment else None

        # Use regions from enrichment data if available, fall back to item or "Global"
        regions = item.get("regions", "Global")
        if enrichment and enrichment.get("affected_regions"):
            extracted_regions = [r for r in enrichment["affected_regions"] if r and r != "Global"]
            if extracted_regions:
                regions = ", ".join(extracted_regions)

        # Check MENA relevance from extracted regions
        mena_keywords = {"middle east", "mena", "gulf", "gcc"}
        is_mena = any(k in regions.lower() for k in mena_keywords)

        self.cursor.execute(
            """
            INSERT INTO threats (
                title, description, source, source_url, severity,
                threat_type, ttp_codes, risk_score, confidence,
                regions, is_mena_relevant, status,
                published_at, discovered_at, created_at, updated_at,
                enrichment_data
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            ) RETURNING id
            """,
            (
                title,
                item.get("description", ""),
                source,
                item.get("source_url", ""),
                severity,
                item.get("threat_type", "unknown"),
                item.get("ttp_codes", "")[:500],
                risk_score,
                0.7,
                regions,
                is_mena,
                "ACTIVE",
                item.get("published_at", datetime.utcnow()),
                datetime.utcnow(),
                datetime.utcnow(),
                datetime.utcnow(),
                enrichment_json,
            ),
        )

        result = self.cursor.fetchone()
        threat_id = result[0] if result else None
        self.conn.commit()
        self.items_stored += 1
        logger.info(f"[Stored] Threat: {title[:50]} (Score: {risk_score})")

        if risk_score >= 70 and threat_id:
            self._create_alert(item, risk_score, threat_id=threat_id)

    def _create_proposal(self, item):
        """
        File an enrichment proposal when a duplicate CVE is scraped by a
        second source. The analyst reviews the diff and chooses which fields
        to merge into the canonical CVE row.
        """
        cve_id = item.get("cve_id")
        source = item.get("source") or "unknown"

        # Raw item dict (minus Scrapy internals) stored as JSONB so the UI
        # can diff whatever fields turn out to matter later.
        proposed = {
            "title": item.get("title", ""),
            "description": item.get("description", ""),
            "affected_products": item.get("affected_products", ""),
            "vendor": item.get("vendor", ""),
            "cvss_base_score": item.get("cvss_base_score"),
            "cvss_vector": item.get("cvss_vector", ""),
            "cvss_severity": item.get("cvss_severity", ""),
            "exploit_available": item.get("exploit_available", "unknown"),
            "patch_available": item.get("patch_available", "unknown"),
            "source_url": item.get("source_url", ""),
            "references": item.get("references", ""),
            "enrichment_data": item.get("_enrichment"),
        }

        try:
            # Skip if this CVE already has any non-terminal proposal in flight
            self.cursor.execute(
                """
                SELECT 1 FROM cve_enrichment_proposals
                WHERE cve_id = %s AND status = 'PENDING' LIMIT 1
                """,
                (cve_id,),
            )
            if self.cursor.fetchone():
                logger.info(f"[Proposal] {cve_id} already in review — skipping new proposal from {source}")
                return

            self.cursor.execute(
                """
                INSERT INTO cve_enrichment_proposals
                    (cve_id, source, origin, proposed_fields, status, created_at)
                VALUES (%s, %s, 'SCRAPER', %s, 'PENDING', %s)
                RETURNING id
                """,
                (cve_id, source, json.dumps(proposed), datetime.utcnow()),
            )
            self.cursor.fetchone()
            self.conn.commit()
            logger.info(f"[Proposal] Filed enrichment proposal for {cve_id} from {source}")
        except Exception as e:
            self.conn.rollback()
            logger.error(f"[Proposal] Failed to file proposal for {cve_id}: {e}")

    def _create_threat_proposal(self, threat_id, item):
        """
        File an enrichment proposal when a duplicate threat (same title, different
        source) is scraped. Analyst reviews the diff to decide if the second
        source carries richer data worth merging.
        """
        source = item.get("source") or "unknown"
        proposed = {
            "title": item.get("title", ""),
            "description": item.get("description", ""),
            "source_url": item.get("source_url", ""),
            "severity": (item.get("severity") or "").upper(),
            "threat_type": item.get("threat_type", ""),
            "ttp_codes": item.get("ttp_codes", ""),
            "regions": item.get("regions", ""),
            "risk_score": item.get("_risk_score"),
            "enrichment_data": item.get("_enrichment"),
        }
        try:
            self.cursor.execute(
                """
                SELECT 1 FROM threat_enrichment_proposals
                WHERE threat_id = %s AND status = 'PENDING' LIMIT 1
                """,
                (threat_id,),
            )
            if self.cursor.fetchone():
                logger.info(f"[Proposal] Threat {threat_id} already in review — skipping new proposal from {source}")
                return

            self.cursor.execute(
                """
                INSERT INTO threat_enrichment_proposals
                    (threat_id, source, origin, proposed_fields, status, created_at)
                VALUES (%s, %s, 'SCRAPER', %s, 'PENDING', %s)
                RETURNING id
                """,
                (threat_id, source, json.dumps(proposed), datetime.utcnow()),
            )
            self.cursor.fetchone()
            self.conn.commit()
            logger.info(f"[Proposal] Filed threat proposal for threat_id={threat_id} from {source}")
        except Exception as e:
            self.conn.rollback()
            logger.error(f"[Proposal] Failed to file threat proposal for {threat_id}: {e}")

    def _create_alert(self, item, risk_score, threat_id=None, cve_row_id=None):
        if risk_score >= 90:
            priority = "URGENT"
        elif risk_score >= 70:
            priority = "HIGH"
        else:
            return

        # Suppress alerts for items whose description we've already alerted on
        # in the last 7 days. NVD frequently files many distinct CVE IDs that
        # describe variants of the same underlying bug with identical text —
        # TTPXHunter correctly verifies each one, so the filter belongs here,
        # at the alerting stage, not in the classifier.
        description_text = (item.get("description") or "").strip()
        if description_text:
            self.cursor.execute(
                """
                SELECT a.id
                FROM alerts a
                LEFT JOIN cves c    ON a.cve_id    = c.id
                LEFT JOIN threats t ON a.threat_id = t.id
                WHERE a.created_at > NOW() - INTERVAL '7 days'
                  AND md5(lower(regexp_replace(
                        COALESCE(c.description, t.description, ''),
                        '\\s+', ' ', 'g'
                      )))
                      = md5(lower(regexp_replace(%s, '\s+', ' ', 'g')))
                LIMIT 1
                """,
                (description_text,),
            )
            if self.cursor.fetchone():
                logger.info(
                    f"[Alert Suppressed] Duplicate description within 7d — "
                    f"skipping alert for {item.get('cve_id') or item.get('title', '')[:50]}"
                )
                return

        # Build title and message based on item type
        if "cve_id" in item:
            cve_id = item.get("cve_id", "Unknown CVE")
            cvss = item.get("cvss_base_score", "?")
            alert_title = f"CVE: {cve_id} (CVSS {cvss})"
            message = (
                f"{priority.title()} severity CVE detected. "
                f"CVSS: {cvss}. Risk score: {risk_score}. "
                f"Source: {item.get('source', 'NVD')}."
            )
        else:
            raw_title = item.get("title", "Unknown Threat")
            alert_title = raw_title[:100]
            source = item.get("source", "Unknown")
            description = (item.get("description", "") or "")[:250]
            message = (
                f"{priority.title()} severity threat detected. "
                f"Risk score: {risk_score}. Source: {source}."
            )
            if description:
                message += f" {description}"

        self.cursor.execute(
            """
            INSERT INTO alerts (
                title, message, priority, status, trigger_rule,
                threat_id, cve_id, email_sent, created_at, updated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                f"AUTO: {alert_title}",
                message,
                priority,
                "NEW",
                f"risk_score>={70}",
                threat_id,
                cve_row_id,
                False,
                datetime.utcnow(),
                datetime.utcnow(),
            ),
        )
        result = self.cursor.fetchone()
        alert_id = result[0] if result else None
        self.conn.commit()
        logger.info(f"[Alert Created] {priority}: {alert_title[:50]}")

        # Trigger email delivery via Celery
        if alert_id:
            try:
                from app.tasks.celery_app import celery_app
                celery_app.send_task(
                    "app.tasks.scraping_tasks.send_alert_email",
                    args=[alert_id],
                )
            except Exception as e:
                logger.error(f"[Alert] Failed to queue email for alert {alert_id}: {e}")
