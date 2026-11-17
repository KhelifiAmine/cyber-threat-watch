"""
Backfill client_matches in enrichment_data for existing CVEs, Threats, and News.

Runs inside the backend container:
    docker compose exec backend python scripts/backfill_client_matches.py

This script reuses the same matching logic as the scraper pipeline:
- CVEs/Threats: match_clients_for_cve() from matching_engine.py
- News: sector/product overlap with client interests/inventory
"""

import json
import logging
import sys

import psycopg2

sys.path.insert(0, "/app")
from app.services.matching_engine import match_clients_for_cve  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("backfill_client_matches")

DB = dict(
    host="postgres",
    dbname="cybershield",
    user="cybershield",
    password="CHANGE_ME",
)


def backfill_cves(conn):
    """Match CVEs against client inventory using affected_products from enrichment_data."""
    cur = conn.cursor()
    cur.execute("""
        SELECT id, cve_id, enrichment_data
        FROM cves
        WHERE enrichment_data IS NOT NULL
          AND enrichment_data != '{}'::jsonb
          AND jsonb_array_length(COALESCE(enrichment_data->'affected_products', '[]'::jsonb)) > 0
    """)
    rows = cur.fetchall()
    log.info(f"CVEs with affected_products to match: {len(rows)}")

    matched_count = 0
    for cve_db_id, cve_id, enrichment_data in rows:
        if isinstance(enrichment_data, str):
            enrichment_data = json.loads(enrichment_data)
        affected_products = enrichment_data.get("affected_products", [])
        if not affected_products:
            continue

        matches = match_clients_for_cve(affected_products, conn)
        if matches:
            matched_count += 1
            cur.execute(
                """UPDATE cves
                   SET enrichment_data = COALESCE(enrichment_data, '{}'::jsonb) || %s::jsonb
                   WHERE id = %s""",
                (json.dumps({"client_matches": matches}), cve_db_id),
            )
            log.info(f"  [CVE {cve_id}] {len(matches)} client(s) matched")

    conn.commit()
    log.info(f"CVEs: {matched_count}/{len(rows)} matched at least one client")
    cur.close()


def backfill_threats(conn):
    """Match Threats against client inventory using affected_products from enrichment_data."""
    cur = conn.cursor()
    cur.execute("""
        SELECT id, title, enrichment_data
        FROM threats
        WHERE enrichment_data IS NOT NULL
          AND enrichment_data != '{}'::jsonb
          AND jsonb_array_length(COALESCE(enrichment_data->'affected_products', '[]'::jsonb)) > 0
    """)
    rows = cur.fetchall()
    log.info(f"Threats with affected_products to match: {len(rows)}")

    matched_count = 0
    for threat_id, title, enrichment_data in rows:
        if isinstance(enrichment_data, str):
            enrichment_data = json.loads(enrichment_data)
        affected_products = enrichment_data.get("affected_products", [])
        if not affected_products:
            continue

        matches = match_clients_for_cve(affected_products, conn)
        if matches:
            matched_count += 1
            cur.execute(
                """UPDATE threats
                   SET enrichment_data = COALESCE(enrichment_data, '{}'::jsonb) || %s::jsonb
                   WHERE id = %s""",
                (json.dumps({"client_matches": matches}), threat_id),
            )
            log.info(f"  [Threat {threat_id}] {title[:50]} — {len(matches)} client(s)")

    conn.commit()
    log.info(f"Threats: {matched_count}/{len(rows)} matched at least one client")
    cur.close()


def backfill_news(conn):
    """Match News against client interests (sectors) and inventory (products)."""
    cur = conn.cursor()

    # Fetch all active clients
    cur2 = conn.cursor()
    cur2.execute("""
        SELECT id, interests, inventory
        FROM notification_recipients
        WHERE role = 'CLIENT' AND is_active = TRUE
    """)
    clients = cur2.fetchall()
    cur2.close()

    if not clients:
        log.info("No active CLIENT recipients found — skipping news matching")
        return

    # Fetch news with enrichment data containing sectors or affected_products
    cur.execute("""
        SELECT id, enrichment_data
        FROM news_articles
        WHERE enrichment_data IS NOT NULL
          AND enrichment_data != '{}'::jsonb
    """)
    rows = cur.fetchall()
    log.info(f"News articles to match: {len(rows)}")

    matched_count = 0
    for news_id, enrichment_data in rows:
        if isinstance(enrichment_data, str):
            enrichment_data = json.loads(enrichment_data)

        sectors = enrichment_data.get("sectors", [])
        affected_products = enrichment_data.get("affected_products", [])

        news_sectors = set(s.lower() for s in (sectors or []))
        product_names = set()
        for p in (affected_products or []):
            name = p.get("name", "") if isinstance(p, dict) else str(p)
            if name:
                product_names.add(name.lower())

        if not news_sectors and not product_names:
            continue

        matched_ids = []
        for client_id, interests_raw, inventory_raw in clients:
            # Sector match
            if news_sectors and interests_raw:
                if isinstance(interests_raw, str):
                    try:
                        interests_raw = json.loads(interests_raw)
                    except (json.JSONDecodeError, TypeError):
                        interests_raw = []
                client_interests = set(i.lower() for i in (interests_raw or []))
                if client_interests & news_sectors:
                    matched_ids.append(client_id)
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
                        matched_ids.append(client_id)
                        break
                    if inv_vendor and any(inv_vendor in pn or pn in inv_vendor for pn in product_names):
                        matched_ids.append(client_id)
                        break

        if matched_ids:
            matched_count += 1
            cur.execute(
                """UPDATE news_articles
                   SET enrichment_data = COALESCE(enrichment_data, '{}'::jsonb) || %s::jsonb
                   WHERE id = %s""",
                (json.dumps({"client_matches": matched_ids}), news_id),
            )
            log.info(f"  [News {news_id}] {len(matched_ids)} client(s) matched")

    conn.commit()
    log.info(f"News: {matched_count}/{len(rows)} matched at least one client")
    cur.close()


def main():
    conn = psycopg2.connect(**DB)
    conn.autocommit = False
    try:
        backfill_cves(conn)
        backfill_threats(conn)
        backfill_news(conn)
        log.info("Client matches backfill complete.")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
