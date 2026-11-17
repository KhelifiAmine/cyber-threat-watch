"""
Backfill enrichment_data for existing high-risk threats and CVEs linked to alerts.

Runs inside the backend container:
    docker compose exec backend python scripts/backfill_enrichment.py
"""

import json
import logging
import sys

import psycopg2

sys.path.insert(0, "/app")
from app.services.enrichment import enrich  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("backfill")

DB = dict(
    host="postgres",
    dbname="cybershield",
    user="cybershield",
    password="CHANGE_ME",
)


def backfill_threats(cur):
    cur.execute(
        """
        SELECT id, title, description, source
        FROM threats
        WHERE risk_score >= 70
          AND (
            enrichment_data IS NULL
            OR enrichment_data::text = '{}'
            OR (
              COALESCE(jsonb_array_length(enrichment_data->'affected_products'), 0) = 0
              AND COALESCE(jsonb_array_length(enrichment_data->'affected_os'), 0) = 0
              AND COALESCE(jsonb_array_length(enrichment_data->'impact_points'), 0) = 0
              AND COALESCE(jsonb_array_length(enrichment_data->'remediation_steps'), 0) = 0
              AND COALESCE(jsonb_array_length(enrichment_data->'temp_mitigation'), 0) = 0
            )
          )
        ORDER BY risk_score DESC
        """
    )
    rows = cur.fetchall()
    log.info(f"Threats to enrich: {len(rows)}")
    for tid, title, desc, source in rows:
        log.info(f"  [threat {tid}] {title[:60]}")
        data = enrich(title or "", desc or "", source or "")
        cur.execute(
            "UPDATE threats SET enrichment_data = %s::jsonb WHERE id = %s",
            (json.dumps(data), tid),
        )


def backfill_cves(cur):
    cur.execute(
        """
        SELECT DISTINCT c.id, c.cve_id, c.title, c.description, c.source_url
        FROM cves c
        JOIN alerts a ON a.cve_id = c.id
        WHERE c.enrichment_data IS NULL
           OR c.enrichment_data::text = '{}'
           OR (
             COALESCE(jsonb_array_length(c.enrichment_data->'affected_products'), 0) = 0
             AND COALESCE(jsonb_array_length(c.enrichment_data->'affected_os'), 0) = 0
             AND COALESCE(jsonb_array_length(c.enrichment_data->'impact_points'), 0) = 0
             AND COALESCE(jsonb_array_length(c.enrichment_data->'remediation_steps'), 0) = 0
             AND COALESCE(jsonb_array_length(c.enrichment_data->'temp_mitigation'), 0) = 0
           )
        """
    )
    rows = cur.fetchall()
    log.info(f"CVEs to enrich: {len(rows)}")
    for cid, cve_id, title, desc, url in rows:
        log.info(f"  [cve {cid}] {cve_id}")
        data = enrich(title or cve_id, desc or "", url or "NVD")
        cur.execute(
            "UPDATE cves SET enrichment_data = %s::jsonb WHERE id = %s",
            (json.dumps(data), cid),
        )


def main():
    conn = psycopg2.connect(**DB)
    conn.autocommit = False
    cur = conn.cursor()
    try:
        backfill_threats(cur)
        conn.commit()
        backfill_cves(cur)
        conn.commit()
        log.info("Backfill complete.")
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    main()
