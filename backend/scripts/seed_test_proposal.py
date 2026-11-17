"""
Test helper: insert a fake enrichment proposal against an existing CVE.

Usage (from inside the backend container):
    python -m scripts.seed_test_proposal CVE-2024-12345

If no CVE ID is given, it picks the most recently stored CVE.
"""

import json
import os
import sys
from datetime import datetime

import psycopg2

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://cybershield:CHANGE_ME@postgres:5432/cybershield",
).replace("postgresql+asyncpg://", "postgresql://")


def main():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    cve_id = sys.argv[1] if len(sys.argv) > 1 else None
    if cve_id is None:
        cur.execute("SELECT cve_id FROM cves ORDER BY created_at DESC LIMIT 1")
        row = cur.fetchone()
        if not row:
            print("No CVEs in database. Run a scraper first.")
            return
        cve_id = row[0]

    cur.execute("SELECT cve_id FROM cves WHERE cve_id = %s", (cve_id,))
    if not cur.fetchone():
        print(f"CVE {cve_id} does not exist.")
        return

    proposed = {
        "title": f"{cve_id}: Enriched title from GitHub Advisory (test)",
        "description": (
            "This is a synthetic enrichment proposal for end-to-end testing. "
            "GitHub Advisory often carries a longer, clearer description than NVD's "
            "initial entry, including vendor workarounds and patch timelines."
        ),
        "affected_products": "vendor/product >=1.0 <2.3.1 (test data)",
        "vendor": "TestVendor",
        "cvss_base_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_severity": "CRITICAL",
        "exploit_available": "yes",
        "patch_available": "yes",
        "source_url": "https://github.com/advisories/GHSA-test-0000-0000",
        "references": "https://github.com/advisories/GHSA-test-0000-0000 | https://example.com/patch-notes",
        "enrichment_data": None,
    }

    cur.execute(
        """
        INSERT INTO cve_enrichment_proposals
            (cve_id, source, proposed_fields, status, created_at)
        VALUES (%s, %s, %s, 'PENDING', %s)
        ON CONFLICT DO NOTHING
        RETURNING id
        """,
        (cve_id, "github_advisory_test", json.dumps(proposed), datetime.utcnow()),
    )
    row = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()

    if row:
        print(f"Inserted proposal id={row[0]} for {cve_id}. Open /review in the frontend.")
    else:
        print(f"A pending proposal from github_advisory_test already exists for {cve_id}.")


if __name__ == "__main__":
    main()
