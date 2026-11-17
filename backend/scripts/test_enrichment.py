#!/usr/bin/env python3
"""
LLM Enrichment Test Script — measures phi3.5 (or any Ollama model) failure rate.

Usage (inside celery-worker container or with DB access):
  python -m scripts.test_enrichment --sample-size 50
  python -m scripts.test_enrichment --sample-size 100 --model phi3.5 --ollama-url http://localhost:11434

Metrics:
  - Hard fail: JSON parse failure (returns EMPTY_ENRICHMENT)
  - Soft fail: empty products when expected, regions="Global" only, French leakage
  - Combined: unique items with any failure / total
"""

import argparse
import json
import os
import re
import sys
import time

import psycopg2

# Resolve the project root so imports work when run as `python -m scripts.test_enrichment`
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.enrichment import enrich, EMPTY_ENRICHMENT, OllamaUnavailableError

FRENCH_INDICATORS = {
    "les", "des", "une", "vulnérabilité", "mise", "jour", "systèmes",
    "affectés", "risque", "peut", "permet", "exécution", "dans", "cette",
    "sont", "pour", "avec", "qui", "par", "aux", "sur",
}


def get_db_url():
    """Build sync psycopg2 DSN from DATABASE_URL env var."""
    url = os.getenv("DATABASE_URL", "")
    if not url:
        print("ERROR: DATABASE_URL not set")
        sys.exit(1)
    # Convert async URL to sync
    return url.replace("postgresql+asyncpg://", "postgresql://")


def fetch_samples(conn, sample_size: int):
    """Pull a mix of CVEs and Threats that have enrichment_data."""
    samples = []
    with conn.cursor() as cur:
        # CVEs with enrichment
        cur.execute(
            "SELECT 'cve' as type, title, description, source, enrichment_data "
            "FROM cves WHERE enrichment_data IS NOT NULL "
            "ORDER BY created_at DESC LIMIT %s",
            (sample_size // 2,)
        )
        for row in cur.fetchall():
            samples.append({
                "item_type": row[0],
                "title": row[1] or "",
                "description": row[2] or "",
                "source": row[3] or "",
                "original_enrichment": row[4] if isinstance(row[4], dict) else json.loads(row[4]) if row[4] else {},
            })

        # Threats with enrichment
        cur.execute(
            "SELECT 'threat' as type, title, description, source, enrichment_data "
            "FROM threats WHERE enrichment_data IS NOT NULL "
            "ORDER BY created_at DESC LIMIT %s",
            (sample_size - len(samples),)
        )
        for row in cur.fetchall():
            samples.append({
                "item_type": row[0],
                "title": row[1] or "",
                "description": row[2] or "",
                "source": row[3] or "",
                "original_enrichment": row[4] if isinstance(row[4], dict) else json.loads(row[4]) if row[4] else {},
            })

    return samples


def detect_french(text: str) -> bool:
    """Check if text contains French words."""
    words = set(re.findall(r"[a-zéèêëàâùûôîïç]+", text.lower()))
    french_count = len(words & FRENCH_INDICATORS)
    return french_count >= 3


def check_french_leakage(result: dict) -> list[str]:
    """Return list of fields that contain French text."""
    leaked = []
    for key in ["impact_points", "remediation_steps", "temp_mitigation"]:
        for item in result.get(key, []):
            if isinstance(item, str) and detect_french(item):
                leaked.append(key)
                break
    for prod in result.get("affected_products", []):
        if isinstance(prod, dict):
            notes = prod.get("notes", "")
            if isinstance(notes, str) and detect_french(notes):
                leaked.append("affected_products.notes")
                break
    return leaked


def evaluate_item(sample: dict, result: dict) -> dict:
    """Evaluate a single enrichment result against expectations."""
    original = sample["original_enrichment"]
    is_empty = (result == EMPTY_ENRICHMENT or all(len(result.get(k, [])) == 0 for k in EMPTY_ENRICHMENT))

    # Hard fail: returned empty when original had content
    original_has_products = len(original.get("affected_products", [])) > 0
    hard_fail = is_empty and original_has_products

    # Soft fail checks
    soft_fails = []

    # Products empty when original had them
    if original_has_products and len(result.get("affected_products", [])) == 0:
        soft_fails.append("products_missing")

    # Regions is only "Global" when original had specific regions
    orig_regions = original.get("affected_regions", [])
    result_regions = result.get("affected_regions", [])
    if orig_regions and any(r != "Global" for r in orig_regions):
        if not result_regions or result_regions == ["Global"]:
            soft_fails.append("regions_global_only")

    # French leakage
    french_fields = check_french_leakage(result)
    if french_fields:
        soft_fails.append(f"french_leakage:{','.join(french_fields)}")

    return {
        "title": sample["title"][:80],
        "type": sample["item_type"],
        "hard_fail": hard_fail,
        "soft_fails": soft_fails,
        "any_fail": hard_fail or len(soft_fails) > 0,
        "products_count": len(result.get("affected_products", [])),
        "regions": result.get("affected_regions", []),
        "impact_count": len(result.get("impact_points", [])),
        "steps_count": len(result.get("remediation_steps", [])),
    }


def main():
    parser = argparse.ArgumentParser(description="Test LLM enrichment quality")
    parser.add_argument("--sample-size", type=int, default=50, help="Number of items to test")
    parser.add_argument("--model", type=str, default=None, help="Ollama model name (overrides OLLAMA_MODEL env)")
    parser.add_argument("--ollama-url", type=str, default=None, help="Ollama URL (overrides OLLAMA_URL env)")
    args = parser.parse_args()

    if args.model:
        os.environ["OLLAMA_MODEL"] = args.model
        # Force reload
        import app.services.enrichment as enr
        enr.MODEL = args.model
    if args.ollama_url:
        os.environ["OLLAMA_URL"] = args.ollama_url
        import app.services.enrichment as enr
        enr.OLLAMA_URL = args.ollama_url

    dsn = get_db_url()
    conn = psycopg2.connect(dsn)

    print(f"Fetching {args.sample_size} samples from database...")
    samples = fetch_samples(conn, args.sample_size)
    conn.close()

    if not samples:
        print("ERROR: No samples found in database. Run some spiders first.")
        sys.exit(1)

    print(f"Found {len(samples)} samples ({sum(1 for s in samples if s['item_type']=='cve')} CVEs, "
          f"{sum(1 for s in samples if s['item_type']=='threat')} Threats)")
    print(f"Testing with model: {os.getenv('OLLAMA_MODEL', 'phi3.5')}")
    print("-" * 70)

    results = []
    ollama_errors = 0

    for i, sample in enumerate(samples):
        prefix = f"[{i+1}/{len(samples)}]"
        try:
            t0 = time.time()
            result = enrich(sample["title"], sample["description"], sample["source"])
            elapsed = time.time() - t0
            evaluation = evaluate_item(sample, result)
            evaluation["elapsed_s"] = round(elapsed, 1)
            results.append(evaluation)

            status = "FAIL" if evaluation["any_fail"] else "OK"
            details = ""
            if evaluation["hard_fail"]:
                details = " [HARD FAIL: empty response]"
            elif evaluation["soft_fails"]:
                details = f" [SOFT: {', '.join(evaluation['soft_fails'])}]"
            print(f"{prefix} {status} ({elapsed:.1f}s) {sample['title'][:60]}{details}")

        except OllamaUnavailableError as e:
            ollama_errors += 1
            print(f"{prefix} OLLAMA ERROR: {e}")
            if ollama_errors >= 3:
                print("\nABORTED: Ollama unreachable 3 times in a row.")
                break

    # Summary
    print("\n" + "=" * 70)
    print("ENRICHMENT TEST RESULTS")
    print("=" * 70)

    total = len(results)
    if total == 0:
        print("No results to analyze.")
        return

    hard_fails = sum(1 for r in results if r["hard_fail"])
    soft_fails = sum(1 for r in results if r["soft_fails"] and not r["hard_fail"])
    any_fails = sum(1 for r in results if r["any_fail"])
    avg_time = sum(r["elapsed_s"] for r in results) / total

    print(f"\nTotal tested:      {total}")
    print(f"Hard fails:        {hard_fails} ({hard_fails/total*100:.1f}%)")
    print(f"Soft fails only:   {soft_fails} ({soft_fails/total*100:.1f}%)")
    print(f"Combined fail:     {any_fails} ({any_fails/total*100:.1f}%)")
    print(f"Pass rate:         {total - any_fails} ({(total-any_fails)/total*100:.1f}%)")
    print(f"Ollama errors:     {ollama_errors}")
    print(f"Avg response time: {avg_time:.1f}s")

    # Per-field emptiness
    print("\nPer-field emptiness rates:")
    for field in ["affected_products", "affected_regions", "impact_points", "remediation_steps", "temp_mitigation"]:
        if field == "affected_products":
            empty = sum(1 for r in results if r["products_count"] == 0)
        elif field == "affected_regions":
            empty = sum(1 for r in results if not r["regions"] or r["regions"] == ["Global"])
        elif field == "impact_points":
            empty = sum(1 for r in results if r["impact_count"] == 0)
        elif field == "remediation_steps":
            empty = sum(1 for r in results if r["steps_count"] == 0)
        else:
            empty = total  # temp_mitigation is often legitimately empty
        print(f"  {field:25s}: {empty}/{total} empty ({empty/total*100:.1f}%)")

    # Soft fail breakdown
    soft_fail_types: dict[str, int] = {}
    for r in results:
        for sf in r["soft_fails"]:
            key = sf.split(":")[0]
            soft_fail_types[key] = soft_fail_types.get(key, 0) + 1
    if soft_fail_types:
        print("\nSoft fail breakdown:")
        for k, v in sorted(soft_fail_types.items(), key=lambda x: -x[1]):
            print(f"  {k:25s}: {v}")

    # Verdict
    threshold = 2.0
    combined_pct = any_fails / total * 100
    print(f"\n{'='*70}")
    if combined_pct <= threshold:
        print(f"VERDICT: PASS — {combined_pct:.1f}% failure rate (threshold: {threshold}%)")
        print("phi3.5 is performing within acceptable limits.")
    else:
        print(f"VERDICT: FAIL — {combined_pct:.1f}% failure rate (threshold: {threshold}%)")
        print("Consider fine-tuning or switching models.")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
