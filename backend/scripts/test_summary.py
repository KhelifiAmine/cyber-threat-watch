"""
Test LLM summary generation on BleepingComputer articles.
Sends each article to phi3.5 and prints the generated summary + conclusion.

Usage:
  docker compose exec celery-worker python scripts/test_summary.py
"""

import json
import os
import urllib.request
import psycopg2

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
MODEL = os.getenv("OLLAMA_MODEL", "phi3.5")

SUMMARY_PROMPT = (
    "You are a senior cybersecurity threat intelligence analyst. "
    "Read the article below and extract the geographic regions that are explicitly mentioned, "
    "targeted, or affected. Return a JSON object with exactly one field:\n"
    "{\n"
    '  "regions": ["list of regions"]\n'
    "}\n\n"
    "RULES:\n"
    "1. Return ONLY the JSON object. No markdown, no explanation.\n"
    "2. Extract regions ONLY if they are explicitly stated in the text.\n"
    "3. Use standard region names: Middle East, MENA, Europe, North America, Asia-Pacific, "
    "Africa, Latin America, Global. Also include specific countries if named.\n"
    "4. If the article mentions specific countries, include BOTH the country AND the broader region.\n"
    "5. If no geographic region is mentioned or implied, return {\"regions\": [\"Global\"]}.\n"
    "6. Do NOT guess or infer regions from vendor names (e.g., Microsoft does not mean North America).\n"
    "7. Only extract regions that are relevant to the threat/incident, not the author's location."
)

DB_URL = os.getenv("DATABASE_URL", "").replace("+asyncpg", "") or "postgresql://cybershield:CHANGE_ME@postgres:5432/cybershield"


def call_llm(title: str, description: str) -> dict:
    msg = f"Title: {title}\n\nArticle:\n{description}"
    body = json.dumps({
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SUMMARY_PROMPT},
            {"role": "user", "content": msg},
        ],
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.0},
    }).encode()

    req = urllib.request.Request(
        OLLAMA_URL + "/api/chat",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as r:
        raw = json.loads(r.read())["message"]["content"].strip()

    return json.loads(raw)


def main():
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()
    cur.execute("""
        SELECT id, title, description
        FROM news_articles
        WHERE source = 'BleepingComputer'
        ORDER BY id
    """)
    articles = cur.fetchall()
    cur.close()
    conn.close()

    print(f"\n{'='*80}")
    print(f"  Testing LLM Region Extraction — {len(articles)} articles")
    print(f"  Model: {MODEL}")
    print(f"{'='*80}\n")

    for article_id, title, description in articles:
        print(f"\n{'─'*80}")
        print(f"  Article #{article_id}: {title[:70]}")
        print(f"  Input: {len(description)} chars")
        print(f"{'─'*80}")

        try:
            result = call_llm(title, description)
            regions = result.get("regions", [])
            print(f"\n  REGIONS: {regions}\n")
        except Exception as e:
            print(f"\n  ERROR: {e}\n")


if __name__ == "__main__":
    main()
