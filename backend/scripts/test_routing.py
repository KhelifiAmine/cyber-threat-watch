#!/usr/bin/env python3
"""
Quick test: calls each enrichment path against live Ollama with sample text.
No database needed.
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("OLLAMA_URL", "http://localhost:11434")

from app.services.enrichment import (
    _classify_source,
    _enrich_structured,
    _enrich_unstructured,
    _enrich_news,
    _parse_summary_conclusion,
    _parse_sectors,
    _verify_sectors,
    enrich,
    EMPTY_ENRICHMENT,
)

# ---------------------------------------------------------------------------
# Unit tests (no Ollama needed)
# ---------------------------------------------------------------------------

def test_classify_source():
    print("--- test_classify_source ---")
    assert _classify_source("NVD") == "structured"
    assert _classify_source("Cisco PSIRT") == "structured"
    assert _classify_source("FortiGuard") == "structured"
    assert _classify_source("Microsoft MSRC") == "structured"
    assert _classify_source("GitHub Advisory") == "structured"
    assert _classify_source("CERT-EU") == "unstructured"
    assert _classify_source("CERT-FR") == "unstructured"
    assert _classify_source("darkreading") == "news"
    assert _classify_source("securityweek") == "news"
    assert _classify_source("bleepingcomputer") == "news"
    assert _classify_source("thehackernews") == "news"
    # Case-insensitive — spider source names use mixed case
    assert _classify_source("SecurityWeek") == "news"
    assert _classify_source("BleepingComputer") == "news"
    assert _classify_source("DarkReading") == "news"
    assert _classify_source("TheHackerNews") == "news"
    assert _classify_source("SomeNewSpider") == "unstructured"  # unknown defaults
    assert _classify_source("") == "unstructured"
    print("  PASS: all 17 assertions\n")


def test_empty_enrichment_keys():
    print("--- test_empty_enrichment_keys ---")
    expected = {"affected_os", "affected_products", "affected_regions",
                "impact_points", "remediation_steps", "temp_mitigation",
                "summary", "conclusion"}
    assert set(EMPTY_ENRICHMENT.keys()) == expected
    print("  PASS: EMPTY_ENRICHMENT has all 8 keys\n")


def test_parse_summary_conclusion():
    print("--- test_parse_summary_conclusion ---")
    text = "SUMMARY:\nThis is the summary.\n\nCONCLUSION:\nPatch now."
    s, c = _parse_summary_conclusion(text)
    assert "summary" in s.lower()
    assert "patch" in c.lower()

    # No labels — entire text becomes summary
    text2 = "Just a blob of text with no labels."
    s2, c2 = _parse_summary_conclusion(text2)
    assert s2 == text2.strip()
    assert c2 == ""
    print("  PASS: labeled and unlabeled parsing\n")


def test_parse_sectors():
    print("--- test_parse_sectors ---")
    # Normal case
    assert _parse_sectors("Some text.\n\nSECTORS: Healthcare, Government") == ["Healthcare", "Government"]
    # Case-insensitive
    assert _parse_sectors("SECTORS: healthcare, GOVERNMENT") == ["Healthcare", "Government"]
    # None
    assert _parse_sectors("SECTORS: none") == []
    # Invalid sectors filtered out
    assert _parse_sectors("SECTORS: Healthcare, Fake Sector, Telecom") == ["Healthcare", "Telecom"]
    # No SECTORS line
    assert _parse_sectors("Just a normal paragraph.") == []
    # All valid sectors
    assert len(_parse_sectors("SECTORS: Banking & Finance, Energy & Utilities, Healthcare, Telecom, Government, Manufacturing, Retail, Education, Transportation, Technology")) == 10
    print("  PASS: all 6 assertions\n")


def test_verify_sectors():
    print("--- test_verify_sectors ---")
    # Banking stripped when no evidence
    assert _verify_sectors(["Banking & Finance", "Technology"], "A software supply chain attack on npm packages") == ["Technology"]
    # Banking kept when evidence exists
    assert _verify_sectors(["Banking & Finance"], "Bank of America reports credential stuffing attack") == ["Banking & Finance"]
    # Healthcare stripped when no evidence
    assert _verify_sectors(["Healthcare", "Technology"], "A new vulnerability in VS Code extensions") == ["Technology"]
    # Healthcare kept when evidence exists
    assert _verify_sectors(["Healthcare"], "Hospital networks were targeted by ransomware") == ["Healthcare"]
    # Manufacturing stripped — "supply chain" alone is not manufacturing
    assert _verify_sectors(["Manufacturing", "Technology"], "Software supply chain attack compromised developer workstations") == ["Technology"]
    # Sectors without evidence checks pass through
    assert _verify_sectors(["Government", "Telecom"], "Some article text") == ["Government", "Telecom"]
    # Empty list
    assert _verify_sectors([], "Some text") == []
    # "Transactional NTFS" should NOT trigger Banking (transaction removed)
    assert _verify_sectors(["Banking & Finance"], "The Transactional NTFS replaying deletes winpeshl") == []
    # Retail stripped when no evidence
    assert _verify_sectors(["Retail", "Technology"], "An infostealer stole credentials from users") == ["Technology"]
    print("  PASS: all 9 assertions\n")


# ---------------------------------------------------------------------------
# Live Ollama tests
# ---------------------------------------------------------------------------

SAMPLE_STRUCTURED = {
    "title": "CVE-2024-21762 - FortiOS Out-of-Bound Write Vulnerability",
    "source": "FortiGuard",
    "description": (
        "A out-of-bound write vulnerability [CWE-787] in FortiOS may allow a "
        "remote unauthenticated attacker to execute arbitrary code or command via "
        "specially crafted HTTP requests. Affected versions: FortiOS 7.4.0 through "
        "7.4.2, FortiOS 7.2.0 through 7.2.6, FortiOS 7.0.0 through 7.0.13, "
        "FortiOS 6.4.0 through 6.4.14, FortiOS 6.2.0 through 6.2.15. "
        "Fortinet recommends upgrading to FortiOS 7.4.3 or above."
    ),
}

SAMPLE_UNSTRUCTURED = {
    "title": "CERTFR-2024-AVI-0245 - Multiples vulnérabilités dans les produits Adobe",
    "source": "CERT-FR",
    "description": (
        "De multiples vulnérabilités ont été découvertes dans les produits Adobe. "
        "Certaines d'entre elles permettent à un attaquant de provoquer une exécution "
        "de code arbitraire à distance, un déni de service à distance et une atteinte "
        "à la confidentialité des données. Systèmes affectés: Adobe ColdFusion versions "
        "antérieures à 2023.18 et 2025.6, Adobe Acrobat Reader versions antérieures à "
        "24.001.20604. Il est recommandé d'appliquer les mises à jour publiées par Adobe."
    ),
}

SAMPLE_NEWS = {
    "title": "Hackers Exploit Zero-Day in Ivanti VPN to Deploy Malware",
    "source": "bleepingcomputer",
    "description": (
        "Threat actors are actively exploiting a critical zero-day vulnerability in "
        "Ivanti Connect Secure VPN appliances to deploy custom malware and steal "
        "credentials. The attacks, first spotted in January 2024, target organizations "
        "across multiple sectors. Ivanti has released patches and urges customers to "
        "apply them immediately. Security researchers at Mandiant have identified at "
        "least five distinct malware families being deployed through the compromised "
        "VPN appliances. The vulnerability allows unauthenticated remote code execution "
        "and has been assigned CVE-2024-21887 with a CVSS score of 9.1."
    ),
}


def run_live_test(name, fn, sample):
    print(f"--- LIVE: {name} ---")
    print(f"  Source: {sample['source']}")
    print(f"  Title:  {sample['title'][:70]}")
    t0 = time.time()
    try:
        result = fn(sample["title"], sample["description"], sample["source"])
        elapsed = time.time() - t0
        print(f"  Time:   {elapsed:.1f}s")

        # Verify shape
        missing = set(EMPTY_ENRICHMENT.keys()) - set(result.keys())
        if missing:
            print(f"  FAIL: missing keys: {missing}")
            return False

        # Print results
        for k, v in result.items():
            if isinstance(v, list):
                print(f"  {k}: [{len(v)} items]")
                for item in v[:3]:
                    print(f"    - {item}")
            else:
                preview = str(v)[:120] + "..." if len(str(v)) > 120 else str(v)
                print(f"  {k}: {preview}")

        print(f"  PASS\n")
        return True
    except Exception as e:
        elapsed = time.time() - t0
        print(f"  FAIL ({elapsed:.1f}s): {e}\n")
        return False


def main():
    print("=" * 70)
    print("ENRICHMENT ROUTING TEST")
    print("=" * 70 + "\n")

    # Unit tests
    print("UNIT TESTS (no Ollama)\n")
    test_classify_source()
    test_empty_enrichment_keys()
    test_parse_summary_conclusion()
    test_parse_sectors()
    test_verify_sectors()

    # Live tests
    print("LIVE TESTS (Ollama phi3.5)\n")
    results = []

    results.append(("Path 1 (Structured)",
                     run_live_test("_enrich_structured", _enrich_structured, SAMPLE_STRUCTURED)))

    results.append(("Path 2 (Unstructured)",
                     run_live_test("_enrich_unstructured", _enrich_unstructured, SAMPLE_UNSTRUCTURED)))

    results.append(("Path 3 (News)",
                     run_live_test("_enrich_news", _enrich_news, SAMPLE_NEWS)))

    results.append(("enrich() dispatcher",
                     run_live_test("enrich", enrich, SAMPLE_STRUCTURED)))

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n  {passed}/{total} passed")
    print("=" * 70)


if __name__ == "__main__":
    main()
